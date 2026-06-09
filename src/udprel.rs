//! Надёжный UDP-проброс.
//!
//! Обычный UDP-режим шлёт датаграммы поверх ICMP «как есть» (tcpmode=0), без
//! подтверждений — при потерях в ICMP-канале датаграммы теряются. Надёжный режим
//! (флаг `--udp_rel 1`) пускает датаграммы через тот же [`FrameMgr`], что и TCP:
//! получаем ретрансмиссию, упорядочивание и контроль окна.
//!
//! [`FrameMgr`] переносит непрерывный **байтовый** поток, а UDP оперирует
//! датаграммами с границами. Чтобы вернуть границы на приёме, каждая датаграмма
//! предваряется длиной (u16, big-endian). Адаптеры ниже представляют UDP-сторону
//! соединения как обычный `AsyncRead + AsyncWrite` (через `tokio::io::duplex`),
//! поэтому цикл соединения (`Client::pump` / `Server::run_conn`) переиспользуется
//! без изменений — он просто видит «поток», в который с одной стороны кладут, а с
//! другой забирают уже сериализованные датаграммы.
//!
//! [`FrameMgr`]: crate::framemgr::FrameMgr

use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::time::MissedTickBehavior;

/// Длина поля-префикса (u16 BE), которым предваряется каждая датаграмма в потоке.
const LEN_PREFIX: usize = 2;
/// Максимальная длина датаграммы, которую можно закодировать префиксом u16.
const MAX_DATAGRAM: usize = u16::MAX as usize;
/// Ёмкость внутреннего буфера duplex-пары (байт). Создаёт естественный
/// backpressure: пока цикл соединения не вычитал поток, адаптер не принимает
/// новые датаграммы и они отбрасываются (нормальное поведение для UDP).
const DUPLEX_CAP: usize = 256 * 1024;

/// Дописывает датаграмму в поток с префиксом длины.
fn push_framed(stream_buf: &mut Vec<u8>, datagram: &[u8]) {
    stream_buf.extend_from_slice(&(datagram.len() as u16).to_be_bytes());
    stream_buf.extend_from_slice(datagram);
}

/// Сборщик датаграмм из байтового потока: накапливает байты и отдаёт каждую
/// полную датаграмму (по префиксу длины) в колбэк.
struct Deframer {
    buf: Vec<u8>,
}

impl Deframer {
    fn new() -> Deframer {
        Deframer { buf: Vec::new() }
    }

    /// Добавляет очередной кусок потока и вызывает `on_datagram` для каждой
    /// полностью собранной датаграммы.
    fn feed<F: FnMut(&[u8])>(&mut self, chunk: &[u8], mut on_datagram: F) {
        self.buf.extend_from_slice(chunk);
        let mut start = 0;
        while self.buf.len() - start >= LEN_PREFIX {
            let len = u16::from_be_bytes([self.buf[start], self.buf[start + 1]]) as usize;
            if self.buf.len() - start < LEN_PREFIX + len {
                break; // датаграмма ещё не пришла целиком
            }
            on_datagram(&self.buf[start + LEN_PREFIX..start + LEN_PREFIX + len]);
            start += LEN_PREFIX + len;
        }
        if start > 0 {
            self.buf.drain(0..start);
        }
    }
}

fn idle_ticker(idle: Duration) -> tokio::time::Interval {
    let mut ticker = tokio::time::interval(idle.max(Duration::from_secs(1)));
    ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
    ticker
}

/// Клиентская сторона надёжного UDP-потока.
///
/// Возвращает «поток» для [`Client::pump`](crate::client) и запускает фоновую
/// задачу-мост:
/// - датаграммы приложения приходят по `from_app` → пакуются в поток → читаются
///   циклом соединения и уходят на сервер;
/// - то, что цикл соединения пишет в поток (ответы цели), распаковывается в
///   датаграммы и передаётся в `reply` — колбэк, который доставляет датаграмму
///   приложению (для чистого UDP — `send_to` на исходный адрес, для SOCKS5 —
///   обёртка в UDP-датаграмму SOCKS5). Так адаптер не знает про SOCKS5.
///
/// Задача завершается, если датаграмм нет дольше `idle` либо поток закрыт.
pub fn spawn_client_bridge<R>(
    mut from_app: mpsc::Receiver<Vec<u8>>,
    reply: R,
    idle: Duration,
) -> DuplexStream
where
    R: Fn(&[u8]) + Send + 'static,
{
    let (conn_side, mut udp_side) = tokio::io::duplex(DUPLEX_CAP);
    tokio::spawn(async move {
        let mut deframer = Deframer::new();
        let mut read_buf = vec![0u8; 64 * 1024];
        let mut last_activity = Instant::now();
        let mut idle_tick = idle_ticker(idle);
        loop {
            tokio::select! {
                datagram = from_app.recv() => {
                    match datagram {
                        Some(datagram) => {
                            if datagram.len() > MAX_DATAGRAM {
                                continue;
                            }
                            let mut framed = Vec::with_capacity(LEN_PREFIX + datagram.len());
                            push_framed(&mut framed, &datagram);
                            if udp_side.write_all(&framed).await.is_err() {
                                break;
                            }
                            last_activity = Instant::now();
                        }
                        None => break,
                    }
                }
                read = udp_side.read(&mut read_buf) => {
                    match read {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            deframer.feed(&read_buf[..n], &reply);
                            last_activity = Instant::now();
                        }
                    }
                }
                _ = idle_tick.tick() => {
                    if last_activity.elapsed() >= idle {
                        break;
                    }
                }
            }
        }
    });
    conn_side
}

/// Серверная сторона надёжного UDP-потока.
///
/// `target_sock` — уже `connect`-нутый к цели UDP-сокет. Возвращает «поток» для
/// [`Server::run_conn`](crate::server) и запускает задачу-мост:
/// - ответы цели читаются из сокета → пакуются в поток → уходят клиенту;
/// - то, что цикл соединения пишет в поток (датаграммы приложения), распаковывается
///   и отправляется цели.
///
/// Задача завершается, если датаграмм нет дольше `idle` либо поток закрыт.
pub fn spawn_server_bridge(target_sock: UdpSocket, idle: Duration) -> DuplexStream {
    let (conn_side, mut udp_side) = tokio::io::duplex(DUPLEX_CAP);
    tokio::spawn(async move {
        let mut deframer = Deframer::new();
        let mut stream_buf = vec![0u8; 64 * 1024];
        let mut target_buf = vec![0u8; 64 * 1024];
        let mut last_activity = Instant::now();
        let mut idle_tick = idle_ticker(idle);
        loop {
            tokio::select! {
                from_target = target_sock.recv(&mut target_buf) => {
                    match from_target {
                        Ok(n) if n > 0 && n <= MAX_DATAGRAM => {
                            let mut framed = Vec::with_capacity(LEN_PREFIX + n);
                            push_framed(&mut framed, &target_buf[..n]);
                            if udp_side.write_all(&framed).await.is_err() {
                                break;
                            }
                            last_activity = Instant::now();
                        }
                        Ok(_) => {}
                        Err(_) => break,
                    }
                }
                read = udp_side.read(&mut stream_buf) => {
                    match read {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            deframer.feed(&stream_buf[..n], |datagram| {
                                let _ = target_sock.try_send(datagram);
                            });
                            last_activity = Instant::now();
                        }
                    }
                }
                _ = idle_tick.tick() => {
                    if last_activity.elapsed() >= idle {
                        break;
                    }
                }
            }
        }
    });
    conn_side
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deframer_reassembles_split_and_merged() {
        let mut wire = Vec::new();
        push_framed(&mut wire, b"hello");
        push_framed(&mut wire, b"");
        push_framed(&mut wire, b"world!");

        // Скармливаем поток по одному байту — границы датаграмм должны
        // восстановиться независимо от того, как поток нарезан.
        let mut deframer = Deframer::new();
        let mut got: Vec<Vec<u8>> = Vec::new();
        for b in &wire {
            deframer.feed(&[*b], |d| got.push(d.to_vec()));
        }
        assert_eq!(got, vec![b"hello".to_vec(), b"".to_vec(), b"world!".to_vec()]);
    }

    #[test]
    fn deframer_handles_multiple_in_one_chunk() {
        let mut wire = Vec::new();
        push_framed(&mut wire, b"a");
        push_framed(&mut wire, b"bb");
        let mut deframer = Deframer::new();
        let mut got: Vec<Vec<u8>> = Vec::new();
        deframer.feed(&wire, |d| got.push(d.to_vec()));
        assert_eq!(got, vec![b"a".to_vec(), b"bb".to_vec()]);
    }
}
