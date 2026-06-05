//! Низкоуровневый ICMP-транспорт: raw-сокет, сборка/разбор echo-пакетов и
//! упаковка protobuf-сообщения MyMsg (с опциональным шифрованием) в payload.
//!
//! На Linux raw ICMP-сокет при чтении возвращает пакет вместе с IP-заголовком,
//! поэтому его длина вычисляется из IHL и отбрасывается, чтобы получить ICMP-часть
//! ровно как в Go-версии (offset 8 = начало payload).

use crate::crypto::Crypto;
use crate::proto::{MyMsg, MAGIC};
use anyhow::{anyhow, Result};
use prost::Message;
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use std::io;
use std::mem::MaybeUninit;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

pub const ICMP_ECHO_REQUEST: u8 = 8;
#[allow(dead_code)]
pub const ICMP_ECHO_REPLY: u8 = 0;

/// Открывает ICMP-сокет, привязанный к адресу (или 0.0.0.0).
///
/// Сначала пытается создать привилегированный RAW-сокет; при отказе
/// (нет CAP_NET_RAW) откатывается на непривилегированный datagram-сокет
/// (как android-путь Go-версии). Возвращает сокет и флаг datagram-режима.
///
/// Важно: datagram-режим пригоден для клиента (ядро управляет id и фильтрует
/// echo reply по сокету), но сервер обязан использовать RAW, т.к. echo request
/// на datagram-сокет не доставляется.
pub fn listen_icmp(addr: &str) -> Result<(Socket, bool)> {
    let ip: Ipv4Addr = if addr.is_empty() {
        Ipv4Addr::UNSPECIFIED
    } else {
        addr.parse().unwrap_or(Ipv4Addr::UNSPECIFIED)
    };
    let bind = SocketAddr::new(IpAddr::V4(ip), 0);

    match Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::ICMPV4)) {
        Ok(socket) => {
            socket.bind(&bind.into())?;
            tune_socket(&socket);
            Ok((socket, false))
        }
        Err(_) => {
            let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::ICMPV4))?;
            socket.bind(&bind.into())?;
            tune_socket(&socket);
            log::warn!("RAW ICMP недоступен (нет CAP_NET_RAW), используется datagram-режим (клиентский)");
            Ok((socket, true))
        }
    }
}

/// Настраивает таймауты и размеры буферов ICMP-сокета.
///
/// Ключевой момент — таймаут на запись: при насыщении очереди отправки ядра
/// (много соединений под нагрузкой) `send_to` не должен блокироваться навсегда,
/// иначе зависает весь поток отправки. Потерянный при таймауте пакет будет
/// повторно отправлен надёжным слоем (FrameMgr).
fn tune_socket(socket: &Socket) {
    let _ = socket.set_read_timeout(Some(Duration::from_millis(100)));
    let _ = socket.set_write_timeout(Some(Duration::from_millis(200)));
    // Просим побольше буферов (ядро может урезать до net.core.{r,w}mem_max).
    let _ = socket.set_send_buffer_size(4 << 20);
    let _ = socket.set_recv_buffer_size(8 << 20);
}

/// Контрольная сумма Интернета (RFC 1071) поверх ICMP-сообщения.
fn checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < data.len() {
        sum += ((data[i] as u32) << 8) | (data[i + 1] as u32);
        i += 2;
    }
    if i < data.len() {
        sum += (data[i] as u32) << 8;
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn build_echo(icmp_type: u8, id: u16, seq: u16, payload: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(8 + payload.len());
    buf.push(icmp_type);
    buf.push(0); // code
    buf.push(0);
    buf.push(0); // checksum placeholder
    buf.extend_from_slice(&id.to_be_bytes());
    buf.extend_from_slice(&seq.to_be_bytes());
    buf.extend_from_slice(payload);
    let cs = checksum(&buf);
    buf[2..4].copy_from_slice(&cs.to_be_bytes());
    buf
}

/// Разобранный входящий ICMP-пакет с уже распакованным MyMsg.
pub struct Packet {
    pub my: MyMsg,
    pub src: Ipv4Addr,
    pub echo_id: u16,
    pub echo_seq: u16,
}

/// Отправляет MyMsg: устанавливает magic, сериализует, шифрует, упаковывает в echo.
/// `sproto` — тип ICMP (8 = echo request у клиента, значение rproto у ответов сервера).
#[allow(clippy::too_many_arguments)]
pub fn send_icmp(
    socket: &Socket,
    icmp_id: u16,
    seq: u16,
    dst: Ipv4Addr,
    sproto: u8,
    mut my: MyMsg,
    crypto: Option<&Crypto>,
) -> Result<()> {
    my.magic = MAGIC;
    let mut payload = Vec::with_capacity(my.encoded_len());
    my.encode(&mut payload).map_err(|e| anyhow!("encode: {e}"))?;
    if let Some(c) = crypto {
        payload = c.encrypt(&payload)?;
    }
    let pkt = build_echo(sproto, icmp_id, seq, &payload);
    let addr = SocketAddr::new(IpAddr::V4(dst), 0);
    socket.send_to(&pkt, &addr.into())?;
    Ok(())
}

/// Читает один ICMP-пакет (блокируется до read-timeout сокета), декодирует MyMsg.
/// Возвращает Ok(None) при таймауте или невалидном/чужом пакете.
///
/// В datagram-режиме ядро уже отбросило IP-заголовок; в RAW-режиме его длина
/// вычисляется из IHL и пропускается.
pub fn recv_icmp(
    socket: &Socket,
    datagram: bool,
    crypto: Option<&Crypto>,
) -> io::Result<Option<Packet>> {
    let mut buf = [MaybeUninit::<u8>::uninit(); 10240];
    let (n, src) = match socket.recv_from(&mut buf) {
        Ok(v) => v,
        Err(e) if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut => {
            return Ok(None);
        }
        Err(e) => return Err(e),
    };
    if n == 0 {
        return Ok(None);
    }
    let data: &[u8] = unsafe { std::slice::from_raw_parts(buf.as_ptr() as *const u8, n) };
    if data.is_empty() {
        return Ok(None);
    }

    let icmp = if datagram {
        data
    } else {
        // Отбрасываем IP-заголовок (длина = IHL * 4).
        let ihl = ((data[0] & 0x0f) as usize) * 4;
        if data.len() < ihl + 8 {
            return Ok(None);
        }
        &data[ihl..]
    };
    if icmp.len() < 8 {
        return Ok(None);
    }

    let echo_id = u16::from_be_bytes([icmp[4], icmp[5]]);
    let echo_seq = u16::from_be_bytes([icmp[6], icmp[7]]);
    let mut payload = icmp[8..].to_vec();

    if let Some(c) = crypto {
        payload = match c.decrypt(&payload) {
            Ok(p) => p,
            Err(_) => return Ok(None),
        };
    }

    let my = match MyMsg::decode(&payload[..]) {
        Ok(m) => m,
        Err(_) => return Ok(None),
    };
    if my.magic != MAGIC {
        return Ok(None);
    }

    let src_ip = match src.as_socket() {
        Some(SocketAddr::V4(v4)) => *v4.ip(),
        _ => Ipv4Addr::UNSPECIFIED,
    };
    let _ = SockAddr::from(SocketAddr::new(IpAddr::V4(src_ip), 0));

    Ok(Some(Packet {
        my,
        src: src_ip,
        echo_id,
        echo_seq,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checksum_zeroes_over_complete_message() {
        // Контрольная сумма поверх сообщения с уже вписанной CRC должна давать 0.
        let pkt = build_echo(ICMP_ECHO_REQUEST, 0x1234, 0x0001, b"ping payload");
        assert_eq!(checksum(&pkt), 0);
    }

    #[test]
    fn echo_header_layout() {
        let pkt = build_echo(ICMP_ECHO_REQUEST, 0xBEEF, 0x00AA, b"data");
        assert_eq!(pkt[0], ICMP_ECHO_REQUEST);
        assert_eq!(pkt[1], 0); // code
        assert_eq!(u16::from_be_bytes([pkt[4], pkt[5]]), 0xBEEF);
        assert_eq!(u16::from_be_bytes([pkt[6], pkt[7]]), 0x00AA);
        assert_eq!(&pkt[8..], b"data");
    }

    #[test]
    fn kernel_loopback_roundtrip() {
        // Реальный round-trip против ICMP-ответчика ядра по loopback в
        // datagram-режиме: проверяет сборку echo, контрольную сумму, разбор
        // ответа и (де)сериализацию MyMsg сквозь настоящий сокет.
        // Если окружение запрещает ICMP-сокеты — тест мягко пропускается.
        let (socket, datagram) = match listen_icmp("127.0.0.1") {
            Ok(v) => v,
            Err(_) => return, // нет прав ни на RAW, ни на DGRAM — пропуск
        };
        if !datagram {
            // RAW-режим: на loopback ядро также отвечает, но не будем зависеть.
            return;
        }
        let my = MyMsg {
            id: "roundtrip".into(),
            r#type: 0,
            data: vec![9, 8, 7, 6],
            rproto: -1,
            magic: MAGIC,
            key: 42,
            ..Default::default()
        };
        send_icmp(&socket, 0, 1, Ipv4Addr::LOCALHOST, ICMP_ECHO_REQUEST, my, None)
            .expect("send");

        for _ in 0..20 {
            if let Ok(Some(pkt)) = recv_icmp(&socket, datagram, None) {
                assert_eq!(pkt.my.id, "roundtrip");
                assert_eq!(pkt.my.data, vec![9, 8, 7, 6]);
                assert_eq!(pkt.my.key, 42);
                return;
            }
        }
        panic!("не получили эхо-ответ от ядра по loopback");
    }

    #[test]
    fn mymsg_roundtrip() {
        use prost::Message;
        let my = MyMsg {
            id: "conn-1".into(),
            r#type: 0,
            target: "1.2.3.4:80".into(),
            data: vec![1, 2, 3, 4, 5],
            rproto: -1,
            magic: MAGIC,
            key: 123456,
            ..Default::default()
        };
        let mut buf = Vec::new();
        my.encode(&mut buf).unwrap();
        let got = MyMsg::decode(&buf[..]).unwrap();
        assert_eq!(got.id, "conn-1");
        assert_eq!(got.rproto, -1);
        assert_eq!(got.magic, MAGIC);
        assert_eq!(got.key, 123456);
        assert_eq!(got.data, vec![1, 2, 3, 4, 5]);
    }
}
