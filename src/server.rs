//! Async-сервер на tokio: принимает ICMP пачками (recvmmsg), демультиплексирует
//! по conn-id в задачи соединений; каждая задача дозванивается к цели и качает
//! трафик по событиям. Исходящее — через единый write-таск (sendmmsg).
//! Поддержаны TCP (через FrameMgr) и UDP (прямой проброс датаграмм).

use crate::crypto::Crypto;
use crate::forward::{self, ForwardConfig};
use crate::framemgr::{marshal_frame, FrameMgr};
use crate::icmp::{self, encode_packet, IcmpIo, OutPkt, RecvBatch};
use crate::proto::*;
use crate::util::{now_ns, Counters};
use anyhow::Result;
use prost::Message as _;
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicI64, AtomicU16, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::mpsc;
use tokio::time::timeout;

// См. client.rs: мелкий тик при наличии работы, крупный на простое; соединение
// event-driven, busy-poll на 1мс не нужен.
const ACTIVE_TICK: Duration = Duration::from_millis(10);
const IDLE_TICK: Duration = Duration::from_millis(500);

pub struct ServerConfig {
    pub icmp_listen: String,
    pub key: i32,
    pub maxconn: i32,
    pub connect_timeout: i32,
    pub frame_size: usize,
}

/// Параметры FrameMgr, объявленные клиентом в connect-пакете.
#[derive(Clone, Copy)]
struct ConnParams {
    buffersize: usize,
    maxwin: i64,
    resend: i64,
    compress: usize,
    timeout: i32,
    rproto: i32,
}

enum Incoming {
    Data {
        frames: Vec<Vec<u8>>,
        echo_id: u16,
        echo_seq: u16,
        src: Ipv4Addr,
    },
    Kick,
}

/// Серверное UDP-соединение (без FrameMgr): канал данных к задаче + куда слать ответы.
struct ServerUdpConn {
    tx: mpsc::Sender<Vec<u8>>, // данные client→target (задача шлёт через send().await)
    target: String,            // строка target (в ответном MyMsg.target)
    rproto: i32,               // sproto для ответа
    echo_id: AtomicU16,
    echo_seq: AtomicU16,
    src: AtomicU32,            // ip клиента (биты), куда слать ICMP-ответ
    last: AtomicI64,
}

pub struct Server {
    cfg: ServerConfig,
    io: Arc<IcmpIo>,
    tx: mpsc::Sender<OutPkt>,
    crypto: Option<Crypto>,
    datagram: bool,
    forward: Option<ForwardConfig>,
    conns: Mutex<HashMap<String, mpsc::Sender<Incoming>>>,
    udp_conns: Mutex<HashMap<String, Arc<ServerUdpConn>>>,
    conn_error: Mutex<HashMap<String, Instant>>,
    counters: Counters,
}

impl Server {
    pub fn new(
        cfg: ServerConfig,
        crypto: Option<Crypto>,
        forward: Option<ForwardConfig>,
    ) -> Result<Arc<Server>> {
        let (socket, datagram) = icmp::listen_icmp(&cfg.icmp_listen)?;
        if datagram {
            log::warn!("сервер в datagram-режиме: echo request не доставляется, нужен RAW (root)");
        }
        let io = Arc::new(IcmpIo::new(socket)?);
        let tx = icmp::spawn_writer(io.clone(), 8192);
        Ok(Arc::new(Server {
            cfg,
            io,
            tx,
            crypto,
            datagram,
            forward,
            conns: Mutex::new(HashMap::new()),
            udp_conns: Mutex::new(HashMap::new()),
            conn_error: Mutex::new(HashMap::new()),
            counters: Counters::default(),
        }))
    }

    pub async fn run(self: Arc<Self>) -> Result<()> {
        log::info!(
            "Server start (async), icmp {} frame={}B",
            self.cfg.icmp_listen,
            self.cfg.frame_size
        );
        tokio::spawn(self.clone().maintenance());
        self.read_loop().await;
        Ok(())
    }

    // ── Приём ICMP (батч) + демультиплекс ────────────────────────────────

    async fn read_loop(self: Arc<Self>) {
        let mut rb = RecvBatch::new(32);
        let mut groups: HashMap<String, (Vec<Vec<u8>>, u16, u16, Ipv4Addr)> = HashMap::new();
        loop {
            let mut guard = match self.io.fd.readable().await {
                Ok(g) => g,
                Err(_) => break,
            };
            loop {
                match guard.try_io(|s| rb.recv(s.get_ref())) {
                    Ok(Ok(n)) => {
                        groups.clear();
                        for i in 0..n {
                            let (raw, src) = rb.get(i);
                            let (my, eid, eseq) =
                                match icmp::parse_packet(raw, self.datagram, self.crypto.as_ref()) {
                                    Some(v) => v,
                                    None => continue,
                                };
                            if my.key != self.cfg.key || my.rproto < 0 {
                                continue;
                            }
                            match my.r#type {
                                x if x == MSG_PING => {
                                    let pong = MyMsg {
                                        r#type: MSG_PING,
                                        data: my.data,
                                        rproto: -1,
                                        key: self.cfg.key,
                                        ..Default::default()
                                    };
                                    let bytes = encode_packet(
                                        pong,
                                        my.rproto as u8,
                                        eid,
                                        eseq,
                                        self.crypto.as_ref(),
                                    );
                                    let _ = self.tx.try_send((src, bytes));
                                }
                                x if x == MSG_KICK => {
                                    let h = self.conns.lock().unwrap().get(&my.id).cloned();
                                    if let Some(h) = h {
                                        let _ = h.try_send(Incoming::Kick);
                                    }
                                    self.udp_conns.lock().unwrap().remove(&my.id);
                                }
                                _ => {
                                    if my.tcpmode == 0 {
                                        // UDP: пишем данные в сокет к цели напрямую.
                                        let uc = self.udp_conns.lock().unwrap().get(&my.id).cloned();
                                        match uc {
                                            Some(uc) => {
                                                uc.echo_id.store(eid, Ordering::Relaxed);
                                                uc.echo_seq.store(eseq, Ordering::Relaxed);
                                                uc.src.store(u32::from(src), Ordering::Relaxed);
                                                uc.last.store(now_ns(), Ordering::Relaxed);
                                                self.counters.add_recv(my.data.len());
                                                let _ = uc.tx.try_send(my.data);
                                            }
                                            None => self.create_udp_conn(my, eid, eseq, src),
                                        }
                                        continue;
                                    }
                                    let exists = self.conns.lock().unwrap().contains_key(&my.id);
                                    if exists {
                                        self.counters.add_recv(my.data.len());
                                        let e = groups
                                            .entry(my.id)
                                            .or_insert_with(|| (Vec::new(), eid, eseq, src));
                                        e.0.push(my.data);
                                        e.1 = eid;
                                        e.2 = eseq;
                                        e.3 = src;
                                    } else {
                                        // новое соединение — создаём сразу (редкий путь)
                                        self.create_conn(my, eid, eseq, src);
                                    }
                                }
                            }
                        }
                        for (id, (frames, eid, eseq, src)) in groups.drain() {
                            let h = self.conns.lock().unwrap().get(&id).cloned();
                            if let Some(h) = h {
                                let _ = h.try_send(Incoming::Data {
                                    frames,
                                    echo_id: eid,
                                    echo_seq: eseq,
                                    src,
                                });
                            }
                        }
                    }
                    Ok(Err(e)) => {
                        log::debug!("recvmmsg error: {e}");
                        break;
                    }
                    Err(_would_block) => break,
                }
            }
        }
    }

    fn create_conn(self: &Arc<Self>, my: MyMsg, echo_id: u16, echo_seq: u16, src: Ipv4Addr) {
        let id = my.id.clone();
        let addr = my.target.clone();
        if self.cfg.maxconn > 0 && self.conns.lock().unwrap().len() >= self.cfg.maxconn as usize {
            self.remote_error(echo_id, echo_seq, &id, my.rproto, src);
            return;
        }
        if self.is_conn_error(&addr) {
            self.remote_error(echo_id, echo_seq, &id, my.rproto, src);
            return;
        }
        let params = ConnParams {
            buffersize: my.tcpmode_buffersize.max(1) as usize,
            maxwin: my.tcpmode_maxwin.max(1) as i64,
            resend: my.tcpmode_resend_timems.max(1) as i64,
            compress: my.tcpmode_compress.max(0) as usize,
            timeout: my.timeout.max(1),
            rproto: my.rproto,
        };
        let (tx, rx) = mpsc::channel::<Incoming>(2048);
        let _ = tx.try_send(Incoming::Data {
            frames: vec![my.data],
            echo_id,
            echo_seq,
            src,
        });
        // Регистрируем ДО spawn, чтобы следующие пакеты для этого id нашли канал.
        self.conns.lock().unwrap().insert(id.clone(), tx);
        let me = self.clone();
        tokio::spawn(me.server_conn(id, addr, params, echo_id, echo_seq, src, rx));
    }

    /// Создаёт серверное UDP-соединение к цели (без FrameMgr).
    fn create_udp_conn(self: &Arc<Self>, my: MyMsg, echo_id: u16, echo_seq: u16, src: Ipv4Addr) {
        let id = my.id.clone();
        let addr = my.target.clone();
        if self.cfg.maxconn > 0 && self.udp_conns.lock().unwrap().len() >= self.cfg.maxconn as usize {
            self.remote_error(echo_id, echo_seq, &id, my.rproto, src);
            return;
        }
        if self.is_conn_error(&addr) {
            self.remote_error(echo_id, echo_seq, &id, my.rproto, src);
            return;
        }
        let (dtx, drx) = mpsc::channel::<Vec<u8>>(256);
        let uc = Arc::new(ServerUdpConn {
            tx: dtx,
            target: addr.clone(),
            rproto: my.rproto,
            echo_id: AtomicU16::new(echo_id),
            echo_seq: AtomicU16::new(echo_seq),
            src: AtomicU32::new(u32::from(src)),
            last: AtomicI64::new(now_ns()),
        });
        self.udp_conns.lock().unwrap().insert(id.clone(), uc.clone());
        self.counters.add_recv(my.data.len());
        let _ = uc.tx.try_send(my.data); // первый датаграм
        let to = my.timeout.max(1);
        let me = self.clone();
        tokio::spawn(me.server_udp_task(id, uc, addr, to, drx));
    }

    /// Задача UDP-соединения: дозванивается к цели, форвардит в обе стороны.
    async fn server_udp_task(
        self: Arc<Self>,
        id: String,
        uc: Arc<ServerUdpConn>,
        addr: String,
        timeout_secs: i32,
        mut drx: mpsc::Receiver<Vec<u8>>,
    ) {
        // bind+connect асинхронно (без EWOULDBLOCK на первом send).
        let sock = match UdpSocket::bind("0.0.0.0:0").await {
            Ok(s) => s,
            Err(e) => {
                log::debug!("udp bind failed: {e}");
                self.remote_error_for(&uc, &id);
                self.udp_conns.lock().unwrap().remove(&id);
                return;
            }
        };
        if let Err(e) = sock.connect(&addr).await {
            log::debug!("udp connect {addr} failed: {e}");
            self.remote_error_for(&uc, &id);
            self.add_conn_error(&addr);
            self.udp_conns.lock().unwrap().remove(&id);
            return;
        }

        let timeout_ns = timeout_secs as i64 * 1_000_000_000;
        let mut idle = tokio::time::interval(Duration::from_secs(timeout_secs.max(1) as u64));
        idle.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut buf = vec![0u8; 65535];
        loop {
            tokio::select! {
                data = drx.recv() => {
                    match data {
                        Some(d) => { let _ = sock.send(&d).await; uc.last.store(now_ns(), Ordering::Relaxed); }
                        None => break,
                    }
                }
                r = sock.recv(&mut buf) => {
                    match r {
                        Ok(n) if n > 0 => {
                            uc.last.store(now_ns(), Ordering::Relaxed);
                            let my = MyMsg {
                                id: id.clone(),
                                r#type: MSG_DATA,
                                target: uc.target.clone(),
                                data: buf[..n].to_vec(),
                                rproto: -1,
                                key: self.cfg.key,
                                ..Default::default()
                            };
                            let bytes = encode_packet(my, uc.rproto as u8,
                                uc.echo_id.load(Ordering::Relaxed),
                                uc.echo_seq.load(Ordering::Relaxed), self.crypto.as_ref());
                            self.counters.add_send(n);
                            let dst = Ipv4Addr::from(uc.src.load(Ordering::Relaxed));
                            let _ = self.tx.send((dst, bytes)).await;
                        }
                        Ok(_) => {}
                        Err(_) => break,
                    }
                }
                _ = idle.tick() => {
                    if now_ns() - uc.last.load(Ordering::Relaxed) > timeout_ns { break; }
                }
            }
        }
        self.udp_conns.lock().unwrap().remove(&id);
        log::debug!("close udp conn {id}");
    }

    fn remote_error_for(&self, uc: &ServerUdpConn, id: &str) {
        let dst = Ipv4Addr::from(uc.src.load(Ordering::Relaxed));
        self.remote_error(
            uc.echo_id.load(Ordering::Relaxed),
            uc.echo_seq.load(Ordering::Relaxed),
            id,
            uc.rproto,
            dst,
        );
    }

    async fn server_conn(
        self: Arc<Self>,
        id: String,
        addr: String,
        params: ConnParams,
        mut echo_id: u16,
        mut echo_seq: u16,
        mut src: Ipv4Addr,
        mut rx: mpsc::Receiver<Incoming>,
    ) {
        let to = Duration::from_millis(self.cfg.connect_timeout.max(1) as u64);
        let dialed = if let Some(fwd) = &self.forward {
            forward::dial_through_proxy(fwd, &addr, to).await
        } else {
            match timeout(to, TcpStream::connect(&addr)).await {
                Ok(Ok(s)) => Ok(s),
                Ok(Err(e)) => Err(anyhow::anyhow!("{e}")),
                Err(_) => Err(anyhow::anyhow!("connect timeout")),
            }
        };
        let stream = match dialed {
            Ok(s) => s,
            Err(e) => {
                log::debug!("connect target {addr} failed: {e}");
                self.remote_error(echo_id, echo_seq, &id, params.rproto, src);
                self.add_conn_error(&addr);
                self.conns.lock().unwrap().remove(&id);
                return;
            }
        };
        let _ = stream.set_nodelay(true);

        let mut fm = FrameMgr::new(
            self.cfg.frame_size,
            FRAME_MAX_ID as i64,
            params.buffersize,
            params.maxwin,
            params.resend,
            params.compress,
        );
        let (mut rd, mut wr) = stream.into_split();
        let mut rbuf = vec![0u8; 256 * 1024];
        let timeout_dur = Duration::from_secs(params.timeout as u64);
        let mut last_recv = Instant::now();
        let mut local_eof = false;
        let mut close_since: Option<Instant> = None;

        loop {
            let connected = fm.is_connected();
            // См. client.rs: читаем не больше, чем влезет в send-буфер, иначе
            // RBuffer::write отбрасывает излишек (потеря данных, нет backpressure).
            let send_left = fm.get_send_buffer_left();
            let read_cap = send_left.min(rbuf.len());
            let tick = if fm.has_pending_work() { ACTIVE_TICK } else { IDLE_TICK };
            tokio::select! {
                m = rx.recv() => {
                    match m {
                        Some(Incoming::Data{frames, echo_id:e, echo_seq:s, src:sr}) => {
                            echo_id=e; echo_seq=s; src=sr;
                            for fr in frames { if let Ok(f)=Frame::decode(&fr[..]) { fm.on_recv_frame(f); } }
                            last_recv = Instant::now();
                            while let Ok(more) = rx.try_recv() {
                                match more {
                                    Incoming::Data{frames, echo_id:e, echo_seq:s, src:sr} => {
                                        echo_id=e; echo_seq=s; src=sr;
                                        for fr in frames { if let Ok(f)=Frame::decode(&fr[..]) { fm.on_recv_frame(f); } }
                                    }
                                    Incoming::Kick => fm.close(),
                                }
                            }
                        }
                        Some(Incoming::Kick) | None => fm.close(),
                    }
                }
                r = rd.read(&mut rbuf[..read_cap]), if connected && !local_eof && send_left > 0 => {
                    match r {
                        Ok(0) => { local_eof = true; fm.close(); }
                        Ok(n) => { fm.write_send_buffer(&rbuf[..n]); }
                        Err(_) => { local_eof = true; fm.close(); }
                    }
                }
                _ = tokio::time::sleep(tick) => {}
            }

            fm.update();

            let list = fm.take_send_list();
            if !list.is_empty() {
                for f in &list {
                    let my = MyMsg {
                        id: id.clone(),
                        r#type: MSG_DATA,
                        data: marshal_frame(f),
                        rproto: -1,
                        key: self.cfg.key,
                        ..Default::default()
                    };
                    let bytes = encode_packet(my, params.rproto as u8, echo_id, echo_seq, self.crypto.as_ref());
                    self.counters.add_send(bytes.len());
                    let _ = self.tx.send((src, bytes)).await;
                }
            }

            loop {
                if fm.get_recv_buffer_size() == 0 {
                    break;
                }
                let chunk = fm.get_recv_read_line_buffer();
                match wr.write(&chunk).await {
                    Ok(n) if n > 0 => fm.skip_recv_buffer(n),
                    Ok(_) => break,
                    Err(_) => {
                        fm.close();
                        break;
                    }
                }
            }

            if fm.is_remote_closed() {
                break;
            }
            // Таймаут по тишине от пира (см. client.rs): завязка на last_send
            // ломала закрытие, т.к. сервер сам шлёт ping/hb каждую секунду —
            // соединения-зомби копились, а счётчики только росли.
            if last_recv.elapsed() > timeout_dur {
                break;
            }
            if local_eof {
                let since = close_since.get_or_insert_with(Instant::now);
                if since.elapsed() > Duration::from_secs(10) {
                    break;
                }
            }
        }

        self.conns.lock().unwrap().remove(&id);
        log::debug!("close conn {id} {addr}");
    }

    // ── Отправка служебного ──────────────────────────────────────────────

    fn remote_error(&self, echo_id: u16, echo_seq: u16, id: &str, rproto: i32, src: Ipv4Addr) {
        let my = MyMsg {
            id: id.to_string(),
            r#type: MSG_KICK,
            rproto: -1,
            key: self.cfg.key,
            ..Default::default()
        };
        let bytes = encode_packet(my, rproto as u8, echo_id, echo_seq, self.crypto.as_ref());
        let _ = self.tx.try_send((src, bytes));
    }

    fn add_conn_error(&self, addr: &str) {
        self.conn_error
            .lock()
            .unwrap()
            .entry(addr.to_string())
            .or_insert_with(Instant::now);
    }
    fn is_conn_error(&self, addr: &str) -> bool {
        self.conn_error.lock().unwrap().contains_key(addr)
    }

    async fn maintenance(self: Arc<Self>) {
        let mut tick = tokio::time::interval(Duration::from_secs(1));
        loop {
            tick.tick().await;
            self.conn_error
                .lock()
                .unwrap()
                .retain(|_, t| t.elapsed() <= Duration::from_secs(5));
            let (sp, ss, rp, rs) = self.counters.take();
            let n = self.conns.lock().unwrap().len() + self.udp_conns.lock().unwrap().len();
            log::info!("send {sp}Packet/s {ss}KB/s recv {rp}Packet/s {rs}KB/s {n}Connections");
        }
    }
}
