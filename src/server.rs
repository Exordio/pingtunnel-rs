//! Async-сервер на tokio: принимает ICMP пачками (recvmmsg), демультиплексирует
//! по conn-id в задачи соединений; каждая задача дозванивается к цели и качает
//! трафик по событиям. Исходящее — через единый write-таск (sendmmsg).
//! Поддержаны TCP (через FrameMgr), простой UDP (прямой проброс датаграмм) и
//! надёжный UDP (датаграммы через FrameMgr, см. [`udprel`]).

use crate::crypto::Crypto;
use crate::forward::{self, ForwardConfig};
use crate::framemgr::{marshal_frame, FrameMgr};
use crate::icmp::{self, encode_packet, IcmpIo, OutPkt, RecvBatch};
use crate::proto::*;
use crate::udprel;
use crate::util::{now_ns, Counters};
use anyhow::Result;
use prost::Message as _;
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicI64, AtomicU16, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
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

/// Параметры FrameMgr-соединения, объявленные клиентом в connect-пакете.
#[derive(Clone, Copy)]
struct ConnParams {
    buffersize: usize,
    maxwin: i64,
    resend: i64,
    compress: usize,
    timeout: i32,
    rproto: i32,
    /// Цель этого FrameMgr-соединения — UDP (надёжный UDP), а не TCP.
    udp: bool,
}

/// Куда слать ICMP-ответ клиенту: echo id/seq из его запроса (чтобы ответ
/// «прилетел» как echo-reply на конкретный ping) и IP клиента.
#[derive(Clone, Copy)]
struct ReplyTo {
    echo_id: u16,
    echo_seq: u16,
    src: Ipv4Addr,
}

enum Incoming {
    Data {
        frames: Vec<Vec<u8>>,
        reply: ReplyTo,
    },
    Kick,
}

/// Накопленные за один recvmmsg-батч фреймы одного соединения вместе с последним
/// адресом ответа (обновляется на каждом пакете батча).
struct BatchedFrames {
    frames: Vec<Vec<u8>>,
    reply: ReplyTo,
}

/// Серверное простое UDP-соединение (без FrameMgr): канал данных к задаче +
/// куда слать ответы. Используется в обычном UDP-режиме; надёжный UDP идёт через
/// FrameMgr и эту структуру не задействует.
struct UdpFlow {
    to_target: mpsc::Sender<Vec<u8>>, // данные client→target (задача шлёт через send().await)
    target: String,                   // строка target (в ответном MyMsg.target)
    rproto: i32,                      // sproto для ответа
    echo_id: AtomicU16,
    echo_seq: AtomicU16,
    src: AtomicU32, // ip клиента (биты), куда слать ICMP-ответ
    last: AtomicI64,
}

pub struct Server {
    cfg: ServerConfig,
    io: Arc<IcmpIo>,
    tx: mpsc::Sender<OutPkt>,
    crypto: Option<Crypto>,
    datagram: bool,
    forward: Option<ForwardConfig>,
    // Соединения с FrameMgr-надёжностью (TCP и надёжный UDP): conn-id → канал
    // входящих фреймов в задачу соединения.
    conns: Mutex<HashMap<String, mpsc::Sender<Incoming>>>,
    // Простые UDP-соединения (прямой проброс): conn-id → соединение.
    udp_conns: Mutex<HashMap<String, Arc<UdpFlow>>>,
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
        let mut recv_batch = RecvBatch::new(32);
        let mut groups: HashMap<String, BatchedFrames> = HashMap::new();
        loop {
            let mut guard = match self.io.fd.readable().await {
                Ok(g) => g,
                Err(_) => break,
            };
            loop {
                match guard.try_io(|s| recv_batch.recv(s.get_ref())) {
                    Ok(Ok(n)) => {
                        groups.clear();
                        for i in 0..n {
                            let (raw, src) = recv_batch.get(i);
                            let (msg, echo_id, echo_seq) =
                                match icmp::parse_packet(raw, self.datagram, self.crypto.as_ref()) {
                                    Some(v) => v,
                                    None => continue,
                                };
                            if msg.key != self.cfg.key || msg.rproto < 0 {
                                continue;
                            }
                            let reply = ReplyTo { echo_id, echo_seq, src };
                            match msg.r#type {
                                x if x == MSG_PING => {
                                    let pong = MyMsg {
                                        r#type: MSG_PING,
                                        data: msg.data,
                                        rproto: -1,
                                        key: self.cfg.key,
                                        ..Default::default()
                                    };
                                    let bytes = encode_packet(
                                        pong,
                                        msg.rproto as u8,
                                        echo_id,
                                        echo_seq,
                                        self.crypto.as_ref(),
                                    );
                                    let _ = self.tx.try_send((src, bytes));
                                }
                                x if x == MSG_KICK => {
                                    let conn_tx = self.conns.lock().unwrap().get(&msg.id).cloned();
                                    if let Some(conn_tx) = conn_tx {
                                        let _ = conn_tx.try_send(Incoming::Kick);
                                    }
                                    self.udp_conns.lock().unwrap().remove(&msg.id);
                                }
                                _ => {
                                    if msg.tcpmode == 0 {
                                        // Простой UDP: пишем данные в сокет к цели напрямую.
                                        let flow = self.udp_conns.lock().unwrap().get(&msg.id).cloned();
                                        match flow {
                                            Some(flow) => {
                                                flow.echo_id.store(echo_id, Ordering::Relaxed);
                                                flow.echo_seq.store(echo_seq, Ordering::Relaxed);
                                                flow.src.store(u32::from(src), Ordering::Relaxed);
                                                flow.last.store(now_ns(), Ordering::Relaxed);
                                                self.counters.add_recv(msg.data.len());
                                                let _ = flow.to_target.try_send(msg.data);
                                            }
                                            None => self.create_udp_conn(msg, reply),
                                        }
                                        continue;
                                    }
                                    // FrameMgr-соединение (TCP или надёжный UDP).
                                    let exists = self.conns.lock().unwrap().contains_key(&msg.id);
                                    if exists {
                                        self.counters.add_recv(msg.data.len());
                                        let batch = groups.entry(msg.id).or_insert_with(|| {
                                            BatchedFrames {
                                                frames: Vec::new(),
                                                reply,
                                            }
                                        });
                                        batch.frames.push(msg.data);
                                        batch.reply = reply;
                                    } else {
                                        // новое соединение — создаём сразу (редкий путь)
                                        self.create_conn(msg, reply);
                                    }
                                }
                            }
                        }
                        for (id, batch) in groups.drain() {
                            let conn_tx = self.conns.lock().unwrap().get(&id).cloned();
                            if let Some(conn_tx) = conn_tx {
                                let _ = conn_tx.try_send(Incoming::Data {
                                    frames: batch.frames,
                                    reply: batch.reply,
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

    fn create_conn(self: &Arc<Self>, msg: MyMsg, reply: ReplyTo) {
        let id = msg.id.clone();
        let addr = msg.target.clone();
        if self.cfg.maxconn > 0 && self.conns.lock().unwrap().len() >= self.cfg.maxconn as usize {
            self.remote_error(reply, &id, msg.rproto);
            return;
        }
        if self.is_conn_error(&addr) {
            self.remote_error(reply, &id, msg.rproto);
            return;
        }
        let params = ConnParams {
            buffersize: msg.tcpmode_buffersize.max(1) as usize,
            maxwin: msg.tcpmode_maxwin.max(1) as i64,
            resend: msg.tcpmode_resend_timems.max(1) as i64,
            compress: msg.tcpmode_compress.max(0) as usize,
            timeout: msg.timeout.max(1),
            rproto: msg.rproto,
            udp: msg.udp != 0,
        };
        let (conn_tx, conn_rx) = mpsc::channel::<Incoming>(2048);
        let _ = conn_tx.try_send(Incoming::Data {
            frames: vec![msg.data],
            reply,
        });
        // Регистрируем ДО spawn, чтобы следующие пакеты для этого id нашли канал.
        self.conns.lock().unwrap().insert(id.clone(), conn_tx);
        let me = self.clone();
        tokio::spawn(me.server_conn(id, addr, params, reply, conn_rx));
    }

    /// Создаёт серверное простое UDP-соединение к цели (без FrameMgr).
    fn create_udp_conn(self: &Arc<Self>, msg: MyMsg, reply: ReplyTo) {
        let id = msg.id.clone();
        let addr = msg.target.clone();
        if self.cfg.maxconn > 0 && self.udp_conns.lock().unwrap().len() >= self.cfg.maxconn as usize {
            self.remote_error(reply, &id, msg.rproto);
            return;
        }
        if self.is_conn_error(&addr) {
            self.remote_error(reply, &id, msg.rproto);
            return;
        }
        let (to_target_tx, to_target_rx) = mpsc::channel::<Vec<u8>>(256);
        let flow = Arc::new(UdpFlow {
            to_target: to_target_tx,
            target: addr.clone(),
            rproto: msg.rproto,
            echo_id: AtomicU16::new(reply.echo_id),
            echo_seq: AtomicU16::new(reply.echo_seq),
            src: AtomicU32::new(u32::from(reply.src)),
            last: AtomicI64::new(now_ns()),
        });
        self.udp_conns.lock().unwrap().insert(id.clone(), flow.clone());
        self.counters.add_recv(msg.data.len());
        let _ = flow.to_target.try_send(msg.data); // первый датаграм
        let idle_secs = msg.timeout.max(1);
        let me = self.clone();
        tokio::spawn(me.server_udp_task(id, flow, addr, idle_secs, to_target_rx));
    }

    /// Задача простого UDP-соединения: дозванивается к цели, форвардит в обе стороны.
    async fn server_udp_task(
        self: Arc<Self>,
        id: String,
        flow: Arc<UdpFlow>,
        addr: String,
        idle_secs: i32,
        mut to_target_rx: mpsc::Receiver<Vec<u8>>,
    ) {
        // bind+connect асинхронно (без EWOULDBLOCK на первом send).
        let sock = match UdpSocket::bind("0.0.0.0:0").await {
            Ok(s) => s,
            Err(e) => {
                log::debug!("udp bind failed: {e}");
                self.remote_error_for(&flow, &id);
                self.udp_conns.lock().unwrap().remove(&id);
                return;
            }
        };
        if let Err(e) = sock.connect(&addr).await {
            log::debug!("udp connect {addr} failed: {e}");
            self.remote_error_for(&flow, &id);
            self.add_conn_error(&addr);
            self.udp_conns.lock().unwrap().remove(&id);
            return;
        }

        let idle_ns = idle_secs as i64 * 1_000_000_000;
        let mut idle = tokio::time::interval(Duration::from_secs(idle_secs.max(1) as u64));
        idle.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut buf = vec![0u8; 65535];
        loop {
            tokio::select! {
                data = to_target_rx.recv() => {
                    match data {
                        Some(d) => { let _ = sock.send(&d).await; flow.last.store(now_ns(), Ordering::Relaxed); }
                        None => break,
                    }
                }
                r = sock.recv(&mut buf) => {
                    match r {
                        Ok(n) if n > 0 => {
                            flow.last.store(now_ns(), Ordering::Relaxed);
                            let msg = MyMsg {
                                id: id.clone(),
                                r#type: MSG_DATA,
                                target: flow.target.clone(),
                                data: buf[..n].to_vec(),
                                rproto: -1,
                                key: self.cfg.key,
                                ..Default::default()
                            };
                            let bytes = encode_packet(msg, flow.rproto as u8,
                                flow.echo_id.load(Ordering::Relaxed),
                                flow.echo_seq.load(Ordering::Relaxed), self.crypto.as_ref());
                            self.counters.add_send(n);
                            let dst = Ipv4Addr::from(flow.src.load(Ordering::Relaxed));
                            let _ = self.tx.send((dst, bytes)).await;
                        }
                        Ok(_) => {}
                        Err(_) => break,
                    }
                }
                _ = idle.tick() => {
                    if now_ns() - flow.last.load(Ordering::Relaxed) > idle_ns { break; }
                }
            }
        }
        self.udp_conns.lock().unwrap().remove(&id);
        log::debug!("close udp conn {id}");
    }

    fn remote_error_for(&self, flow: &UdpFlow, id: &str) {
        let reply = ReplyTo {
            echo_id: flow.echo_id.load(Ordering::Relaxed),
            echo_seq: flow.echo_seq.load(Ordering::Relaxed),
            src: Ipv4Addr::from(flow.src.load(Ordering::Relaxed)),
        };
        self.remote_error(reply, id, flow.rproto);
    }

    /// Дозванивается к цели (TCP или, для надёжного UDP, UDP) и запускает цикл
    /// соединения. При ошибке дозвона шлёт KICK клиенту и помечает адрес.
    async fn server_conn(
        self: Arc<Self>,
        id: String,
        addr: String,
        params: ConnParams,
        reply: ReplyTo,
        rx: mpsc::Receiver<Incoming>,
    ) {
        if params.udp {
            // Надёжный UDP: открываем UDP-сокет к цели и оборачиваем его в
            // байтовый поток (длиннопрефиксный фрейминг датаграмм).
            let sock = match UdpSocket::bind("0.0.0.0:0").await {
                Ok(s) => s,
                Err(e) => {
                    log::debug!("udp bind failed: {e}");
                    self.remote_error(reply, &id, params.rproto);
                    self.conns.lock().unwrap().remove(&id);
                    return;
                }
            };
            if let Err(e) = sock.connect(&addr).await {
                log::debug!("udp connect {addr} failed: {e}");
                self.remote_error(reply, &id, params.rproto);
                self.add_conn_error(&addr);
                self.conns.lock().unwrap().remove(&id);
                return;
            }
            let idle = Duration::from_secs(params.timeout.max(1) as u64);
            let stream = udprel::spawn_server_bridge(sock, idle);
            self.run_conn(id, addr, params, stream, reply, rx).await;
            return;
        }

        let connect_timeout = Duration::from_millis(self.cfg.connect_timeout.max(1) as u64);
        let dialed = if let Some(fwd) = &self.forward {
            forward::dial_through_proxy(fwd, &addr, connect_timeout).await
        } else {
            match timeout(connect_timeout, TcpStream::connect(&addr)).await {
                Ok(Ok(s)) => Ok(s),
                Ok(Err(e)) => Err(anyhow::anyhow!("{e}")),
                Err(_) => Err(anyhow::anyhow!("connect timeout")),
            }
        };
        let stream = match dialed {
            Ok(s) => s,
            Err(e) => {
                log::debug!("connect target {addr} failed: {e}");
                self.remote_error(reply, &id, params.rproto);
                self.add_conn_error(&addr);
                self.conns.lock().unwrap().remove(&id);
                return;
            }
        };
        let _ = stream.set_nodelay(true);
        self.run_conn(id, addr, params, stream, reply, rx).await;
    }

    /// Цикл FrameMgr-соединения: гоняет данные между потоком цели и клиентом по
    /// событиям. Универсален по транспорту цели (`stream`): TCP-сокет или
    /// UDP-мост для надёжного UDP.
    async fn run_conn<S>(
        self: Arc<Self>,
        id: String,
        addr: String,
        params: ConnParams,
        mut stream: S,
        mut reply: ReplyTo,
        mut rx: mpsc::Receiver<Incoming>,
    ) where
        S: AsyncRead + AsyncWrite + Unpin + Send,
    {
        let mut fm = FrameMgr::new(
            self.cfg.frame_size,
            FRAME_MAX_ID as i64,
            params.buffersize,
            params.maxwin,
            params.resend,
            params.compress,
        );
        // См. client.rs: read/write идут последовательно в одной задаче, поэтому
        // делить поток не нужно — гоняем один `&mut stream`.
        let mut read_buf = vec![0u8; 256 * 1024];
        let timeout_dur = Duration::from_secs(params.timeout as u64);
        let mut last_recv = Instant::now();
        let mut local_eof = false;
        let mut close_since: Option<Instant> = None;

        loop {
            let connected = fm.is_connected();
            // См. client.rs: читаем не больше, чем влезет в send-буфер, иначе
            // RBuffer::write отбрасывает излишек (потеря данных, нет backpressure).
            let send_left = fm.get_send_buffer_left();
            let read_cap = send_left.min(read_buf.len());
            let tick = if fm.has_pending_work() { ACTIVE_TICK } else { IDLE_TICK };
            tokio::select! {
                m = rx.recv() => {
                    match m {
                        Some(Incoming::Data{frames, reply:r}) => {
                            reply = r;
                            for fr in frames { if let Ok(f)=Frame::decode(&fr[..]) { fm.on_recv_frame(f); } }
                            last_recv = Instant::now();
                            while let Ok(more) = rx.try_recv() {
                                match more {
                                    Incoming::Data{frames, reply:r} => {
                                        reply = r;
                                        for fr in frames { if let Ok(f)=Frame::decode(&fr[..]) { fm.on_recv_frame(f); } }
                                    }
                                    Incoming::Kick => fm.close(),
                                }
                            }
                        }
                        Some(Incoming::Kick) | None => fm.close(),
                    }
                }
                r = stream.read(&mut read_buf[..read_cap]), if connected && !local_eof && send_left > 0 => {
                    match r {
                        Ok(0) => { local_eof = true; fm.close(); }
                        Ok(n) => { fm.write_send_buffer(&read_buf[..n]); }
                        Err(_) => { local_eof = true; fm.close(); }
                    }
                }
                _ = tokio::time::sleep(tick) => {}
            }

            fm.update();

            let list = fm.take_send_list();
            if !list.is_empty() {
                for f in &list {
                    let msg = MyMsg {
                        id: id.clone(),
                        r#type: MSG_DATA,
                        data: marshal_frame(f),
                        rproto: -1,
                        key: self.cfg.key,
                        ..Default::default()
                    };
                    let bytes = encode_packet(msg, params.rproto as u8, reply.echo_id, reply.echo_seq, self.crypto.as_ref());
                    self.counters.add_send(bytes.len());
                    let _ = self.tx.send((reply.src, bytes)).await;
                }
            }

            loop {
                if fm.get_recv_buffer_size() == 0 {
                    break;
                }
                let chunk = fm.get_recv_read_line_buffer();
                match stream.write(&chunk).await {
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

    fn remote_error(&self, reply: ReplyTo, id: &str, rproto: i32) {
        let msg = MyMsg {
            id: id.to_string(),
            r#type: MSG_KICK,
            rproto: -1,
            key: self.cfg.key,
            ..Default::default()
        };
        let bytes = encode_packet(msg, rproto as u8, reply.echo_id, reply.echo_seq, self.crypto.as_ref());
        let _ = self.tx.try_send((reply.src, bytes));
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
            let (send_pkts, send_kb, recv_pkts, recv_kb) = self.counters.take();
            let conns = self.conns.lock().unwrap().len() + self.udp_conns.lock().unwrap().len();
            log::info!(
                "send {send_pkts}Packet/s {send_kb}KB/s recv {recv_pkts}Packet/s {recv_kb}KB/s {conns}Connections"
            );
        }
    }
}
