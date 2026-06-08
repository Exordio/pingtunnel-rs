//! Async-клиент на tokio: принимает локальные TCP/SOCKS5 соединения и
//! туннелирует их поверх ICMP. Каждое соединение — задача (не ОС-поток),
//! работает по событиям (входящий фрейм / локальные данные / таймер), а не
//! busy-poll. Исходящие пакеты идут в единый write-таск (sendmmsg-батчинг).

use crate::crypto::Crypto;
use crate::framemgr::{marshal_frame, FrameMgr};
use crate::icmp::{self, encode_packet, IcmpIo, OutPkt, RecvBatch, ICMP_ECHO_REQUEST};
use crate::proto::*;
use crate::socks5;
use crate::util::{now_ns, resolve_ipv4, unique_id, Counters};
use anyhow::Result;
use prost::Message as _;
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicI64, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::mpsc;

const SEND_PROTO: u8 = ICMP_ECHO_REQUEST; // 8
const RECV_PROTO: i32 = 0;
// Тик цикла соединения. Соединение event-driven: на входящих фреймах и локальных
// данных оно просыпается немедленно (ветки select), а тик нужен лишь для таймеров
// (resend ~400мс, ping/hb ~1с). Поэтому при наличии работы тикаем мелко, а на
// простое — крупно, вместо постоянного busy-poll на 1мс.
const ACTIVE_TICK: Duration = Duration::from_millis(10);
const IDLE_TICK: Duration = Duration::from_millis(500);

pub struct ClientConfig {
    pub listen: String,
    pub server: String,
    pub target: String,
    pub timeout: i32,
    pub key: i32,
    pub icmp_listen: String,
    pub tcpmode: i32,
    pub buffersize: i32,
    pub maxwin: i32,
    pub resend: i32,
    pub compress: i32,
    pub frame_size: usize,
    pub sock5: i32,
    pub s5user: String,
    pub s5pass: String,
}

/// Сообщение в задачу соединения. Frames — пачка фреймов из одного recvmmsg-батча
/// для одного соединения, чтобы FrameMgr обработал их за один update → батч-ACK.
enum Incoming {
    Frames(Vec<Vec<u8>>),
    Kick,
}

/// UDP-соединение (без FrameMgr — прямой проброс датаграмм).
struct UdpConn {
    src: SocketAddr,      // куда слать ответы локально
    sock: Arc<UdpSocket>, // через какой сокет (listen для plain, relay для socks5)
    socks5: bool,         // оборачивать ответ в socks5-датаграмму
    target: String,       // целевой адрес (для socks5-датаграммы)
    addr_key: String,     // ключ в udp_by_addr
    last: AtomicI64,      // время последней активности
}

pub struct Client {
    cfg: ClientConfig,
    io: Arc<IcmpIo>,
    tx: mpsc::Sender<OutPkt>,
    crypto: Option<Crypto>,
    datagram: bool,
    id: u16,
    seq: AtomicU32,
    server_ip: Mutex<Ipv4Addr>,
    conns: Mutex<HashMap<String, mpsc::Sender<Incoming>>>,
    udp_conns: Mutex<HashMap<String, Arc<UdpConn>>>,
    udp_by_addr: Mutex<HashMap<String, String>>,
    counters: Counters,
}

impl Client {
    pub fn new(cfg: ClientConfig, crypto: Option<Crypto>) -> Result<Arc<Client>> {
        let (socket, datagram) = icmp::listen_icmp(&cfg.icmp_listen)?;
        let io = Arc::new(IcmpIo::new(socket, datagram)?);
        let tx = icmp::spawn_writer(io.clone(), 8192);
        let server_ip = resolve_ipv4(&cfg.server)?;
        let id = (rand::random::<u16>() & 0x7fff).max(1);
        Ok(Arc::new(Client {
            cfg,
            io,
            tx,
            crypto,
            datagram,
            id,
            seq: AtomicU32::new(0),
            server_ip: Mutex::new(server_ip),
            conns: Mutex::new(HashMap::new()),
            udp_conns: Mutex::new(HashMap::new()),
            udp_by_addr: Mutex::new(HashMap::new()),
            counters: Counters::default(),
        }))
    }

    fn next_seq(&self) -> u16 {
        self.seq.fetch_add(1, Ordering::Relaxed) as u16
    }
    fn server_ip(&self) -> Ipv4Addr {
        *self.server_ip.lock().unwrap()
    }

    pub async fn run(self: Arc<Self>) -> Result<()> {
        tokio::spawn(self.clone().read_loop());
        tokio::spawn(self.clone().maintenance());

        log::info!(
            "Client listen {} server {} ({}) icmp {} (async, frame={}B)",
            self.cfg.listen,
            self.cfg.server,
            self.server_ip(),
            self.cfg.icmp_listen,
            self.cfg.frame_size
        );

        let listen = normalize_bind(&self.cfg.listen);

        // Чистый UDP-проброс: слушаем локальный UDP и гоняем датаграммы.
        if self.cfg.tcpmode == 0 && self.cfg.sock5 == 0 {
            let sock = Arc::new(UdpSocket::bind(&listen).await?);
            return self.accept_udp(sock).await;
        }

        let listener = TcpListener::bind(&listen).await?;
        loop {
            let (sock, _peer) = match listener.accept().await {
                Ok(v) => v,
                Err(e) => {
                    log::debug!("accept error: {e}");
                    continue;
                }
            };
            let _ = sock.set_nodelay(true);
            let me = self.clone();
            if self.cfg.sock5 > 0 {
                tokio::spawn(me.handle_socks5(sock));
            } else {
                let target = self.cfg.target.clone();
                tokio::spawn(me.serve_conn(sock, target));
            }
        }
    }

    // ── Приём ICMP (батч) ────────────────────────────────────────────────

    async fn read_loop(self: Arc<Self>) {
        let mut rb = RecvBatch::new(32);
        let mut groups: HashMap<String, Vec<Vec<u8>>> = HashMap::new();
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
                            let (raw, _src) = rb.get(i);
                            let (my, echo_id, _seq) =
                                match icmp::parse_packet(raw, self.datagram, self.crypto.as_ref()) {
                                    Some(v) => v,
                                    None => continue,
                                };
                            if my.rproto >= 0 || my.key != self.cfg.key {
                                continue;
                            }
                            if !self.datagram && echo_id != self.id {
                                continue;
                            }
                            match my.r#type {
                                x if x == MSG_PING => {}
                                x if x == MSG_KICK => {
                                    let tx = self.conns.lock().unwrap().get(&my.id).cloned();
                                    if let Some(tx) = tx {
                                        let _ = tx.try_send(Incoming::Kick);
                                    }
                                }
                                _ => {
                                    self.counters.add_recv(my.data.len());
                                    // UDP-соединение? — отвечаем сразу, не группируя как фрейм.
                                    let uc = self.udp_conns.lock().unwrap().get(&my.id).cloned();
                                    if let Some(uc) = uc {
                                        self.reply_udp(&uc, &my.target, &my.data);
                                    } else {
                                        groups.entry(my.id).or_default().push(my.data);
                                    }
                                }
                            }
                        }
                        for (id, frames) in groups.drain() {
                            let tx = self.conns.lock().unwrap().get(&id).cloned();
                            match tx {
                                Some(tx) => {
                                    let _ = tx.try_send(Incoming::Frames(frames));
                                }
                                None => self.send_kick(&id),
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

    // ── Отправка служебных пакетов ───────────────────────────────────────

    fn send_kick(&self, id: &str) {
        let my = MyMsg {
            id: id.to_string(),
            r#type: MSG_KICK,
            rproto: RECV_PROTO,
            key: self.cfg.key,
            ..Default::default()
        };
        let bytes = encode_packet(my, SEND_PROTO, self.id, self.next_seq(), self.crypto.as_ref());
        let _ = self.tx.try_send((self.server_ip(), bytes));
    }

    fn ping(&self) {
        let my = MyMsg {
            r#type: MSG_PING,
            data: now_ns().to_le_bytes().to_vec(),
            rproto: RECV_PROTO,
            key: self.cfg.key,
            ..Default::default()
        };
        let bytes = encode_packet(my, SEND_PROTO, self.id, self.next_seq(), self.crypto.as_ref());
        let _ = self.tx.try_send((self.server_ip(), bytes));
    }

    fn frame_packet(&self, id: &str, frame: &Frame, target: &str, with_params: bool) -> Vec<u8> {
        let my = MyMsg {
            id: id.to_string(),
            r#type: MSG_DATA,
            target: target.to_string(),
            data: marshal_frame(frame),
            rproto: RECV_PROTO,
            key: self.cfg.key,
            tcpmode: 1,
            tcpmode_buffersize: if with_params { self.cfg.buffersize } else { 0 },
            tcpmode_maxwin: if with_params { self.cfg.maxwin } else { 0 },
            tcpmode_resend_timems: if with_params { self.cfg.resend } else { 0 },
            tcpmode_compress: if with_params { self.cfg.compress } else { 0 },
            timeout: if with_params { self.cfg.timeout } else { 0 },
            ..Default::default()
        };
        encode_packet(my, SEND_PROTO, self.id, self.next_seq(), self.crypto.as_ref())
    }

    // ── UDP-проброс ───────────────────────────────────────────────────────

    fn send_udp(&self, id: &str, target: &str, data: &[u8]) {
        let my = MyMsg {
            id: id.to_string(),
            r#type: MSG_DATA,
            target: target.to_string(),
            data: data.to_vec(),
            rproto: RECV_PROTO,
            key: self.cfg.key,
            tcpmode: 0,
            timeout: self.cfg.timeout,
            ..Default::default()
        };
        let bytes = encode_packet(my, SEND_PROTO, self.id, self.next_seq(), self.crypto.as_ref());
        self.counters.add_send(data.len());
        let _ = self.tx.try_send((self.server_ip(), bytes));
    }

    /// Пишет ответный UDP-датаграм локально (sync, неблокирующе).
    fn reply_udp(&self, uc: &UdpConn, target_from_pkt: &str, data: &[u8]) {
        if uc.socks5 {
            let target = if !target_from_pkt.is_empty() {
                target_from_pkt
            } else {
                &uc.target
            };
            if let Ok(dgram) = socks5::build_udp_datagram(target, data) {
                let _ = uc.sock.try_send_to(&dgram, uc.src);
            }
        } else {
            let _ = uc.sock.try_send_to(data, uc.src);
        }
        uc.last.store(now_ns(), Ordering::Relaxed);
    }

    /// Находит/создаёт UDP-соединение по ключу адреса. Возвращает id.
    fn get_or_create_udp(
        &self,
        addr_key: String,
        src: SocketAddr,
        sock: Arc<UdpSocket>,
        socks5: bool,
        target: String,
    ) -> String {
        if let Some(id) = self.udp_by_addr.lock().unwrap().get(&addr_key) {
            return id.clone();
        }
        let id = unique_id();
        let uc = Arc::new(UdpConn {
            src,
            sock,
            socks5,
            target,
            addr_key: addr_key.clone(),
            last: AtomicI64::new(now_ns()),
        });
        self.udp_conns.lock().unwrap().insert(id.clone(), uc);
        self.udp_by_addr.lock().unwrap().insert(addr_key, id.clone());
        id
    }

    fn close_udp(&self, id: &str) {
        if let Some(uc) = self.udp_conns.lock().unwrap().remove(id) {
            self.udp_by_addr.lock().unwrap().remove(&uc.addr_key);
        }
    }

    /// Чистый UDP-проброс: датаграммы с локального порта → сервер → target.
    async fn accept_udp(self: Arc<Self>, sock: Arc<UdpSocket>) -> Result<()> {
        log::info!("client udp forward listen");
        let mut buf = vec![0u8; 65535];
        loop {
            let (n, src) = match sock.recv_from(&mut buf).await {
                Ok(v) => v,
                Err(e) => {
                    log::debug!("udp recv error: {e}");
                    continue;
                }
            };
            let id = self.get_or_create_udp(
                src.to_string(),
                src,
                sock.clone(),
                false,
                self.cfg.target.clone(),
            );
            if let Some(uc) = self.udp_conns.lock().unwrap().get(&id) {
                uc.last.store(now_ns(), Ordering::Relaxed);
            }
            self.send_udp(&id, &self.cfg.target, &buf[..n]);
        }
    }

    /// SOCKS5 UDP ASSOCIATE: поднимаем relay-сокет, держим управляющий TCP.
    async fn accept_socks5_udp(self: Arc<Self>, mut control: tokio::net::TcpStream) {
        let relay = match UdpSocket::bind("0.0.0.0:0").await {
            Ok(s) => Arc::new(s),
            Err(e) => {
                log::debug!("socks5 udp relay bind: {e}");
                let _ =
                    socks5::write_reply_async(&mut control, socks5::REPLY_GENERAL_FAILURE, "0.0.0.0:0")
                        .await;
                return;
            }
        };
        let mut relay_addr = relay.local_addr().unwrap();
        if relay_addr.ip().is_unspecified() {
            if let Ok(local) = control.local_addr() {
                relay_addr = SocketAddr::new(local.ip(), relay_addr.port());
            }
        }
        if socks5::write_reply_async(&mut control, socks5::REPLY_SUCCEEDED, &relay_addr.to_string())
            .await
            .is_err()
        {
            return;
        }
        log::debug!("socks5 udp associate relay {relay_addr}");

        let me = self.clone();
        let relay2 = relay.clone();
        let recv = tokio::spawn(async move { me.recv_socks5_udp(relay2).await });

        // Держим управляющий TCP открытым; разрыв = конец ассоциации.
        let mut b = [0u8; 1];
        loop {
            match control.read(&mut b).await {
                Ok(0) | Err(_) => break,
                Ok(_) => {}
            }
        }
        recv.abort();
        self.close_socks5_udp_flows(&relay);
        log::debug!("socks5 udp associate closed {relay_addr}");
    }

    async fn recv_socks5_udp(self: Arc<Self>, relay: Arc<UdpSocket>) {
        let relay_local = relay.local_addr().map(|a| a.to_string()).unwrap_or_default();
        let mut buf = vec![0u8; 65535];
        loop {
            let (n, src) = match relay.recv_from(&mut buf).await {
                Ok(v) => v,
                Err(_) => return,
            };
            let (target, payload) = match socks5::parse_udp_datagram(&buf[..n]) {
                Ok(v) => v,
                Err(_) => continue,
            };
            let key = format!("{relay_local}|{src}|{target}");
            let id = self.get_or_create_udp(key, src, relay.clone(), true, target.clone());
            if let Some(uc) = self.udp_conns.lock().unwrap().get(&id) {
                uc.last.store(now_ns(), Ordering::Relaxed);
            }
            self.send_udp(&id, &target, &payload);
        }
    }

    fn close_socks5_udp_flows(&self, relay: &Arc<UdpSocket>) {
        let ids: Vec<String> = self
            .udp_conns
            .lock()
            .unwrap()
            .iter()
            .filter(|(_, uc)| uc.socks5 && Arc::ptr_eq(&uc.sock, relay))
            .map(|(id, _)| id.clone())
            .collect();
        for id in ids {
            self.close_udp(&id);
        }
    }

    // ── Локальные соединения ─────────────────────────────────────────────

    async fn handle_socks5(self: Arc<Self>, mut sock: tokio::net::TcpStream) {
        if let Err(e) =
            socks5::server_handshake_async(&mut sock, &self.cfg.s5user, &self.cfg.s5pass).await
        {
            log::debug!("socks handshake: {e}");
            return;
        }
        let req = match socks5::read_request_async(&mut sock).await {
            Ok(r) => r,
            Err(e) => {
                log::debug!("socks request: {e}");
                let _ =
                    socks5::write_reply_async(&mut sock, socks5::REPLY_GENERAL_FAILURE, "0.0.0.0:0")
                        .await;
                return;
            }
        };
        match req.command {
            socks5::CMD_CONNECT => {
                if socks5::write_reply_async(&mut sock, socks5::REPLY_SUCCEEDED, "0.0.0.0:0")
                    .await
                    .is_err()
                {
                    return;
                }
                self.serve_conn(sock, req.address).await;
            }
            socks5::CMD_UDP_ASSOCIATE => {
                self.accept_socks5_udp(sock).await;
            }
            other => {
                log::debug!("unsupported socks command: {other}");
                let _ = socks5::write_reply_async(
                    &mut sock,
                    socks5::REPLY_COMMAND_NOT_SUPPORTED,
                    "0.0.0.0:0",
                )
                .await;
            }
        }
    }

    async fn serve_conn(self: Arc<Self>, stream: tokio::net::TcpStream, target: String) {
        let id = unique_id();
        let (ctx, crx) = mpsc::channel::<Incoming>(2048);
        self.conns.lock().unwrap().insert(id.clone(), ctx);
        self.pump(stream, target, &id, crx).await;
        self.conns.lock().unwrap().remove(&id);
    }

    /// Главный event-loop соединения: гоняет FrameMgr по событиям, без busy-poll.
    async fn pump(
        &self,
        stream: tokio::net::TcpStream,
        target: String,
        id: &str,
        mut crx: mpsc::Receiver<Incoming>,
    ) {
        let mut fm = FrameMgr::new(
            self.cfg.frame_size,
            FRAME_MAX_ID as i64,
            self.cfg.buffersize as usize,
            self.cfg.maxwin as i64,
            self.cfg.resend as i64,
            self.cfg.compress as usize,
        );
        fm.connect();
        let (mut rd, mut wr) = stream.into_split();
        let mut rbuf = vec![0u8; 256 * 1024];

        let start = Instant::now();
        let timeout_dur = Duration::from_secs(self.cfg.timeout.max(1) as u64);
        let mut last_recv = Instant::now();
        let mut local_eof = false;
        let mut close_since: Option<Instant> = None;
        let server_ip = self.server_ip();

        loop {
            let connected = fm.is_connected();
            let tick = if fm.has_pending_work() { ACTIVE_TICK } else { IDLE_TICK };
            tokio::select! {
                m = crx.recv() => {
                    match m {
                        Some(Incoming::Frames(v)) => {
                            for b in v { if let Ok(f) = Frame::decode(&b[..]) { fm.on_recv_frame(f); } }
                            last_recv = Instant::now();
                            while let Ok(more) = crx.try_recv() {
                                match more {
                                    Incoming::Frames(v) => { for b in v { if let Ok(f)=Frame::decode(&b[..]) { fm.on_recv_frame(f); } } }
                                    Incoming::Kick => { fm.close(); }
                                }
                            }
                        }
                        Some(Incoming::Kick) | None => fm.close(),
                    }
                }
                r = rd.read(&mut rbuf), if connected && !local_eof && fm.get_send_buffer_left() > 0 => {
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
                let with_params = !connected;
                for f in &list {
                    let bytes = self.frame_packet(id, f, &target, with_params);
                    self.counters.add_send(bytes.len());
                    let _ = self.tx.send((server_ip, bytes)).await;
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

            if !fm.is_connected() {
                if start.elapsed() > Duration::from_secs(5) {
                    break;
                }
            }
            if fm.is_remote_closed() {
                break;
            }
            // Таймаут по «тишине от пира»: живой пир шлёт ping/hb каждую секунду,
            // поэтому last_recv обновляется. Нельзя завязываться на last_send —
            // мы сами шлём ping/hb постоянно, и условие никогда бы не срабатывало
            // (это и приводило к утечке зомби-соединений и росту счётчиков).
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
    }

    // ── Обслуживание ─────────────────────────────────────────────────────

    async fn maintenance(self: Arc<Self>) {
        let mut tick = tokio::time::interval(Duration::from_secs(1));
        loop {
            tick.tick().await;
            self.ping();
            // Закрываем неактивные UDP-соединения.
            let now = now_ns();
            let timeout_ns = self.cfg.timeout.max(1) as i64 * 1_000_000_000;
            let stale: Vec<String> = self
                .udp_conns
                .lock()
                .unwrap()
                .iter()
                .filter(|(_, uc)| now - uc.last.load(Ordering::Relaxed) > timeout_ns)
                .map(|(id, _)| id.clone())
                .collect();
            for id in stale {
                self.close_udp(&id);
            }
            let (sp, ss, rp, rs) = self.counters.take();
            let n = self.conns.lock().unwrap().len() + self.udp_conns.lock().unwrap().len();
            log::info!("send {sp}Packet/s {ss}KB/s recv {rp}Packet/s {rs}KB/s {n}Connections");
            if let Ok(ip) = resolve_ipv4(&self.cfg.server) {
                let mut cur = self.server_ip.lock().unwrap();
                if *cur != ip {
                    log::info!("server ip refreshed {} -> {}", *cur, ip);
                    *cur = ip;
                }
            }
        }
    }
}

fn normalize_bind(addr: &str) -> String {
    if let Some(rest) = addr.strip_prefix('*') {
        return format!("0.0.0.0{rest}");
    }
    if addr.starts_with(':') {
        return format!("0.0.0.0{addr}");
    }
    addr.to_string()
}
