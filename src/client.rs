//! Async-клиент на tokio: принимает локальные TCP/SOCKS5 соединения и
//! туннелирует их поверх ICMP. Каждое соединение — задача (не ОС-поток),
//! работает по событиям (входящий фрейм / локальные данные / таймер), а не
//! busy-poll. Исходящие пакеты идут в единый write-таск (sendmmsg-батчинг).

use crate::crypto::Crypto;
use crate::framemgr::{marshal_frame, FrameMgr};
use crate::icmp::{self, encode_packet, IcmpIo, OutPkt, RecvBatch, RecvMode, Wire, ICMP_ECHO_REQUEST};
use crate::proto::*;
use crate::socks5;
use crate::stats::{ConnInfo, ConnKind, Stats};
use crate::udprel;
use crate::util::{now_ns, resolve_ipv4, trim_memory, unique_id};
use anyhow::Result;
use prost::Message as _;
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicI64, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream};
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
    /// Надёжный UDP-проброс: датаграммы идут через FrameMgr (см. [`udprel`]).
    pub udp_reliable: bool,
    /// IP-протоколы транспорта. `[1]` = обычный ICMP. Несколько = экспериментальная
    /// ротация: на каждое соединение выбирается случайный протокол из списка
    /// (см. [`icmp::listen_transport`]).
    pub ip_protos: Vec<u8>,
    /// Максимум случайных байт паддинга на пакет (Dynamic Packet Padding; 0 = off).
    pub pad_max: u16,
    /// Обфускация заголовка (Header Obfuscation): снять echo-обёртку, на проводе
    /// только nonce+шифртекст. Требует шифрования и кастомного IP-протокола.
    pub obfs: bool,
    /// Базовый интервал фонового keep-alive (ping), сек.
    pub keepalive_secs: u64,
    /// Джиттер keep-alive: разброс +/- сек вокруг базового интервала (0 = строго).
    pub keepalive_jitter: u64,
    /// Интервал возврата свободной памяти ОС (malloc_trim), сек. 0 = выключено.
    pub mem_trim_secs: u64,
}

/// Сообщение в задачу соединения. Frames — пачка фреймов из одного recvmmsg-батча
/// для одного соединения, чтобы FrameMgr обработал их за один update → батч-ACK.
enum Incoming {
    Frames(Vec<Vec<u8>>),
    Kick,
}

/// Простое UDP-соединение (без FrameMgr — прямой проброс датаграмм, без гарантий
/// доставки). Используется в обычном режиме; надёжный режим (`udp_reliable`) идёт
/// через FrameMgr и эту структуру не задействует.
struct UdpConn {
    src: SocketAddr,      // куда слать ответы локально
    sock: Arc<UdpSocket>, // через какой сокет (listen для plain, relay для socks5)
    socks5: bool,         // оборачивать ответ в socks5-датаграмму
    target: String,       // целевой адрес (для socks5-датаграммы)
    addr_key: String,     // ключ в udp_by_addr
    last: AtomicI64,      // время последней активности
    proto: u8,            // IP-протокол транспорта этого соединения (ротация)
    info: Arc<ConnInfo>,  // запись в реестре статистики (per-conn байты)
}

pub struct Client {
    cfg: ClientConfig,
    rx: Arc<IcmpIo>,
    tx: mpsc::Sender<OutPkt>,
    wire: Wire,
    datagram: bool,
    id: u16,
    seq: AtomicU32,
    server_ip: Mutex<Ipv4Addr>,
    // Соединения с FrameMgr-надёжностью (TCP, SOCKS5-CONNECT и надёжный UDP):
    // conn-id → канал входящих фреймов в задачу соединения.
    conns: Mutex<HashMap<String, mpsc::Sender<Incoming>>>,
    // Простые UDP-соединения (прямой проброс): conn-id → соединение.
    udp_conns: Mutex<HashMap<String, Arc<UdpConn>>>,
    udp_by_addr: Mutex<HashMap<String, String>>,
    counters: Arc<Stats>,
}

impl Client {
    pub fn new(cfg: ClientConfig, crypto: Option<Crypto>, stats: Arc<Stats>) -> Result<Arc<Client>> {
        let t = icmp::listen_transport(&cfg.icmp_listen, &cfg.ip_protos)?;
        let tx = icmp::spawn_writer(&t, 8192);
        let datagram = t.recv_mode == RecvMode::InetDatagram;
        let rx = t.rx;
        let server_ip = resolve_ipv4(&cfg.server)?;
        let id = (rand::random::<u16>() & 0x7fff).max(1);
        let wire = Wire::new(crypto, cfg.pad_max, cfg.obfs);
        Ok(Arc::new(Client {
            cfg,
            rx,
            tx,
            wire,
            datagram,
            id,
            seq: AtomicU32::new(0),
            server_ip: Mutex::new(server_ip),
            conns: Mutex::new(HashMap::new()),
            udp_conns: Mutex::new(HashMap::new()),
            udp_by_addr: Mutex::new(HashMap::new()),
            counters: stats,
        }))
    }

    fn next_seq(&self) -> u16 {
        self.seq.fetch_add(1, Ordering::Relaxed) as u16
    }
    fn server_ip(&self) -> Ipv4Addr {
        *self.server_ip.lock().unwrap()
    }

    /// Выбирает IP-протокол транспорта для нового соединения (ротация). При
    /// единственном протоколе всегда он.
    fn pick_proto(&self) -> u8 {
        let protos = &self.cfg.ip_protos;
        if protos.len() == 1 {
            protos[0]
        } else {
            protos[(rand::random::<u32>() as usize) % protos.len()]
        }
    }

    pub async fn run(self: Arc<Self>) -> Result<()> {
        tokio::spawn(self.clone().read_loop());
        tokio::spawn(self.clone().maintenance());
        tokio::spawn(self.clone().keepalive());

        log::info!(
            "Client listen {} server {} ({}) icmp {} (async, frame={}B, protos={}){}",
            self.cfg.listen,
            self.cfg.server,
            self.server_ip(),
            self.cfg.icmp_listen,
            self.cfg.frame_size,
            self.cfg.ip_protos.len(),
            if self.cfg.udp_reliable { ", udp=reliable" } else { "" }
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
        let mut recv_batch = RecvBatch::new(32);
        let mut groups: HashMap<String, Vec<Vec<u8>>> = HashMap::new();
        loop {
            let mut guard = match self.rx.fd.readable().await {
                Ok(g) => g,
                Err(_) => break,
            };
            loop {
                match guard.try_io(|s| recv_batch.recv(s.get_ref())) {
                    Ok(Ok(n)) => {
                        groups.clear();
                        for i in 0..n {
                            let (raw, _src) = recv_batch.get(i);
                            let (msg, echo_id, _seq) =
                                match icmp::parse_packet(raw, self.datagram, &self.wire) {
                                    Some(v) => v,
                                    None => continue,
                                };
                            if msg.rproto >= 0 || msg.key != self.cfg.key {
                                continue;
                            }
                            // В obfs нет echo-заголовка: echo_id отсутствует
                            // (parse возвращает 0), фильтр по id пропускаем.
                            if !self.datagram && !self.wire.obfs() && echo_id != self.id {
                                continue;
                            }
                            match msg.r#type {
                                x if x == MSG_PING => {}
                                x if x == MSG_KICK => {
                                    let tx = self.conns.lock().unwrap().get(&msg.id).cloned();
                                    if let Some(tx) = tx {
                                        let _ = tx.try_send(Incoming::Kick);
                                    }
                                }
                                _ => {
                                    self.counters.add_recv(msg.data.len());
                                    // Простое UDP-соединение? — отвечаем сразу, не группируя
                                    // как фрейм. Надёжные UDP-соединения живут в `conns` и
                                    // сюда не попадают (идут общим путём фреймов ниже).
                                    let flow = self.udp_conns.lock().unwrap().get(&msg.id).cloned();
                                    if let Some(flow) = flow {
                                        self.reply_udp(&flow, &msg.target, &msg.data);
                                    } else {
                                        groups.entry(msg.id).or_default().push(msg.data);
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
        let msg = MyMsg {
            id: id.to_string(),
            r#type: MSG_KICK,
            rproto: RECV_PROTO,
            key: self.cfg.key,
            ..Default::default()
        };
        let bytes = encode_packet(msg, SEND_PROTO, self.id, self.next_seq(), &self.wire);
        let _ = self.tx.try_send((self.server_ip(), bytes, self.pick_proto()));
    }

    fn ping(&self) {
        let msg = MyMsg {
            r#type: MSG_PING,
            data: now_ns().to_le_bytes().to_vec(),
            rproto: RECV_PROTO,
            key: self.cfg.key,
            ..Default::default()
        };
        let bytes = encode_packet(msg, SEND_PROTO, self.id, self.next_seq(), &self.wire);
        let _ = self.tx.try_send((self.server_ip(), bytes, self.pick_proto()));
    }

    /// Пакует один фрейм FrameMgr в ICMP-пакет. `with_params` — отправить ли
    /// параметры соединения (только в connect-пакете). `udp` — это надёжное
    /// UDP-соединение (сервер откроет цель как UDP).
    fn frame_packet(&self, id: &str, frame: &Frame, target: &str, with_params: bool, udp: bool) -> Vec<u8> {
        let msg = MyMsg {
            id: id.to_string(),
            r#type: MSG_DATA,
            target: target.to_string(),
            data: marshal_frame(frame),
            rproto: RECV_PROTO,
            key: self.cfg.key,
            tcpmode: 1,
            udp: if udp { 1 } else { 0 },
            tcpmode_buffersize: if with_params { self.cfg.buffersize } else { 0 },
            tcpmode_maxwin: if with_params { self.cfg.maxwin } else { 0 },
            tcpmode_resend_timems: if with_params { self.cfg.resend } else { 0 },
            tcpmode_compress: if with_params { self.cfg.compress } else { 0 },
            timeout: if with_params { self.cfg.timeout } else { 0 },
            ..Default::default()
        };
        encode_packet(msg, SEND_PROTO, self.id, self.next_seq(), &self.wire)
    }

    // ── Простой UDP-проброс (без гарантий доставки) ───────────────────────

    fn send_udp(&self, id: &str, target: &str, data: &[u8], proto: u8) {
        let msg = MyMsg {
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
        let bytes = encode_packet(msg, SEND_PROTO, self.id, self.next_seq(), &self.wire);
        self.counters.add_send(data.len());
        let _ = self.tx.try_send((self.server_ip(), bytes, proto));
    }

    /// Пишет ответный UDP-датаграм локально (sync, неблокирующе).
    fn reply_udp(&self, flow: &UdpConn, target_from_pkt: &str, data: &[u8]) {
        if flow.socks5 {
            let target = if !target_from_pkt.is_empty() {
                target_from_pkt
            } else {
                &flow.target
            };
            if let Ok(dgram) = socks5::build_udp_datagram(target, data) {
                let _ = flow.sock.try_send_to(&dgram, flow.src);
            }
        } else {
            let _ = flow.sock.try_send_to(data, flow.src);
        }
        flow.info.add_recv(data.len());
        flow.last.store(now_ns(), Ordering::Relaxed);
    }

    /// Находит/создаёт простое UDP-соединение по ключу адреса. Возвращает id.
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
        let proto = self.pick_proto();
        let info = self
            .counters
            .register(id.clone(), ConnKind::Udp, target.clone(), proto);
        let flow = Arc::new(UdpConn {
            src,
            sock,
            socks5,
            target,
            addr_key: addr_key.clone(),
            last: AtomicI64::new(now_ns()),
            proto,
            info,
        });
        self.udp_conns.lock().unwrap().insert(id.clone(), flow);
        self.udp_by_addr.lock().unwrap().insert(addr_key, id.clone());
        id
    }

    fn close_udp(&self, id: &str) {
        if let Some(flow) = self.udp_conns.lock().unwrap().remove(id) {
            self.udp_by_addr.lock().unwrap().remove(&flow.addr_key);
        }
        self.counters.unregister(id);
    }

    /// Чистый UDP-проброс: датаграммы с локального порта → сервер → target.
    /// В надёжном режиме каждый локальный источник обслуживается отдельной
    /// FrameMgr-задачей (см. [`serve_udp_flow`](Self::serve_udp_flow)).
    async fn accept_udp(self: Arc<Self>, sock: Arc<UdpSocket>) -> Result<()> {
        if self.cfg.udp_reliable {
            return self.accept_udp_reliable(sock).await;
        }
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
            let proto = {
                let conns = self.udp_conns.lock().unwrap();
                match conns.get(&id) {
                    Some(flow) => {
                        flow.info.add_send(n);
                        flow.last.store(now_ns(), Ordering::Relaxed);
                        flow.proto
                    }
                    None => self.pick_proto(),
                }
            };
            self.send_udp(&id, &self.cfg.target, &buf[..n], proto);
        }
    }

    /// Надёжный UDP-проброс: на каждый локальный источник держим FrameMgr-задачу
    /// и раздаём ей датаграммы через канал. Задача сама закрывается по простою,
    /// и при следующей датаграмме источника поднимается заново.
    async fn accept_udp_reliable(self: Arc<Self>, sock: Arc<UdpSocket>) -> Result<()> {
        log::info!("client udp forward listen (reliable)");
        // Источник датаграмм → канал в его FrameMgr-задачу. Цикл приёма —
        // единственный писатель, поэтому карта локальна для этой задачи.
        let mut flows: HashMap<SocketAddr, mpsc::Sender<Vec<u8>>> = HashMap::new();
        let idle = Duration::from_secs(self.cfg.timeout.max(1) as u64);
        let mut buf = vec![0u8; 65535];
        loop {
            let (n, src) = match sock.recv_from(&mut buf).await {
                Ok(v) => v,
                Err(e) => {
                    log::debug!("udp recv error: {e}");
                    continue;
                }
            };
            let mut datagram = buf[..n].to_vec();
            if let Some(to_flow) = flows.get(&src) {
                match to_flow.try_send(datagram) {
                    Ok(()) => continue,
                    Err(mpsc::error::TrySendError::Full(_)) => continue, // backpressure: дроп
                    // Задача источника завершилась (простой) — поднимем заново.
                    Err(mpsc::error::TrySendError::Closed(d)) => datagram = d,
                }
            }
            let (to_flow, from_app) = mpsc::channel::<Vec<u8>>(1024);
            let _ = to_flow.try_send(datagram);
            flows.insert(src, to_flow);
            // Ответы цели возвращаем приложению как есть, на его адрес.
            let reply_sock = sock.clone();
            let stream = udprel::spawn_client_bridge(
                from_app,
                move |datagram| {
                    let _ = reply_sock.try_send_to(datagram, src);
                },
                idle,
            );
            tokio::spawn(self.clone().serve_reliable_udp(stream, self.cfg.target.clone()));
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
        // В надёжном режиме каждый поток (src+target) обслуживается FrameMgr-задачей;
        // карта живёт здесь и закрывается вместе с recv-задачей при разрыве ассоциации.
        let mut flows: HashMap<String, mpsc::Sender<Vec<u8>>> = HashMap::new();
        let idle = Duration::from_secs(self.cfg.timeout.max(1) as u64);
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

            // Надёжный режим: поток (src+target) обслуживается FrameMgr-задачей.
            // Ответы цели возвращаем приложению обёрнутыми в SOCKS5 UDP-датаграмму
            // на исходный `src` через тот же relay-сокет.
            if self.cfg.udp_reliable {
                let mut payload = payload;
                if let Some(to_flow) = flows.get(&key) {
                    match to_flow.try_send(payload) {
                        Ok(()) => continue,
                        Err(mpsc::error::TrySendError::Full(_)) => continue, // backpressure: дроп
                        Err(mpsc::error::TrySendError::Closed(d)) => payload = d, // поток закрылся — заново
                    }
                }
                let (to_flow, from_app) = mpsc::channel::<Vec<u8>>(1024);
                let _ = to_flow.try_send(payload);
                flows.insert(key, to_flow);
                let reply_sock = relay.clone();
                let reply_target = target.clone();
                let stream = udprel::spawn_client_bridge(
                    from_app,
                    move |datagram| {
                        if let Ok(dgram) = socks5::build_udp_datagram(&reply_target, datagram) {
                            let _ = reply_sock.try_send_to(&dgram, src);
                        }
                    },
                    idle,
                );
                tokio::spawn(self.clone().serve_reliable_udp(stream, target));
                continue;
            }

            let id = self.get_or_create_udp(key, src, relay.clone(), true, target.clone());
            let proto = {
                let conns = self.udp_conns.lock().unwrap();
                match conns.get(&id) {
                    Some(flow) => {
                        flow.info.add_send(payload.len());
                        flow.last.store(now_ns(), Ordering::Relaxed);
                        flow.proto
                    }
                    None => self.pick_proto(),
                }
            };
            self.send_udp(&id, &target, &payload, proto);
        }
    }

    fn close_socks5_udp_flows(&self, relay: &Arc<UdpSocket>) {
        let ids: Vec<String> = self
            .udp_conns
            .lock()
            .unwrap()
            .iter()
            .filter(|(_, flow)| flow.socks5 && Arc::ptr_eq(&flow.sock, relay))
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

    /// TCP/SOCKS5-CONNECT соединение: гоняем локальный поток через FrameMgr.
    async fn serve_conn(self: Arc<Self>, stream: tokio::net::TcpStream, target: String) {
        let id = unique_id();
        let proto = self.pick_proto();
        let info = self
            .counters
            .register(id.clone(), ConnKind::Tcp, target.clone(), proto);
        let (frames_tx, frames_rx) = mpsc::channel::<Incoming>(2048);
        self.conns.lock().unwrap().insert(id.clone(), frames_tx);
        self.pump(stream, target, &id, false, proto, frames_rx, info).await;
        self.conns.lock().unwrap().remove(&id);
        self.counters.unregister(&id);
    }

    /// Обслуживает один надёжный UDP-поток (см. [`udprel`]): регистрирует
    /// FrameMgr-соединение и качает данные через `pump`, как у TCP. `stream` —
    /// готовый UDP↔поток-мост (его построил вызывающий, зная, как доставлять
    /// ответы приложению: напрямую или обёрнутыми в SOCKS5-датаграмму).
    async fn serve_reliable_udp(self: Arc<Self>, stream: DuplexStream, target: String) {
        let id = unique_id();
        let proto = self.pick_proto();
        let info = self
            .counters
            .register(id.clone(), ConnKind::UdpReliable, target.clone(), proto);
        let (frames_tx, frames_rx) = mpsc::channel::<Incoming>(2048);
        self.conns.lock().unwrap().insert(id.clone(), frames_tx);
        self.pump(stream, target, &id, true, proto, frames_rx, info).await;
        self.conns.lock().unwrap().remove(&id);
        self.counters.unregister(&id);
    }

    /// Главный event-loop соединения: гоняет FrameMgr по событиям, без busy-poll.
    /// `udp` — это надёжное UDP-соединение (сервер откроет цель как UDP).
    #[allow(clippy::too_many_arguments)]
    async fn pump<S>(
        &self,
        mut stream: S,
        target: String,
        id: &str,
        udp: bool,
        proto: u8,
        mut frames_rx: mpsc::Receiver<Incoming>,
        info: Arc<ConnInfo>,
    ) where
        S: AsyncRead + AsyncWrite + Unpin + Send,
    {
        let mut fm = FrameMgr::new(
            self.cfg.frame_size,
            FRAME_MAX_ID as i64,
            self.cfg.buffersize as usize,
            self.cfg.maxwin as i64,
            self.cfg.resend as i64,
            self.cfg.compress as usize,
        );
        fm.connect();
        // Чтение и запись локального потока идут последовательно в одной задаче
        // (read в select, write после него), поэтому делить поток на половины не
        // нужно — гоняем один `&mut stream` без накладных расходов split/BiLock.
        let mut read_buf = vec![0u8; 256 * 1024];

        let start = Instant::now();
        let timeout_dur = Duration::from_secs(self.cfg.timeout.max(1) as u64);
        let mut last_recv = Instant::now();
        let mut local_eof = false;
        let mut close_since: Option<Instant> = None;
        let server_ip = self.server_ip();

        loop {
            let connected = fm.is_connected();
            // Читаем из локального сокета не больше, чем влезет в send-буфер:
            // RBuffer::write всё-или-ничего и молча отбрасывает то, что не влезло.
            // Без этого ограничения при переполнении буфера данные терялись (нет
            // backpressure). Совпадает с min(sendBufferLeft, buf) в Go-оригинале.
            let send_left = fm.get_send_buffer_left();
            let read_cap = send_left.min(read_buf.len());
            let tick = if fm.has_pending_work() { ACTIVE_TICK } else { IDLE_TICK };
            tokio::select! {
                m = frames_rx.recv() => {
                    match m {
                        Some(Incoming::Frames(v)) => {
                            for b in v { info.add_recv(b.len()); if let Ok(f) = Frame::decode(&b[..]) { fm.on_recv_frame(f); } }
                            last_recv = Instant::now();
                            while let Ok(more) = frames_rx.try_recv() {
                                match more {
                                    Incoming::Frames(v) => { for b in v { info.add_recv(b.len()); if let Ok(f)=Frame::decode(&b[..]) { fm.on_recv_frame(f); } } }
                                    Incoming::Kick => { fm.close(); }
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
                let with_params = !connected;
                for f in &list {
                    let bytes = self.frame_packet(id, f, &target, with_params, udp);
                    self.counters.add_send(bytes.len());
                    info.add_send(bytes.len());
                    let _ = self.tx.send((server_ip, bytes, proto)).await;
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

    /// Фоновый keep-alive: шлёт транспортный ping, чтобы удержать NAT/сессию,
    /// когда туннель простаивает. Интервал - `--keepalive` сек, плюс случайный
    /// джиттер +/- `--keepalive_jitter` сек (через `sleep`, а не `interval`),
    /// чтобы фоновые пакеты не образовывали строго периодичный «пульс».
    async fn keepalive(self: Arc<Self>) {
        let base = self.cfg.keepalive_secs.max(1);
        let jitter = self.cfg.keepalive_jitter;
        loop {
            let secs = if jitter == 0 {
                base as f64
            } else {
                let lo = base.saturating_sub(jitter).max(1) as f64;
                let hi = (base + jitter) as f64;
                lo + rand::random::<f64>() * (hi - lo)
            };
            tokio::time::sleep(Duration::from_secs_f64(secs)).await;
            self.ping();
        }
    }

    async fn maintenance(self: Arc<Self>) {
        let mut tick = tokio::time::interval(Duration::from_secs(1));
        let mut since_trim = 0u32;
        loop {
            tick.tick().await;
            // Закрываем неактивные простые UDP-соединения (надёжные закрываются
            // сами в своих задачах по простою).
            let now = now_ns();
            let timeout_ns = self.cfg.timeout.max(1) as i64 * 1_000_000_000;
            let stale: Vec<String> = self
                .udp_conns
                .lock()
                .unwrap()
                .iter()
                .filter(|(_, flow)| now - flow.last.load(Ordering::Relaxed) > timeout_ns)
                .map(|(id, _)| id.clone())
                .collect();
            for id in stale {
                self.close_udp(&id);
            }
            let (send_pkts, send_kb, recv_pkts, recv_kb) = self.counters.take();
            let conns = self.conns.lock().unwrap().len() + self.udp_conns.lock().unwrap().len();
            log::info!(
                "send {send_pkts}Packet/s {send_kb}KB/s recv {recv_pkts}Packet/s {recv_kb}KB/s {conns}Connections"
            );
            if let Ok(ip) = resolve_ipv4(&self.cfg.server) {
                let mut cur = self.server_ip.lock().unwrap();
                if *cur != ip {
                    log::info!("server ip refreshed {} -> {}", *cur, ip);
                    *cur = ip;
                }
            }
            // Опционально (--mem_trim N): возвращаем ОС память, освобождённую
            // закрытыми соединениями (glibc сам её не отдаёт - см. [`trim_memory`]).
            if self.cfg.mem_trim_secs > 0 {
                since_trim += 1;
                if since_trim >= self.cfg.mem_trim_secs as u32 {
                    since_trim = 0;
                    trim_memory();
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
