//! Клиент: принимает локальные TCP/UDP/SOCKS5 соединения и туннелирует их
//! поверх ICMP к серверу. Порт client.go.

use crate::crypto::Crypto;
use crate::framemgr::{marshal_frame, FrameMgr};
use crate::icmp::{self, ICMP_ECHO_REQUEST};
use crate::proto::*;
use crate::socks5;
use crate::util::{now_ns, resolve_ipv4, unique_id, Backoff, Counters};
use anyhow::Result;
use prost::Message as _;
use socket2::Socket;
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const SEND_PROTO: u8 = ICMP_ECHO_REQUEST; // 8
const RECV_PROTO: i32 = 0;
const POLL: Duration = Duration::from_millis(2);

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
    pub stat: i32,
    pub sock5: i32,
    pub maxconn: i32,
    pub s5user: String,
    pub s5pass: String,
}

struct ClientConn {
    id: String,
    addr_key: Mutex<String>,
    tcpmode: i32,
    fm: Option<Arc<Mutex<FrameMgr>>>,
    exit: AtomicBool,
    active_recv: AtomicI64,
    active_send: AtomicI64,
    // UDP-режим
    udp_ipaddr: Mutex<Option<SocketAddr>>,
    udp_relay: Mutex<Option<Arc<UdpSocket>>>,
    udp_target: Mutex<String>,
}

impl ClientConn {
    fn touch_recv(&self) {
        self.active_recv.store(now_ns(), Ordering::Relaxed);
    }
    fn touch_send(&self) {
        self.active_send.store(now_ns(), Ordering::Relaxed);
    }
}

pub struct Client {
    cfg: ClientConfig,
    socket: Socket,
    crypto: Option<Crypto>,
    datagram: bool,
    id: u16,
    seq: AtomicU32,
    server_ip: Mutex<Ipv4Addr>,
    counters: Counters,
    exit: AtomicBool,
    by_id: Mutex<HashMap<String, Arc<ClientConn>>>,
    by_addr: Mutex<HashMap<String, Arc<ClientConn>>>,
    listen_udp: Mutex<Option<Arc<UdpSocket>>>,
}

impl Client {
    pub fn new(cfg: ClientConfig, crypto: Option<Crypto>) -> Result<Arc<Client>> {
        let (socket, datagram) = icmp::listen_icmp(&cfg.icmp_listen)?;
        let server_ip = resolve_ipv4(&cfg.server)?;
        let id = (rand::random::<u16>() & 0x7fff).max(1);
        Ok(Arc::new(Client {
            cfg,
            socket,
            crypto,
            datagram,
            id,
            seq: AtomicU32::new(0),
            server_ip: Mutex::new(server_ip),
            counters: Counters::default(),
            exit: AtomicBool::new(false),
            by_id: Mutex::new(HashMap::new()),
            by_addr: Mutex::new(HashMap::new()),
            listen_udp: Mutex::new(None),
        }))
    }

    fn next_seq(&self) -> u16 {
        self.seq.fetch_add(1, Ordering::Relaxed) as u16
    }

    fn server_ip(&self) -> Ipv4Addr {
        *self.server_ip.lock().unwrap()
    }

    fn active_count(&self) -> usize {
        self.by_id.lock().unwrap().len()
    }

    pub fn run(self: &Arc<Client>) -> Result<()> {
        let listen = normalize_bind(&self.cfg.listen);
        let tcpmode = self.cfg.tcpmode > 0;
        if tcpmode {
            let listener = TcpListener::bind(&listen)?;
            let me = self.clone();
            std::thread::spawn(move || me.accept_tcp(listener));
        } else {
            let sock = Arc::new(UdpSocket::bind(&listen)?);
            sock.set_read_timeout(Some(Duration::from_millis(100)))?;
            *self.listen_udp.lock().unwrap() = Some(sock.clone());
            let me = self.clone();
            std::thread::spawn(move || me.accept_udp(sock));
        }

        // Диспетчер входящих ICMP-пакетов.
        {
            let me = self.clone();
            std::thread::spawn(move || me.recv_loop());
        }
        // Обслуживание: ping, таймауты, статистика.
        {
            let me = self.clone();
            std::thread::spawn(move || me.maintenance());
        }

        log::info!(
            "Client listen {} server {} ({}) target {} icmp {}",
            self.cfg.listen,
            self.cfg.server,
            self.server_ip(),
            self.cfg.target,
            self.cfg.icmp_listen
        );

        loop {
            std::thread::sleep(Duration::from_secs(3600));
        }
    }

    // ── Отправка ICMP ────────────────────────────────────────────────────

    fn send_data(&self, connid: &str, target: &str, data: Vec<u8>, with_params: bool) {
        let my = MyMsg {
            id: connid.to_string(),
            r#type: MSG_DATA,
            target: target.to_string(),
            data,
            rproto: RECV_PROTO,
            key: self.cfg.key,
            tcpmode: self.cfg.tcpmode,
            tcpmode_buffersize: if with_params { self.cfg.buffersize } else { 0 },
            tcpmode_maxwin: if with_params { self.cfg.maxwin } else { 0 },
            tcpmode_resend_timems: if with_params { self.cfg.resend } else { 0 },
            tcpmode_compress: if with_params { self.cfg.compress } else { 0 },
            tcpmode_stat: if with_params { self.cfg.stat } else { 0 },
            timeout: if with_params { self.cfg.timeout } else { 0 },
            ..Default::default()
        };
        let len = my.data.len();
        let _ = icmp::send_icmp(
            &self.socket,
            self.id,
            self.next_seq(),
            self.server_ip(),
            SEND_PROTO,
            my,
            self.crypto.as_ref(),
        );
        self.counters.add_send(len);
    }

    fn send_udp(&self, connid: &str, target: &str, data: &[u8]) {
        let my = MyMsg {
            id: connid.to_string(),
            r#type: MSG_DATA,
            target: target.to_string(),
            data: data.to_vec(),
            rproto: RECV_PROTO,
            key: self.cfg.key,
            tcpmode: 0,
            timeout: self.cfg.timeout,
            ..Default::default()
        };
        let _ = icmp::send_icmp(
            &self.socket,
            self.id,
            self.next_seq(),
            self.server_ip(),
            SEND_PROTO,
            my,
            self.crypto.as_ref(),
        );
        self.counters.add_send(data.len());
    }

    fn send_kick(&self, connid: &str) {
        let my = MyMsg {
            id: connid.to_string(),
            r#type: MSG_KICK,
            rproto: RECV_PROTO,
            key: self.cfg.key,
            ..Default::default()
        };
        let _ = icmp::send_icmp(
            &self.socket,
            self.id,
            self.next_seq(),
            self.server_ip(),
            SEND_PROTO,
            my,
            self.crypto.as_ref(),
        );
    }

    fn ping(&self) {
        let now = now_ns().to_le_bytes().to_vec();
        let my = MyMsg {
            r#type: MSG_PING,
            data: now,
            rproto: RECV_PROTO,
            key: self.cfg.key,
            ..Default::default()
        };
        let _ = icmp::send_icmp(
            &self.socket,
            self.id,
            self.next_seq(),
            self.server_ip(),
            SEND_PROTO,
            my,
            self.crypto.as_ref(),
        );
    }

    // ── Приём ICMP ───────────────────────────────────────────────────────

    fn recv_loop(self: Arc<Client>) {
        while !self.exit.load(Ordering::Relaxed) {
            match icmp::recv_icmp(&self.socket, self.datagram, self.crypto.as_ref()) {
                Ok(Some(pkt)) => self.process_packet(pkt),
                Ok(None) => {}
                Err(e) => log::debug!("recv icmp error: {e}"),
            }
        }
    }

    fn process_packet(&self, pkt: icmp::Packet) {
        let my = pkt.my;
        if my.rproto >= 0 {
            return; // игнорируем echo request'ы и ответы ядра
        }
        if my.key != self.cfg.key {
            return;
        }
        // В datagram-режиме id управляется ядром, фильтр по echo_id неприменим.
        if !self.datagram && pkt.echo_id != self.id {
            return;
        }

        if my.r#type == MSG_PING {
            if my.data.len() >= 8 {
                let mut b = [0u8; 8];
                b.copy_from_slice(&my.data[..8]);
                let sent = i64::from_le_bytes(b);
                let rtt = now_ns() - sent;
                log::info!("pong from {} {}ms", pkt.src, rtt / 1_000_000);
            }
            return;
        }

        if my.r#type == MSG_KICK {
            // ВАЖНО: сначала освобождаем замок by_id (через let-привязку), и только
            // потом вызываем close_conn, который снова берёт by_id. Иначе временный
            // MutexGuard в `if let` жил бы до конца блока → self-deadlock.
            let conn = self.by_id.lock().unwrap().get(&my.id).cloned();
            if let Some(conn) = conn {
                self.close_conn(&conn);
                log::debug!("remote kick local {}", my.id);
            }
            return;
        }

        let found = self.by_id.lock().unwrap().get(&my.id).cloned();
        let conn = match found {
            Some(c) => c,
            None => {
                self.send_kick(&my.id);
                return;
            }
        };

        conn.touch_recv();

        if conn.tcpmode > 0 {
            match Frame::decode(&my.data[..]) {
                Ok(f) => {
                    if let Some(fm) = &conn.fm {
                        fm.lock().unwrap().on_recv_frame(f);
                    }
                }
                Err(e) => log::debug!("unmarshal tcp frame error: {e}"),
            }
        } else if !my.data.is_empty() {
            let ipaddr = *conn.udp_ipaddr.lock().unwrap();
            if let Some(addr) = ipaddr {
                let relay = conn.udp_relay.lock().unwrap().clone();
                if let Some(relay) = relay {
                    let target = if !my.target.is_empty() {
                        my.target.clone()
                    } else {
                        conn.udp_target.lock().unwrap().clone()
                    };
                    if let Ok(dgram) = socks5::build_udp_datagram(&target, &my.data) {
                        let _ = relay.send_to(&dgram, addr);
                    }
                } else if let Some(listen) = self.listen_udp.lock().unwrap().clone() {
                    let _ = listen.send_to(&my.data, addr);
                }
            }
        }
        self.counters.add_recv(my.data.len());
    }

    // ── Локальный UDP ────────────────────────────────────────────────────

    fn accept_udp(self: Arc<Client>, sock: Arc<UdpSocket>) {
        let mut buf = vec![0u8; 10240];
        while !self.exit.load(Ordering::Relaxed) {
            let (n, src) = match sock.recv_from(&mut buf) {
                Ok(v) => v,
                Err(e)
                    if e.kind() == std::io::ErrorKind::WouldBlock
                        || e.kind() == std::io::ErrorKind::TimedOut =>
                {
                    continue
                }
                Err(_) => continue,
            };
            if n == 0 {
                continue;
            }
            let key = src.to_string();
            let conn = self.by_addr.lock().unwrap().get(&key).cloned();
            let conn = match conn {
                Some(c) => c,
                None => {
                    if self.cfg.maxconn > 0 && self.active_count() >= self.cfg.maxconn as usize {
                        continue;
                    }
                    let id = unique_id();
                    let conn = Arc::new(ClientConn {
                        id: id.clone(),
                        addr_key: Mutex::new(key.clone()),
                        tcpmode: 0,
                        fm: None,
                        exit: AtomicBool::new(false),
                        active_recv: AtomicI64::new(now_ns()),
                        active_send: AtomicI64::new(now_ns()),
                        udp_ipaddr: Mutex::new(Some(src)),
                        udp_relay: Mutex::new(None),
                        udp_target: Mutex::new(String::new()),
                    });
                    self.add_conn(&conn);
                    log::debug!("client accept new local udp {id} {key}");
                    conn
                }
            };
            conn.touch_send();
            self.send_udp(&conn.id, &self.cfg.target, &buf[..n]);
        }
    }

    // ── Локальный TCP / SOCKS5 ───────────────────────────────────────────

    fn accept_tcp(self: Arc<Client>, listener: TcpListener) {
        log::info!("client waiting local accept tcp");
        for stream in listener.incoming() {
            if self.exit.load(Ordering::Relaxed) {
                break;
            }
            let stream = match stream {
                Ok(s) => s,
                Err(_) => continue,
            };
            let me = self.clone();
            if self.cfg.sock5 > 0 {
                std::thread::spawn(move || me.accept_socks5(stream));
            } else {
                let target = self.cfg.target.clone();
                std::thread::spawn(move || me.run_tcp_conn(stream, target));
            }
        }
    }

    fn accept_socks5(self: Arc<Client>, mut stream: TcpStream) {
        if let Err(e) = socks5::server_handshake(&mut stream, &self.cfg.s5user, &self.cfg.s5pass) {
            log::debug!("socks handshake: {e}");
            return;
        }
        let req = match socks5::read_request(&mut stream) {
            Ok(r) => r,
            Err(e) => {
                log::debug!("error getting request: {e}");
                let _ = socks5::write_reply(&mut stream, socks5::REPLY_GENERAL_FAILURE, "0.0.0.0:0");
                return;
            }
        };
        match req.command {
            socks5::CMD_CONNECT => {
                if socks5::write_reply(&mut stream, socks5::REPLY_SUCCEEDED, "0.0.0.0:0").is_err() {
                    return;
                }
                log::debug!("accept new sock5 tcp conn: {}", req.address);
                self.run_tcp_conn(stream, req.address);
            }
            socks5::CMD_UDP_ASSOCIATE => {
                self.accept_socks5_udp(stream);
            }
            other => {
                log::info!("unsupported sock5 command: {other}");
                let _ = socks5::write_reply(
                    &mut stream,
                    socks5::REPLY_COMMAND_NOT_SUPPORTED,
                    "0.0.0.0:0",
                );
            }
        }
    }

    fn run_tcp_conn(self: Arc<Client>, stream: TcpStream, target: String) {
        let peer = match stream.peer_addr() {
            Ok(a) => a.to_string(),
            Err(_) => return,
        };
        if self.cfg.maxconn > 0 && self.active_count() >= self.cfg.maxconn as usize {
            log::debug!("too many connections, reject {peer}");
            return;
        }
        let id = unique_id();
        let fm = Arc::new(Mutex::new(FrameMgr::new(
            FRAME_MAX_SIZE,
            FRAME_MAX_ID as i64,
            self.cfg.buffersize as usize,
            self.cfg.maxwin as i64,
            self.cfg.resend as i64,
            self.cfg.compress as usize,
        )));
        let conn = Arc::new(ClientConn {
            id: id.clone(),
            addr_key: Mutex::new(peer.clone()),
            tcpmode: 1,
            fm: Some(fm.clone()),
            exit: AtomicBool::new(false),
            active_recv: AtomicI64::new(now_ns()),
            active_send: AtomicI64::new(now_ns()),
            udp_ipaddr: Mutex::new(None),
            udp_relay: Mutex::new(None),
            udp_target: Mutex::new(String::new()),
        });
        self.add_conn(&conn);
        log::debug!("client accept new local tcp {id} {peer}");

        fm.lock().unwrap().connect();

        // Фаза установления соединения (CONN с полным набором tcp-параметров).
        let start = Instant::now();
        let mut backoff = Backoff::new(2, 30);
        loop {
            if self.exit.load(Ordering::Relaxed) || conn.exit.load(Ordering::Relaxed) {
                break;
            }
            if fm.lock().unwrap().is_connected() {
                break;
            }
            fm.lock().unwrap().update();
            let list = fm.lock().unwrap().take_send_list();
            for f in &list {
                self.send_data(&id, &target, marshal_frame(f), true);
            }
            if start.elapsed() > Duration::from_secs(5) {
                log::debug!("can not connect remote tcp {id} {peer}");
                self.close_conn(&conn);
                return;
            }
            if list.is_empty() {
                backoff.step();
            } else {
                backoff.reset();
                std::thread::sleep(POLL);
            }
        }
        log::debug!("connected remote tcp {id} {peer}");

        self.pump_tcp(&conn, fm, stream, &target, &peer);
        self.close_conn(&conn);
        log::debug!("close tcp conn {id} {peer}");
    }

    /// Двунаправленная перекачка между локальным TCP и FrameMgr.
    fn pump_tcp(
        &self,
        conn: &Arc<ClientConn>,
        fm: Arc<Mutex<FrameMgr>>,
        stream: TcpStream,
        target: &str,
        peer: &str,
    ) {
        let read_err = Arc::new(AtomicBool::new(false));

        // Поток чтения из локального сокета в буфер отправки FrameMgr.
        let reader_stream = match stream.try_clone() {
            Ok(s) => s,
            Err(_) => return,
        };
        let _ = reader_stream.set_read_timeout(Some(Duration::from_millis(500)));
        let reader_fm = fm.clone();
        let reader_conn = conn.clone();
        let reader_flag = read_err.clone();
        let reader = std::thread::spawn(move || {
            let mut stream = reader_stream;
            let mut buf = vec![0u8; 10240];
            loop {
                if reader_conn.exit.load(Ordering::Relaxed) {
                    break;
                }
                let left = reader_fm.lock().unwrap().get_send_buffer_left();
                if left == 0 {
                    std::thread::sleep(POLL);
                    continue;
                }
                let cap = left.min(buf.len());
                match stream.read(&mut buf[..cap]) {
                    Ok(0) => {
                        reader_flag.store(true, Ordering::Relaxed);
                        break;
                    }
                    Ok(n) => reader_fm.lock().unwrap().write_send_buffer(&buf[..n]),
                    Err(e)
                        if e.kind() == std::io::ErrorKind::WouldBlock
                            || e.kind() == std::io::ErrorKind::TimedOut =>
                    {
                        continue
                    }
                    Err(_) => {
                        reader_flag.store(true, Ordering::Relaxed);
                        break;
                    }
                }
            }
        });

        let mut writer = stream;
        let _ = writer.set_write_timeout(Some(Duration::from_millis(200)));
        let timeout_ns = self.cfg.timeout as i64 * 1_000_000_000;
        let mut backoff = Backoff::new(2, 100);

        loop {
            if self.exit.load(Ordering::Relaxed) || conn.exit.load(Ordering::Relaxed) {
                break;
            }
            let mut had_work = false;
            fm.lock().unwrap().update();
            let list = fm.lock().unwrap().take_send_list();
            if !list.is_empty() {
                had_work = true;
                conn.touch_send();
                for f in &list {
                    self.send_data(&conn.id, target, marshal_frame(f), false);
                }
            }

            loop {
                let rsize = fm.lock().unwrap().get_recv_buffer_size();
                if rsize_done(rsize) {
                    break;
                }
                let chunk = fm.lock().unwrap().get_recv_read_line_buffer();
                match writer.write(&chunk) {
                    Ok(n) if n > 0 => {
                        had_work = true;
                        fm.lock().unwrap().skip_recv_buffer(n);
                    }
                    Ok(_) => break,
                    Err(e)
                        if e.kind() == std::io::ErrorKind::WouldBlock
                            || e.kind() == std::io::ErrorKind::TimedOut =>
                    {
                        break
                    }
                    Err(e) => {
                        log::debug!("error write tcp {} {} {}", conn.id, peer, e);
                        fm.lock().unwrap().close();
                        break;
                    }
                }
            }

            let now = now_ns();
            let diffrecv = now - conn.active_recv.load(Ordering::Relaxed);
            let diffsend = now - conn.active_send.load(Ordering::Relaxed);
            if diffrecv > timeout_ns || diffsend > timeout_ns {
                log::debug!("close inactive conn {} {}", conn.id, peer);
                fm.lock().unwrap().close();
                break;
            }
            if fm.lock().unwrap().is_remote_closed() {
                log::debug!("closed by remote conn {} {}", conn.id, peer);
                fm.lock().unwrap().close();
                break;
            }
            if read_err.load(Ordering::Relaxed) {
                fm.lock().unwrap().close();
                break;
            }
            if had_work {
                backoff.reset();
                std::thread::sleep(POLL);
            } else {
                backoff.step();
            }
        }

        conn.exit.store(true, Ordering::Relaxed);
        fm.lock().unwrap().close();

        // Фаза закрытия: дослать CLOSE и слить остатки (до 60с).
        let close_start = Instant::now();
        loop {
            if self.exit.load(Ordering::Relaxed) {
                break;
            }
            fm.lock().unwrap().update();
            let list = fm.lock().unwrap().take_send_list();
            for f in &list {
                self.send_data(&conn.id, target, marshal_frame(f), false);
            }
            let mut nodata = true;
            let rsize = fm.lock().unwrap().get_recv_buffer_size();
            if rsize > 0 {
                let chunk = fm.lock().unwrap().get_recv_read_line_buffer();
                if let Ok(n) = writer.write(&chunk) {
                    if n > 0 {
                        fm.lock().unwrap().skip_recv_buffer(n);
                        nodata = false;
                    }
                }
            }
            if close_start.elapsed() > Duration::from_secs(60) {
                break;
            }
            if fm.lock().unwrap().is_remote_closed() && nodata {
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }

        let _ = reader.join();
    }

    // ── SOCKS5 UDP ASSOCIATE ─────────────────────────────────────────────

    fn accept_socks5_udp(self: Arc<Client>, mut control: TcpStream) {
        let relay = match UdpSocket::bind("0.0.0.0:0") {
            Ok(s) => Arc::new(s),
            Err(e) => {
                log::error!("create sock5 udp relay failed: {e}");
                let _ = socks5::write_reply(
                    &mut control,
                    socks5::REPLY_GENERAL_FAILURE,
                    "0.0.0.0:0",
                );
                return;
            }
        };
        let _ = relay.set_read_timeout(Some(Duration::from_millis(100)));
        let mut relay_addr = relay.local_addr().unwrap();
        if relay_addr.ip().is_unspecified() {
            if let Ok(local) = control.local_addr() {
                relay_addr = SocketAddr::new(local.ip(), relay_addr.port());
            }
        }
        if socks5::write_reply(&mut control, socks5::REPLY_SUCCEEDED, &relay_addr.to_string())
            .is_err()
        {
            return;
        }
        log::debug!("accept new sock5 udp associate relay {relay_addr}");

        let me = self.clone();
        let relay_for_recv = relay.clone();
        let recv = std::thread::spawn(move || me.recv_socks5_udp(relay_for_recv));

        // Удержание управляющего TCP открытым: при разрыве — закрываем ассоциацию.
        let _ = control.set_read_timeout(Some(Duration::from_millis(200)));
        let mut b = [0u8; 1];
        while !self.exit.load(Ordering::Relaxed) {
            match control.read(&mut b) {
                Ok(0) => break,
                Ok(_) => {}
                Err(e)
                    if e.kind() == std::io::ErrorKind::WouldBlock
                        || e.kind() == std::io::ErrorKind::TimedOut => {}
                Err(_) => break,
            }
        }
        self.close_socks5_udp_flows(&relay);
        let _ = recv.join();
        log::debug!("close sock5 udp associate relay {relay_addr}");
    }

    fn recv_socks5_udp(self: Arc<Client>, relay: Arc<UdpSocket>) {
        let mut buf = vec![0u8; 65535];
        let mut source: Option<SocketAddr> = None;
        loop {
            if self.exit.load(Ordering::Relaxed) {
                return;
            }
            let (n, src) = match relay.recv_from(&mut buf) {
                Ok(v) => v,
                Err(e)
                    if e.kind() == std::io::ErrorKind::WouldBlock
                        || e.kind() == std::io::ErrorKind::TimedOut =>
                {
                    // Признак закрытия relay-сокета определяем по флагам потоков.
                    if Arc::strong_count(&relay) <= 1 {
                        return;
                    }
                    continue;
                }
                Err(_) => return,
            };
            if n == 0 {
                continue;
            }
            // Фиксируем первого отправителя.
            match source {
                Some(s) if s != src => continue,
                None => source = Some(src),
                _ => {}
            }
            let (target, payload) = match socks5::parse_udp_datagram(&buf[..n]) {
                Ok(v) => v,
                Err(_) => continue,
            };
            let key = format!("{}|{}|{}", relay.local_addr().unwrap(), src, target);
            let conn = self.by_addr.lock().unwrap().get(&key).cloned();
            let conn = match conn {
                Some(c) => c,
                None => {
                    if self.cfg.maxconn > 0 && self.active_count() >= self.cfg.maxconn as usize {
                        continue;
                    }
                    let id = unique_id();
                    let conn = Arc::new(ClientConn {
                        id: id.clone(),
                        addr_key: Mutex::new(key.clone()),
                        tcpmode: 0,
                        fm: None,
                        exit: AtomicBool::new(false),
                        active_recv: AtomicI64::new(now_ns()),
                        active_send: AtomicI64::new(now_ns()),
                        udp_ipaddr: Mutex::new(Some(src)),
                        udp_relay: Mutex::new(Some(relay.clone())),
                        udp_target: Mutex::new(target.clone()),
                    });
                    self.add_conn(&conn);
                    log::debug!("client accept new sock5 udp {id} {src} -> {target}");
                    conn
                }
            };
            conn.touch_send();
            self.send_udp(&conn.id, &target, &payload);
        }
    }

    fn close_socks5_udp_flows(&self, relay: &Arc<UdpSocket>) {
        let mut to_close = Vec::new();
        for conn in self.by_id.lock().unwrap().values() {
            let same = conn
                .udp_relay
                .lock()
                .unwrap()
                .as_ref()
                .map_or(false, |r| Arc::ptr_eq(r, relay));
            if conn.tcpmode == 0 && same {
                to_close.push(conn.clone());
            }
        }
        for conn in to_close {
            self.close_conn(&conn);
        }
    }

    // ── Обслуживание ─────────────────────────────────────────────────────

    fn maintenance(self: Arc<Client>) {
        let mut next_ping = Instant::now();
        loop {
            if self.exit.load(Ordering::Relaxed) {
                break;
            }
            self.check_timeout();
            self.show_net();
            if Instant::now() >= next_ping {
                self.ping();
                next_ping = Instant::now() + self.ping_interval();
            }
            self.maybe_refresh_server();
            std::thread::sleep(Duration::from_secs(1));
        }
    }

    fn ping_interval(&self) -> Duration {
        if self.active_count() > 0 {
            Duration::from_secs(1)
        } else {
            Duration::from_secs(3)
        }
    }

    fn maybe_refresh_server(&self) {
        if let Ok(ip) = resolve_ipv4(&self.cfg.server) {
            let mut cur = self.server_ip.lock().unwrap();
            if *cur != ip {
                log::info!("server ip refreshed {} -> {}", *cur, ip);
                *cur = ip;
            }
        }
    }

    fn check_timeout(&self) {
        let now = now_ns();
        let timeout_ns = self.cfg.timeout as i64 * 1_000_000_000;
        let conns: Vec<Arc<ClientConn>> =
            self.by_id.lock().unwrap().values().cloned().collect();
        for conn in conns {
            if conn.tcpmode > 0 {
                continue;
            }
            let diffrecv = now - conn.active_recv.load(Ordering::Relaxed);
            let diffsend = now - conn.active_send.load(Ordering::Relaxed);
            if diffrecv > timeout_ns || diffsend > timeout_ns {
                log::debug!("close inactive udp conn {}", conn.id);
                self.close_conn(&conn);
            }
        }
    }

    fn show_net(&self) {
        let (sp, ss, rp, rs) = self.counters.take();
        log::info!(
            "send {sp}Packet/s {ss}KB/s recv {rp}Packet/s {rs}KB/s {}Connections",
            self.active_count()
        );
    }

    // ── Работа с картами соединений ──────────────────────────────────────

    fn add_conn(&self, conn: &Arc<ClientConn>) {
        let key = conn.addr_key.lock().unwrap().clone();
        self.by_addr.lock().unwrap().insert(key, conn.clone());
        self.by_id.lock().unwrap().insert(conn.id.clone(), conn.clone());
    }

    fn close_conn(&self, conn: &Arc<ClientConn>) {
        // Важно: удаляем из карт ВСЕГДА, даже если conn.exit уже был выставлен
        // (pump_tcp ставит exit=true до вызова close_conn). Иначе завершённые
        // TCP-соединения утекают в карту навсегда и копятся зомби.
        conn.exit.store(true, Ordering::Relaxed);
        self.by_id.lock().unwrap().remove(&conn.id);
        let key = conn.addr_key.lock().unwrap().clone();
        let mut by_addr = self.by_addr.lock().unwrap();
        // Удаляем по ключу, только если он всё ещё указывает на ЭТО соединение
        // (для UDP ключ-адрес может быть переиспользован новым соединением).
        if by_addr.get(&key).map_or(false, |c| Arc::ptr_eq(c, conn)) {
            by_addr.remove(&key);
        }
    }
}

fn rsize_done(rsize: usize) -> bool {
    rsize == 0
}

/// Приводит адрес прослушивания в стиле Go (`:port` или `*:port`) к виду,
/// понятному std (`0.0.0.0:port`).
fn normalize_bind(addr: &str) -> String {
    if let Some(rest) = addr.strip_prefix('*') {
        return format!("0.0.0.0{rest}");
    }
    if addr.starts_with(':') {
        return format!("0.0.0.0{addr}");
    }
    addr.to_string()
}
