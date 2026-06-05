//! Сервер: принимает ICMP, устанавливает соединения к целевым адресам
//! (напрямую или через socks5/http-прокси) и проксирует трафик. Порт server.go.

use crate::crypto::Crypto;
use crate::forward::{self, ForwardConfig};
use crate::framemgr::{marshal_frame, FrameMgr};
use crate::icmp;
use crate::proto::*;
use crate::socks5;
use crate::util::{now_ns, Backoff, Counters};
use anyhow::Result;
use prost::Message as _;
use socket2::Socket;
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpStream, ToSocketAddrs, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU16, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const POLL: Duration = Duration::from_millis(2);

pub struct ServerConfig {
    pub icmp_listen: String,
    pub key: i32,
    pub maxconn: i32,
    pub connect_timeout: i32,
}

struct ServerConn {
    id: String,
    rproto: i32,
    tcpmode: i32,
    timeout: i32,
    src: Ipv4Addr,
    echo_id: AtomicU16,
    echo_seq: AtomicU16,
    exit: AtomicBool,
    active_recv: AtomicI64,
    active_send: AtomicI64,
    fm: Option<Arc<Mutex<FrameMgr>>>,
    tcp: Mutex<Option<TcpStream>>,
    udp: Mutex<Option<Arc<UdpSocket>>>,
    udp_target: Mutex<String>,
    udp_via_proxy: bool,
    udp_relay: Mutex<Option<SocketAddr>>,
    _control: Mutex<Option<TcpStream>>,
}

impl ServerConn {
    fn touch_recv(&self) {
        self.active_recv.store(now_ns(), Ordering::Relaxed);
    }
    fn touch_send(&self) {
        self.active_send.store(now_ns(), Ordering::Relaxed);
    }
    fn echo(&self) -> (u16, u16) {
        (
            self.echo_id.load(Ordering::Relaxed),
            self.echo_seq.load(Ordering::Relaxed),
        )
    }
}

pub struct Server {
    cfg: ServerConfig,
    socket: Socket,
    crypto: Option<Crypto>,
    datagram: bool,
    forward: Option<ForwardConfig>,
    conns: Mutex<HashMap<String, Arc<ServerConn>>>,
    conn_error: Mutex<HashMap<String, Instant>>,
    counters: Counters,
    exit: AtomicBool,
}

impl Server {
    pub fn new(
        cfg: ServerConfig,
        crypto: Option<Crypto>,
        forward: Option<ForwardConfig>,
    ) -> Result<Arc<Server>> {
        let (socket, datagram) = icmp::listen_icmp(&cfg.icmp_listen)?;
        if datagram {
            log::warn!("сервер работает в datagram-режиме: echo request не доставляется, нужен RAW (root/CAP_NET_RAW)");
        }
        Ok(Arc::new(Server {
            cfg,
            socket,
            crypto,
            datagram,
            forward,
            conns: Mutex::new(HashMap::new()),
            conn_error: Mutex::new(HashMap::new()),
            counters: Counters::default(),
            exit: AtomicBool::new(false),
        }))
    }

    pub fn run(self: &Arc<Server>) -> Result<()> {
        log::info!("Server start, icmp listen {}", self.cfg.icmp_listen);
        {
            let me = self.clone();
            std::thread::spawn(move || me.maintenance());
        }
        let me = self.clone();
        me.recv_loop();
        Ok(())
    }

    fn timeout_ns(&self, t: i32) -> i64 {
        t as i64 * 1_000_000_000
    }

    // ── Приём ICMP ───────────────────────────────────────────────────────

    fn recv_loop(self: Arc<Server>) {
        while !self.exit.load(Ordering::Relaxed) {
            match icmp::recv_icmp(&self.socket, self.datagram, self.crypto.as_ref()) {
                Ok(Some(pkt)) => self.process_packet(pkt),
                Ok(None) => {}
                Err(e) => log::debug!("recv icmp error: {e}"),
            }
        }
    }

    fn process_packet(self: &Arc<Server>, pkt: icmp::Packet) {
        if pkt.my.key != self.cfg.key {
            return;
        }
        // Принимаем только клиентские пакеты (rproto >= 0). Ответы сервера
        // (rproto = -1) игнорируем — это защищает от отражённых/зациклованных
        // на loopback собственных ответов, которые иначе попали бы в свой же
        // FrameMgr и сломали протокол. Клиент всегда шлёт rproto = 0.
        if pkt.my.rproto < 0 {
            return;
        }
        match pkt.my.r#type {
            x if x == MSG_PING => {
                log::debug!("ping from {}", pkt.src);
                let my = MyMsg {
                    r#type: MSG_PING,
                    data: pkt.my.data.clone(),
                    rproto: -1,
                    key: self.cfg.key,
                    ..Default::default()
                };
                let _ = icmp::send_icmp(
                    &self.socket,
                    pkt.echo_id,
                    pkt.echo_seq,
                    pkt.src,
                    pkt.my.rproto as u8,
                    my,
                    self.crypto.as_ref(),
                );
            }
            x if x == MSG_KICK => {
                // Освобождаем замок conns до close_conn (который снова его берёт),
                // иначе временный guard в `if let` доживёт до конца блока → deadlock.
                let conn = self.conns.lock().unwrap().get(&pkt.my.id).cloned();
                if let Some(conn) = conn {
                    self.close_conn(&conn);
                    log::debug!("remote kick local {}", pkt.my.id);
                }
            }
            _ => self.process_data_packet_impl(pkt),
        }
    }

    fn get_conn(&self, id: &str) -> Option<Arc<ServerConn>> {
        self.conns.lock().unwrap().get(id).cloned()
    }

    fn process_data_packet_impl(self: &Arc<Server>, pkt: icmp::Packet) {
        let id = pkt.my.id.clone();
        let conn = match self.get_conn(&id) {
            Some(c) => c,
            None => match self.new_conn(&pkt) {
                Some(c) => c,
                None => return,
            },
        };

        conn.touch_recv();
        conn.echo_id.store(pkt.echo_id, Ordering::Relaxed);
        conn.echo_seq.store(pkt.echo_seq, Ordering::Relaxed);

        if pkt.my.r#type != MSG_DATA {
            return;
        }

        if conn.tcpmode > 0 {
            match Frame::decode(&pkt.my.data[..]) {
                Ok(f) => {
                    if let Some(fm) = &conn.fm {
                        fm.lock().unwrap().on_recv_frame(f);
                    }
                }
                Err(e) => log::debug!("unmarshal tcp frame error: {e}"),
            }
        } else if !pkt.my.data.is_empty() {
            let udp = conn.udp.lock().unwrap().clone();
            if let Some(udp) = udp {
                if conn.udp_via_proxy {
                    let target = if !pkt.my.target.is_empty() {
                        pkt.my.target.clone()
                    } else {
                        conn.udp_target.lock().unwrap().clone()
                    };
                    let relay = *conn.udp_relay.lock().unwrap();
                    if let (Ok(dgram), Some(relay)) =
                        (socks5::build_udp_datagram(&target, &pkt.my.data), relay)
                    {
                        let _ = udp.send_to(&dgram, relay);
                    }
                } else {
                    let _ = udp.send(&pkt.my.data);
                }
            }
        }
        self.counters.add_recv(pkt.my.data.len());
    }

    fn new_conn(self: &Arc<Server>, pkt: &icmp::Packet) -> Option<Arc<ServerConn>> {
        let id = pkt.my.id.clone();
        let addr = pkt.my.target.clone();

        if self.cfg.maxconn > 0 && self.conns.lock().unwrap().len() >= self.cfg.maxconn as usize {
            self.remote_error(pkt.echo_id, pkt.echo_seq, &id, pkt.my.rproto, pkt.src);
            return None;
        }
        // Адрес недавно не отвечал — не тратим ресурсы, сразу отбиваем KICK.
        if self.is_conn_error(&addr) {
            self.remote_error(pkt.echo_id, pkt.echo_seq, &id, pkt.my.rproto, pkt.src);
            return None;
        }
        log::debug!("start add new connect {id} {addr}");

        if pkt.my.tcpmode > 0 {
            let buffersize = (pkt.my.tcpmode_buffersize.max(1)) as usize;
            let maxwin = pkt.my.tcpmode_maxwin.max(1) as i64;
            let resend = pkt.my.tcpmode_resend_timems.max(1) as i64;
            let compress = pkt.my.tcpmode_compress.max(0) as usize;
            let fm = Arc::new(Mutex::new(FrameMgr::new(
                FRAME_MAX_SIZE,
                FRAME_MAX_ID as i64,
                buffersize,
                maxwin,
                resend,
                compress,
            )));
            let conn = Arc::new(ServerConn {
                id: id.clone(),
                rproto: pkt.my.rproto,
                tcpmode: pkt.my.tcpmode,
                timeout: pkt.my.timeout,
                src: pkt.src,
                echo_id: AtomicU16::new(pkt.echo_id),
                echo_seq: AtomicU16::new(pkt.echo_seq),
                exit: AtomicBool::new(false),
                active_recv: AtomicI64::new(now_ns()),
                active_send: AtomicI64::new(now_ns()),
                fm: Some(fm),
                tcp: Mutex::new(None),
                udp: Mutex::new(None),
                udp_target: Mutex::new(addr.clone()),
                udp_via_proxy: false,
                udp_relay: Mutex::new(None),
                _control: Mutex::new(None),
            });
            self.conns.lock().unwrap().insert(id.clone(), conn.clone());
            let me = self.clone();
            let conn2 = conn.clone();
            std::thread::spawn(move || me.run_tcp(conn2, addr));
            Some(conn)
        } else {
            self.new_udp_conn(pkt, addr)
        }
    }

    fn new_udp_conn(self: &Arc<Server>, pkt: &icmp::Packet, addr: String) -> Option<Arc<ServerConn>> {
        let timeout = Duration::from_millis(self.cfg.connect_timeout as u64);
        let (udp, via_proxy, relay, control): (
            Arc<UdpSocket>,
            bool,
            Option<SocketAddr>,
            Option<TcpStream>,
        ) = if let Some(fwd) = &self.forward {
            if fwd.scheme != "socks5" {
                log::debug!("UDP forwarding requires SOCKS5 proxy");
                self.remote_error(pkt.echo_id, pkt.echo_seq, &pkt.my.id, pkt.my.rproto, pkt.src);
                return None;
            }
            match forward::dial_udp_through_proxy(fwd, timeout) {
                Ok(assoc) => {
                    let _ = assoc.udp.set_read_timeout(Some(Duration::from_millis(100)));
                    (
                        Arc::new(assoc.udp),
                        true,
                        Some(assoc.relay),
                        Some(assoc.control),
                    )
                }
                Err(e) => {
                    log::debug!("udp forward association failed: {e}");
                    self.remote_error(pkt.echo_id, pkt.echo_seq, &pkt.my.id, pkt.my.rproto, pkt.src);
                    self.add_conn_error(&addr);
                    return None;
                }
            }
        } else {
            let target: SocketAddr = match addr.to_socket_addrs().ok().and_then(|mut i| i.next()) {
                Some(a) => a,
                None => {
                    self.remote_error(pkt.echo_id, pkt.echo_seq, &pkt.my.id, pkt.my.rproto, pkt.src);
                    self.add_conn_error(&addr);
                    return None;
                }
            };
            let s = match UdpSocket::bind("0.0.0.0:0").and_then(|s| {
                s.connect(target)?;
                s.set_read_timeout(Some(Duration::from_millis(100)))?;
                Ok(s)
            }) {
                Ok(s) => s,
                Err(e) => {
                    log::debug!("dial udp {addr} failed: {e}");
                    self.remote_error(pkt.echo_id, pkt.echo_seq, &pkt.my.id, pkt.my.rproto, pkt.src);
                    self.add_conn_error(&addr);
                    return None;
                }
            };
            (Arc::new(s), false, None, None)
        };

        let conn = Arc::new(ServerConn {
            id: pkt.my.id.clone(),
            rproto: pkt.my.rproto,
            tcpmode: 0,
            timeout: pkt.my.timeout,
            src: pkt.src,
            echo_id: AtomicU16::new(pkt.echo_id),
            echo_seq: AtomicU16::new(pkt.echo_seq),
            exit: AtomicBool::new(false),
            active_recv: AtomicI64::new(now_ns()),
            active_send: AtomicI64::new(now_ns()),
            fm: None,
            tcp: Mutex::new(None),
            udp: Mutex::new(Some(udp.clone())),
            udp_target: Mutex::new(addr),
            udp_via_proxy: via_proxy,
            udp_relay: Mutex::new(relay),
            _control: Mutex::new(control),
        });
        self.conns
            .lock()
            .unwrap()
            .insert(conn.id.clone(), conn.clone());
        let me = self.clone();
        let conn2 = conn.clone();
        std::thread::spawn(move || me.run_udp(conn2, udp));
        Some(conn)
    }

    // ── TCP-обработка ────────────────────────────────────────────────────

    fn run_tcp(self: Arc<Server>, conn: Arc<ServerConn>, addr: String) {
        let timeout = Duration::from_millis(self.cfg.connect_timeout as u64);
        let stream = if let Some(fwd) = &self.forward {
            forward::dial_through_proxy(fwd, &addr, timeout)
        } else {
            resolve_and_connect(&addr, timeout)
        };
        let stream = match stream {
            Ok(s) => s,
            Err(e) => {
                log::debug!("connect target {addr} failed: {e}");
                self.remote_error(
                    conn.echo_id.load(Ordering::Relaxed),
                    conn.echo_seq.load(Ordering::Relaxed),
                    &conn.id,
                    conn.rproto,
                    conn.src,
                );
                self.add_conn_error(&addr);
                self.close_conn(&conn);
                return;
            }
        };
        *conn.tcp.lock().unwrap() = Some(stream.try_clone().expect("clone stream"));

        let fm = conn.fm.clone().unwrap();

        // Ожидание установления соединения от клиента (CONN/CONNRSP).
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
                self.send_reply(&conn, marshal_frame(f), "");
            }
            if list.is_empty() {
                backoff.step();
            } else {
                backoff.reset();
                std::thread::sleep(POLL);
            }
            if start.elapsed() > Duration::from_secs(5) {
                log::debug!("can not connect remote tcp {} {addr}", conn.id);
                self.remote_error(
                    conn.echo_id.load(Ordering::Relaxed),
                    conn.echo_seq.load(Ordering::Relaxed),
                    &conn.id,
                    conn.rproto,
                    conn.src,
                );
                // Кэшируем неудачу рукопожатия, чтобы клиент не долбил мёртвый
                // адрес заново и не устраивал шторм переподключений.
                self.add_conn_error(&addr);
                self.close_conn(&conn);
                return;
            }
        }
        log::debug!("remote connected tcp {} {addr}", conn.id);

        self.pump_tcp(&conn, fm, stream, &addr);
        self.close_conn(&conn);
        log::debug!("close tcp conn {} {addr}", conn.id);
    }

    fn pump_tcp(&self, conn: &Arc<ServerConn>, fm: Arc<Mutex<FrameMgr>>, stream: TcpStream, addr: &str) {
        let read_err = Arc::new(AtomicBool::new(false));
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
        let timeout_ns = self.timeout_ns(conn.timeout);
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
                    self.send_reply(conn, marshal_frame(f), "");
                }
            }
            loop {
                let rsize = fm.lock().unwrap().get_recv_buffer_size();
                if rsize == 0 {
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
                        log::debug!("error write tcp {} {addr} {e}", conn.id);
                        fm.lock().unwrap().close();
                        break;
                    }
                }
            }

            let now = now_ns();
            let diffrecv = now - conn.active_recv.load(Ordering::Relaxed);
            let diffsend = now - conn.active_send.load(Ordering::Relaxed);
            if diffrecv > timeout_ns || diffsend > timeout_ns {
                log::debug!("close inactive conn {} {addr}", conn.id);
                fm.lock().unwrap().close();
                break;
            }
            if fm.lock().unwrap().is_remote_closed() {
                log::debug!("closed by remote conn {} {addr}", conn.id);
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

        let close_start = Instant::now();
        loop {
            if self.exit.load(Ordering::Relaxed) {
                break;
            }
            fm.lock().unwrap().update();
            let list = fm.lock().unwrap().take_send_list();
            for f in &list {
                self.send_reply(conn, marshal_frame(f), "");
            }
            let mut nodata = true;
            if fm.lock().unwrap().get_recv_buffer_size() > 0 {
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

    // ── UDP-обработка ────────────────────────────────────────────────────

    fn run_udp(self: Arc<Server>, conn: Arc<ServerConn>, udp: Arc<UdpSocket>) {
        let mut buf = vec![0u8; 2000];
        loop {
            if self.exit.load(Ordering::Relaxed) || conn.exit.load(Ordering::Relaxed) {
                break;
            }
            let (n, src) = if conn.udp_via_proxy {
                match udp.recv_from(&mut buf) {
                    Ok(v) => (v.0, Some(v.1)),
                    Err(e)
                        if e.kind() == std::io::ErrorKind::WouldBlock
                            || e.kind() == std::io::ErrorKind::TimedOut =>
                    {
                        continue
                    }
                    Err(_) => break,
                }
            } else {
                match udp.recv(&mut buf) {
                    Ok(n) => (n, None),
                    Err(e)
                        if e.kind() == std::io::ErrorKind::WouldBlock
                            || e.kind() == std::io::ErrorKind::TimedOut =>
                    {
                        continue
                    }
                    Err(_) => break,
                }
            };
            if n == 0 {
                continue;
            }
            conn.touch_send();

            let (target, payload): (String, Vec<u8>) = if conn.udp_via_proxy {
                let relay = *conn.udp_relay.lock().unwrap();
                if let (Some(relay), Some(src)) = (relay, src) {
                    if relay.port() != 0 && src != relay {
                        continue;
                    }
                }
                match socks5::parse_udp_datagram(&buf[..n]) {
                    Ok(v) => v,
                    Err(_) => continue,
                }
            } else {
                (conn.udp_target.lock().unwrap().clone(), buf[..n].to_vec())
            };

            self.send_reply(&conn, payload, &target);
        }
        self.close_conn(&conn);
    }

    // ── Отправка ответов ─────────────────────────────────────────────────

    fn send_reply(&self, conn: &Arc<ServerConn>, data: Vec<u8>, target: &str) {
        let len = data.len();
        let my = MyMsg {
            id: conn.id.clone(),
            r#type: MSG_DATA,
            target: target.to_string(),
            data,
            rproto: -1,
            key: self.cfg.key,
            ..Default::default()
        };
        let (echo_id, echo_seq) = conn.echo();
        let _ = icmp::send_icmp(
            &self.socket,
            echo_id,
            echo_seq,
            conn.src,
            conn.rproto as u8,
            my,
            self.crypto.as_ref(),
        );
        self.counters.add_send(len);
    }

    fn remote_error(&self, echo_id: u16, echo_seq: u16, id: &str, rproto: i32, src: Ipv4Addr) {
        let my = MyMsg {
            id: id.to_string(),
            r#type: MSG_KICK,
            rproto: -1,
            key: self.cfg.key,
            ..Default::default()
        };
        let _ = icmp::send_icmp(
            &self.socket,
            echo_id,
            echo_seq,
            src,
            rproto as u8,
            my,
            self.crypto.as_ref(),
        );
    }

    // ── Обслуживание / служебные ─────────────────────────────────────────

    fn maintenance(self: Arc<Server>) {
        loop {
            if self.exit.load(Ordering::Relaxed) {
                break;
            }
            self.check_timeout();
            self.show_net();
            self.update_conn_error();
            std::thread::sleep(Duration::from_secs(1));
        }
    }

    fn check_timeout(&self) {
        let now = now_ns();
        let conns: Vec<Arc<ServerConn>> = self.conns.lock().unwrap().values().cloned().collect();
        for conn in conns {
            if conn.tcpmode > 0 {
                continue;
            }
            let timeout_ns = self.timeout_ns(conn.timeout);
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
        let n = self.conns.lock().unwrap().len();
        log::info!("send {sp}Packet/s {ss}KB/s recv {rp}Packet/s {rs}KB/s {n}Connections");
    }

    fn close_conn(&self, conn: &Arc<ServerConn>) {
        if conn.exit.swap(true, Ordering::Relaxed) {
            // уже закрыто другим путём — но всё равно убираем из карты
        }
        self.conns.lock().unwrap().remove(&conn.id);
        if let Some(s) = conn.tcp.lock().unwrap().take() {
            let _ = s.shutdown(std::net::Shutdown::Both);
        }
        *conn.udp.lock().unwrap() = None;
        *conn._control.lock().unwrap() = None;
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

    fn update_conn_error(&self) {
        let mut map = self.conn_error.lock().unwrap();
        map.retain(|_, t| t.elapsed() <= Duration::from_secs(5));
    }
}

fn resolve_and_connect(addr: &str, timeout: Duration) -> Result<TcpStream> {
    let sa: SocketAddr = addr
        .to_socket_addrs()
        .ok()
        .and_then(|mut i| i.next())
        .ok_or_else(|| anyhow::anyhow!("cannot resolve {addr}"))?;
    Ok(TcpStream::connect_timeout(&sa, timeout)?)
}
