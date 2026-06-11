//! Асинхронный транспорт с батчингом syscalls.
//!
//! Главная цель - убрать «один syscall на пакет» (это давало ~72% sys CPU на
//! сервере). Чтение/запись идут пачками через `recvmmsg`/`sendmmsg` (десятки
//! пакетов за один вызов ядра), а сокет интегрирован в tokio через `AsyncFd`.
//!
//! Сборка/разбор echo-пакетов и упаковка `MyMsg` (с опц. шифрованием) - здесь же.
//!
//! Два режима транспорта (см. [`listen_transport`]):
//! - **одиночный протокол** (по умолчанию ICMP, либо один кастомный номер):
//!   обычный inet raw/datagram-сокет, как раньше;
//! - **ротация** (диапазон протоколов): приём через **один** `AF_PACKET`-сокет с
//!   BPF-фильтром по диапазону прямо в ядре (raw-сокет принимает лишь один номер,
//!   а тут номер на каждом соединении случайный), отправка - ленивые inet-raw
//!   сокеты, открываемые под используемые номера (так ядро строит IP-заголовок и
//!   само фрагментирует jumbo).

use crate::crypto::Crypto;
use crate::proto::{MyMsg, MAGIC};
use anyhow::Result;
use prost::Message;
use rand::Rng;
use socket2::{Domain, Protocol, Socket, Type};
use std::cell::RefCell;
use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::os::unix::io::{AsRawFd, FromRawFd};
use std::sync::Arc;
use std::{mem, ptr};
use tokio::io::unix::AsyncFd;

pub const ICMP_ECHO_REQUEST: u8 = 8;
#[allow(dead_code)]
pub const ICMP_ECHO_REPLY: u8 = 0;

/// Номер IP-протокола для ICMP (IANA). Транспорт по умолчанию.
pub const IP_PROTO_ICMP: u8 = 1;

// Должен вмещать самый большой датаграм (jumbo-кадр + IP-заголовок после сборки
// IP-фрагментов ядром). 64 КБ покрывает любой допустимый размер.
const BUFSZ: usize = 65535;

/// Как разбирать входящие пакеты и откуда брать адрес источника.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum RecvMode {
    /// Непривилегированный ICMP datagram-сокет: без IP-заголовка, src из адреса.
    InetDatagram,
    /// inet raw-сокет: с IP-заголовком, src из адреса recvmmsg.
    InetRaw,
    /// AF_PACKET (ротация): с IP-заголовком, src и протокол берём из IP-заголовка.
    Packet,
}

/// Готовый транспорт. `rx` - единственный приёмный сокет; отправка - через
/// `spawn_writer`, который в режиме ротации лениво открывает сокеты под протоколы.
pub struct Transport {
    pub rx: Arc<IcmpIo>,
    pub recv_mode: RecvMode,
    /// IP для bind ленивых отправляющих сокетов (режим ротации).
    pub bind_ip: Ipv4Addr,
    /// Одиночный режим: тот же сокет и для отправки (None = ротация: ленивые сокеты).
    pub tx_single: Option<Arc<IcmpIo>>,
}

/// Открывает транспорт под список IP-протоколов `protos`.
///
/// `[1]` (ICMP) - inet raw, при отказе непривилегированный datagram-фоллбэк.
/// Один кастомный номер (напр. 253/254 из RFC 3692) - inet raw (нужен CAP_NET_RAW);
/// штатный режим при ограничениях, см. README.
/// Несколько номеров - экспериментальная ротация: приём через AF_PACKET с
/// BPF-фильтром `[lo..hi]`, отправка - ленивые inet-raw сокеты.
///
/// ВНИМАНИЕ: кастомные протоколы не переживают NAT (трансляция есть только для
/// TCP/UDP/ICMP) и режутся большинством файрволов; имеют смысл лишь при прямой
/// маршрутизации без NAT по пути.
pub fn listen_transport(addr: &str, protos: &[u8]) -> Result<Transport> {
    let ip: Ipv4Addr = if addr.is_empty() {
        Ipv4Addr::UNSPECIFIED
    } else {
        addr.parse().unwrap_or(Ipv4Addr::UNSPECIFIED)
    };

    // Режим ротации: несколько протоколов -> один AF_PACKET-приёмник + BPF.
    if protos.len() > 1 {
        let lo = *protos.iter().min().unwrap();
        let hi = *protos.iter().max().unwrap();
        let sock = open_packet_rx(lo, hi)?;
        let rx = Arc::new(IcmpIo::new_proto(sock, 0)?);
        log::info!(
            "транспорт: ротация IP-протоколов [{lo}..{hi}] через AF_PACKET+BPF (экспериментально)"
        );
        return Ok(Transport {
            rx,
            recv_mode: RecvMode::Packet,
            bind_ip: ip,
            tx_single: None,
        });
    }

    // Одиночный протокол: inet raw (+ datagram-фоллбэк для ICMP).
    let proto = protos.first().copied().unwrap_or(IP_PROTO_ICMP);
    let bind = SocketAddr::new(IpAddr::V4(ip), 0);
    let (socket, datagram) = if proto == IP_PROTO_ICMP {
        match Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::ICMPV4)) {
            Ok(s) => (s, false),
            Err(_) => {
                let s = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::ICMPV4))?;
                log::warn!("RAW ICMP недоступен (нет CAP_NET_RAW), datagram-режим (клиентский)");
                (s, true)
            }
        }
    } else {
        let s = Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::from(proto as i32)))?;
        log::info!("транспорт: кастомный IP-протокол {proto} (RAW)");
        (s, false)
    };
    socket.bind(&bind.into())?;
    socket.set_nonblocking(true)?;
    let _ = socket.set_send_buffer_size(8 << 20);
    let _ = socket.set_recv_buffer_size(16 << 20);
    let io = Arc::new(IcmpIo::new_proto(socket, proto)?);
    Ok(Transport {
        rx: io.clone(),
        recv_mode: if datagram {
            RecvMode::InetDatagram
        } else {
            RecvMode::InetRaw
        },
        bind_ip: ip,
        tx_single: Some(io),
    })
}

/// Открывает inet raw-сокет под конкретный IP-протокол (ленивая отправка в режиме
/// ротации). Ядро само строит IP-заголовок (protocol = `proto`) и фрагментирует.
fn open_inet_raw(bind_ip: Ipv4Addr, proto: u8) -> io::Result<Arc<IcmpIo>> {
    let s = Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::from(proto as i32)))?;
    let bind = SocketAddr::new(IpAddr::V4(bind_ip), 0);
    s.bind(&bind.into())?;
    s.set_nonblocking(true)?;
    let _ = s.set_send_buffer_size(8 << 20);
    Ok(Arc::new(IcmpIo::new_proto(s, proto)?))
}

/// Открывает AF_PACKET (SOCK_DGRAM, ETH_P_IP) - принимает все IPv4-пакеты с
/// L2-заголовком, снятым ядром (буфер начинается с IP-заголовка). BPF-фильтр в
/// ядре отбирает лишь входящие пакеты с номером протокола в `[lo..hi]`.
fn open_packet_rx(lo: u8, hi: u8) -> io::Result<Socket> {
    let proto = (libc::ETH_P_IP as u16).to_be() as libc::c_int;
    let fd = unsafe { libc::socket(libc::AF_PACKET, libc::SOCK_DGRAM, proto) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let sock = unsafe { Socket::from_raw_fd(fd) };
    sock.set_nonblocking(true)?;
    let _ = sock.set_recv_buffer_size(16 << 20);
    attach_proto_filter(&sock, lo, hi)?;
    Ok(sock)
}

/// Вешает cBPF-фильтр: пропустить только входящие (не PACKET_OUTGOING) IPv4-пакеты,
/// у которых байт протокола IP-заголовка в `[lo..hi]`. Смещение протокола берём
/// относительно сетевого слоя (`SKF_NET_OFF`), чтобы не зависеть от длины L2.
fn attach_proto_filter(sock: &Socket, lo: u8, hi: u8) -> io::Result<()> {
    // Спец-смещения cBPF.
    const SKF_AD_OFF: i32 = -0x1000;
    const SKF_AD_PKTTYPE: i32 = 4;
    const SKF_NET_OFF: i32 = -0x10_0000;
    const PACKET_OUTGOING: u32 = 4;
    // Классы/коды инструкций cBPF.
    const LD: u16 = 0x00;
    const B: u16 = 0x10;
    const ABS: u16 = 0x20;
    const JMP: u16 = 0x05;
    const JEQ: u16 = 0x10;
    const JGE: u16 = 0x30;
    const JGT: u16 = 0x20;
    const K: u16 = 0x00;
    const RET: u16 = 0x06;

    let f = |code: u16, jt: u8, jf: u8, k: u32| libc::sock_filter { code, jt, jf, k };
    // Индексы: 5 = accept, 6 = drop. jt/jf - смещения от следующей инструкции.
    let prog = [
        f(LD | B | ABS, 0, 0, (SKF_AD_OFF + SKF_AD_PKTTYPE) as u32), // 0: A = pkttype
        f(JMP | JEQ | K, 4, 0, PACKET_OUTGOING),                    // 1: ==OUTGOING -> drop(6)
        f(LD | B | ABS, 0, 0, (SKF_NET_OFF + 9) as u32),            // 2: A = ip[9] (proto)
        f(JMP | JGE | K, 0, 2, lo as u32),                          // 3: A<lo -> drop(6)
        f(JMP | JGT | K, 1, 0, hi as u32),                          // 4: A>hi -> drop(6)
        f(RET | K, 0, 0, 0xFFFF_FFFF),                              // 5: accept
        f(RET | K, 0, 0, 0),                                        // 6: drop
    ];
    let fprog = libc::sock_fprog {
        len: prog.len() as u16,
        filter: prog.as_ptr() as *mut libc::sock_filter,
    };
    let r = unsafe {
        libc::setsockopt(
            sock.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_ATTACH_FILTER,
            &fprog as *const _ as *const libc::c_void,
            mem::size_of::<libc::sock_fprog>() as libc::socklen_t,
        )
    };
    if r < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Извлекает адрес источника из IPv4-заголовка (для режима AF_PACKET).
pub fn src_from_ip(raw: &[u8]) -> Option<Ipv4Addr> {
    if raw.len() < 20 || (raw[0] >> 4) != 4 {
        return None;
    }
    Some(Ipv4Addr::new(raw[12], raw[13], raw[14], raw[15]))
}

/// Извлекает номер IP-протокола из IPv4-заголовка (для режима AF_PACKET).
pub fn proto_from_ip(raw: &[u8]) -> Option<u8> {
    if raw.len() < 20 || (raw[0] >> 4) != 4 {
        return None;
    }
    Some(raw[9])
}

/// Асинхронный сокет, разделяемый между read- и write-тасками.
pub struct IcmpIo {
    pub fd: AsyncFd<Socket>,
    /// Номер IP-протокола (для inet-сокетов); для AF_PACKET не используется (0).
    pub proto: u8,
}

impl IcmpIo {
    pub fn new_proto(socket: Socket, proto: u8) -> io::Result<IcmpIo> {
        Ok(IcmpIo {
            fd: AsyncFd::new(socket)?,
            proto,
        })
    }
}

// ── Контрольная сумма и сборка echo ──────────────────────────────────────

fn checksum(data: &[u8]) -> u16 {
    // Internet checksum (ones' complement сумма 16-битных big-endian слов).
    // Считаем по 8 байт за итерацию в u64-аккумуляторе - свёртка переносов
    // отложена до конца, цикл в ~4 раза короче побайтового (важно для jumbo).
    let mut sum: u64 = 0;
    let mut chunks = data.chunks_exact(8);
    for c in chunks.by_ref() {
        sum += u16::from_be_bytes([c[0], c[1]]) as u64;
        sum += u16::from_be_bytes([c[2], c[3]]) as u64;
        sum += u16::from_be_bytes([c[4], c[5]]) as u64;
        sum += u16::from_be_bytes([c[6], c[7]]) as u64;
    }
    let rem = chunks.remainder();
    let mut i = 0;
    while i + 1 < rem.len() {
        sum += u16::from_be_bytes([rem[i], rem[i + 1]]) as u64;
        i += 2;
    }
    if i < rem.len() {
        sum += (rem[i] as u64) << 8;
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn build_echo(icmp_type: u8, id: u16, seq: u16, payload: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(8 + payload.len());
    buf.push(icmp_type);
    buf.push(0);
    buf.push(0);
    buf.push(0);
    buf.extend_from_slice(&id.to_be_bytes());
    buf.extend_from_slice(&seq.to_be_bytes());
    buf.extend_from_slice(payload);
    let cs = checksum(&buf);
    buf[2..4].copy_from_slice(&cs.to_be_bytes());
    buf
}

/// Параметры преобразования пакета на проводе: шифрование (AEAD), случайный
/// паддинг (рандомизация размера, Dynamic Packet Padding) и обфускация заголовка
/// (Header Obfuscation). Едина для кодирования и разбора; держится клиентом и
/// сервером и прокидывается в [`encode_packet`]/[`parse_packet`].
pub struct Wire {
    crypto: Option<Crypto>,
    /// Максимум случайных байт паддинга на пакет (0 = выключено).
    pad_max: u16,
    /// Обфускация заголовка: убрать псевдо-echo обёртку - на проводе остаётся лишь
    /// nonce+шифртекст (сплошной шум). Допустима только при включённом шифровании
    /// и кастомном IP-протоколе (валидируется в `main`).
    obfs: bool,
}

impl Wire {
    pub fn new(crypto: Option<Crypto>, pad_max: u16, obfs: bool) -> Wire {
        Wire { crypto, pad_max, obfs }
    }

    /// Включена ли обфускация заголовка (нужно вызывающим: при obfs на проводе нет
    /// echo-заголовка, поэтому echo_id для демультиплексирования недоступен).
    pub fn obfs(&self) -> bool {
        self.obfs
    }
}

/// Кодирует MyMsg в готовый пакет: паддинг -> protobuf -> шифрование -> обёртка.
/// Обёртка - псевдо-echo заголовок (8 байт), либо при `obfs` её нет и на проводе
/// остаётся только `nonce||ciphertext`.
pub fn encode_packet(mut my: MyMsg, sproto: u8, icmp_id: u16, seq: u16, wire: &Wire) -> Vec<u8> {
    my.magic = MAGIC;
    // Dynamic Packet Padding: дописываем 0..=pad_max случайных байт в поле `pad`.
    // Поле уходит внутрь шифрования, рандомизируя итоговый размер пакета; получатель
    // его игнорирует. На пустом pad_max поле не сериализуется (wire-совместимо).
    if wire.pad_max > 0 {
        let n = (rand::random::<u32>() % (wire.pad_max as u32 + 1)) as usize;
        if n > 0 {
            let mut pad = vec![0u8; n];
            rand::rng().fill_bytes(&mut pad);
            my.pad = pad;
        }
    }
    let mut payload = Vec::with_capacity(my.encoded_len());
    my.encode(&mut payload).expect("encode MyMsg");
    if let Some(c) = &wire.crypto {
        payload = c.encrypt(&payload).unwrap_or(payload);
    }
    if wire.obfs {
        // Header Obfuscation: без echo-обёртки, на проводе сплошной шум.
        payload
    } else {
        build_echo(sproto, icmp_id, seq, &payload)
    }
}

/// Разбирает входящий пакет (raw/packet: с IP-заголовком; datagram: без него).
/// Возвращает (MyMsg, echo_id, echo_seq) либо None для чужих/битых. При `obfs`
/// echo-заголовка нет, echo_id/seq возвращаются нулями.
pub fn parse_packet(raw: &[u8], datagram: bool, wire: &Wire) -> Option<(MyMsg, u16, u16)> {
    if raw.is_empty() {
        return None;
    }
    // Тело IP-пакета (для raw/packet снимаем IP-заголовок; datagram уже без него).
    let body = if datagram {
        raw
    } else {
        let ihl = ((raw[0] & 0x0f) as usize) * 4;
        if raw.len() < ihl {
            return None;
        }
        &raw[ihl..]
    };

    // Header Obfuscation: тело - сразу nonce||ciphertext, без echo-заголовка.
    if wire.obfs {
        // decrypt/decode принимают срез - расшифровываем/декодируем прямо из
        // тела пакета, без промежуточной копии (.to_vec) на каждом пакете.
        let my = match &wire.crypto {
            Some(c) => MyMsg::decode(&c.decrypt(body).ok()?[..]).ok()?,
            None => MyMsg::decode(body).ok()?,
        };
        if my.magic != MAGIC {
            return None;
        }
        return Some((my, 0, 0));
    }

    // Обычный путь: псевдо-echo заголовок (8 байт) + payload.
    if body.len() < 8 {
        return None;
    }
    let echo_id = u16::from_be_bytes([body[4], body[5]]);
    let echo_seq = u16::from_be_bytes([body[6], body[7]]);
    let ct = &body[8..];
    let my = match &wire.crypto {
        Some(c) => MyMsg::decode(&c.decrypt(ct).ok()?[..]).ok()?,
        None => MyMsg::decode(ct).ok()?,
    };
    if my.magic != MAGIC {
        return None;
    }
    Some((my, echo_id, echo_seq))
}

// ── Батч приёма (recvmmsg) ───────────────────────────────────────────────

// Per-thread scratch под временные iovec/mmsghdr. recvmmsg/sendmmsg - самый
// горячий путь; раньше оба массива аллоцировались заново на каждый syscall.
// Буферы переиспользуются (clear сохраняет capacity), так что после прогрева
// аллокаций в этом пути нет. Доступ синхронный и невложенный (recv в read-таске,
// send в writer-таске, ни один не держится через .await), поэтому RefCell
// безопасен и сами батчи остаются Send.
thread_local! {
    static RECV_SCRATCH: RefCell<(Vec<libc::iovec>, Vec<libc::mmsghdr>)> =
        const { RefCell::new((Vec::new(), Vec::new())) };
    static SEND_SCRATCH: RefCell<(Vec<libc::iovec>, Vec<libc::mmsghdr>)> =
        const { RefCell::new((Vec::new(), Vec::new())) };
}

fn sockaddr_v4(ip: Ipv4Addr) -> libc::sockaddr_in {
    let mut sa: libc::sockaddr_in = unsafe { mem::zeroed() };
    sa.sin_family = libc::AF_INET as libc::sa_family_t;
    sa.sin_addr = libc::in_addr {
        s_addr: u32::from_ne_bytes(ip.octets()),
    };
    sa
}

/// Батч приёма. Хранит только Send-данные (буферы/адреса/длины); временные
/// `iovec`/`mmsghdr` с сырыми указателями строятся локально в момент syscall,
/// чтобы структуру можно было держать через `.await` в read-таске.
///
/// `msg_name` держим как `sockaddr_storage` - влезает и sockaddr_in (inet), и
/// sockaddr_ll (AF_PACKET); src в режиме packet всё равно берём из IP-заголовка.
pub struct RecvBatch {
    cap: usize,
    bufsz: usize,
    bufs: Vec<Vec<u8>>,
    addrs: Vec<libc::sockaddr_storage>,
    lens: Vec<usize>,
}

impl RecvBatch {
    pub fn new(cap: usize) -> RecvBatch {
        Self::with_bufsz(cap, BUFSZ)
    }

    pub fn with_bufsz(cap: usize, bufsz: usize) -> RecvBatch {
        let bufsz = bufsz.clamp(2048, BUFSZ);
        RecvBatch {
            cap,
            bufsz,
            bufs: vec![vec![0u8; bufsz]; cap],
            addrs: vec![unsafe { mem::zeroed() }; cap],
            lens: vec![0usize; cap],
        }
    }

    /// Один вызов recvmmsg. Возвращает число принятых пакетов или Err(WouldBlock).
    pub fn recv(&mut self, sock: &Socket) -> io::Result<usize> {
        let n = self.cap;
        RECV_SCRATCH.with(|cell| {
            let mut scratch = cell.borrow_mut();
            let (iovs, msgs) = &mut *scratch;
            iovs.clear();
            for i in 0..n {
                iovs.push(libc::iovec {
                    iov_base: self.bufs[i].as_mut_ptr() as *mut libc::c_void,
                    iov_len: self.bufsz,
                });
            }
            msgs.clear();
            for (addr, iov) in self.addrs[..n].iter_mut().zip(iovs.iter_mut()) {
                let mut mh: libc::mmsghdr = unsafe { mem::zeroed() };
                mh.msg_hdr.msg_name = addr as *mut _ as *mut libc::c_void;
                mh.msg_hdr.msg_namelen =
                    mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
                mh.msg_hdr.msg_iov = iov as *mut libc::iovec;
                mh.msg_hdr.msg_iovlen = 1;
                msgs.push(mh);
            }
            let r = unsafe {
                libc::recvmmsg(
                    sock.as_raw_fd(),
                    msgs.as_mut_ptr(),
                    n as libc::c_uint,
                    libc::MSG_DONTWAIT,
                    ptr::null_mut(),
                )
            };
            if r < 0 {
                return Err(io::Error::last_os_error());
            }
            for (slot, mh) in self.lens[..r as usize].iter_mut().zip(msgs.iter()) {
                *slot = mh.msg_len as usize;
            }
            Ok(r as usize)
        })
    }

    /// Возвращает (байты пакета, src из адреса). В режиме AF_PACKET адрес - это
    /// sockaddr_ll (не IP), поэтому src берётся вызывающим из IP-заголовка.
    pub fn get(&self, i: usize) -> (&[u8], Ipv4Addr) {
        let len = self.lens[i].min(self.bufsz);
        let ip = unsafe {
            let sa = &self.addrs[i];
            if sa.ss_family == libc::AF_INET as libc::sa_family_t {
                let sin = &*(sa as *const _ as *const libc::sockaddr_in);
                Ipv4Addr::from(sin.sin_addr.s_addr.to_ne_bytes())
            } else {
                Ipv4Addr::UNSPECIFIED
            }
        };
        (&self.bufs[i][..len], ip)
    }
}

// ── Батч отправки (sendmmsg) ─────────────────────────────────────────────

/// Накопитель исходящих пакетов; шлёт пачкой через sendmmsg. Хранит только
/// Send-данные; временные iovec/mmsghdr строятся локально в момент send().
pub struct SendBatch {
    dsts: Vec<libc::sockaddr_in>,
    bufs: Vec<Vec<u8>>,
}

impl SendBatch {
    pub fn new() -> SendBatch {
        SendBatch {
            dsts: Vec::new(),
            bufs: Vec::new(),
        }
    }

    pub fn push(&mut self, dst: Ipv4Addr, bytes: Vec<u8>) {
        self.dsts.push(sockaddr_v4(dst));
        self.bufs.push(bytes);
    }

    pub fn is_empty(&self) -> bool {
        self.bufs.is_empty()
    }

    /// Шлёт текущую пачку. Возвращает число отправленных; отправленные удаляются
    /// из начала (оставшиеся можно дослать после writable).
    pub fn send(&mut self, sock: &Socket) -> io::Result<usize> {
        let n = self.bufs.len();
        if n == 0 {
            return Ok(0);
        }
        let sent = SEND_SCRATCH.with(|cell| {
            let mut scratch = cell.borrow_mut();
            let (iovs, msgs) = &mut *scratch;
            iovs.clear();
            for i in 0..n {
                iovs.push(libc::iovec {
                    iov_base: self.bufs[i].as_mut_ptr() as *mut libc::c_void,
                    iov_len: self.bufs[i].len(),
                });
            }
            msgs.clear();
            for (dst, iov) in self.dsts[..n].iter_mut().zip(iovs.iter_mut()) {
                let mut mh: libc::mmsghdr = unsafe { mem::zeroed() };
                mh.msg_hdr.msg_name = dst as *mut _ as *mut libc::c_void;
                mh.msg_hdr.msg_namelen = mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
                mh.msg_hdr.msg_iov = iov as *mut libc::iovec;
                mh.msg_hdr.msg_iovlen = 1;
                msgs.push(mh);
            }
            let r = unsafe {
                libc::sendmmsg(
                    sock.as_raw_fd(),
                    msgs.as_mut_ptr(),
                    n as libc::c_uint,
                    libc::MSG_DONTWAIT,
                )
            };
            if r < 0 {
                Err(io::Error::last_os_error())
            } else {
                Ok(r as usize)
            }
        })?;
        self.dsts.drain(0..sent);
        self.bufs.drain(0..sent);
        Ok(sent)
    }
}

impl Default for SendBatch {
    fn default() -> Self {
        Self::new()
    }
}

/// Готовый к отправке пакет: (адрес назначения, байты сообщения, номер
/// IP-протокола, через который слать - в режиме ротации; иначе игнорируется).
pub type OutPkt = (Ipv4Addr, Vec<u8>, u8);

/// Запускает единый write-таск: собирает исходящие пакеты из канала в пачки и
/// шлёт через нужный сокет (`sendmmsg`). В одиночном режиме - один сокет на всё;
/// в режиме ротации сокеты под протоколы открываются лениво и кэшируются.
pub fn spawn_writer(t: &Transport, chan: usize) -> tokio::sync::mpsc::Sender<OutPkt> {
    let (tx, mut rx) = tokio::sync::mpsc::channel::<OutPkt>(chan);
    let single = t.tx_single.clone();
    let bind_ip = t.bind_ip;
    tokio::spawn(async move {
        let mut batches: HashMap<u8, SendBatch> = HashMap::new();
        // Кэш отправляющих сокетов по номеру протокола (режим ротации).
        let mut tx_socks: HashMap<u8, Arc<IcmpIo>> = HashMap::new();
        const MAX_BATCH: usize = 256;
        while let Some((ip, bytes, proto)) = rx.recv().await {
            batches.entry(proto).or_default().push(ip, bytes);
            let mut total = 1usize;
            while total < MAX_BATCH {
                match rx.try_recv() {
                    Ok((ip, bytes, proto)) => {
                        batches.entry(proto).or_default().push(ip, bytes);
                        total += 1;
                    }
                    Err(_) => break,
                }
            }
            for (proto, batch) in batches.iter_mut() {
                if batch.is_empty() {
                    continue;
                }
                // Выбираем сокет: одиночный режим - общий; ротация - ленивый по proto.
                let io = if let Some(s) = &single {
                    s.clone()
                } else {
                    match tx_socks.get(proto) {
                        Some(s) => s.clone(),
                        None => match open_inet_raw(bind_ip, *proto) {
                            Ok(s) => {
                                tx_socks.insert(*proto, s.clone());
                                s
                            }
                            Err(e) => {
                                log::debug!("open tx sock proto={proto}: {e}");
                                batch.bufs.clear();
                                batch.dsts.clear();
                                continue;
                            }
                        },
                    }
                };
                while !batch.is_empty() {
                    let mut guard = match io.fd.writable().await {
                        Ok(g) => g,
                        Err(_) => break,
                    };
                    match guard.try_io(|s| batch.send(s.get_ref())) {
                        Ok(Ok(_)) => {}
                        Ok(Err(e)) => {
                            log::debug!("sendmmsg error: {e}");
                            break;
                        }
                        Err(_would_block) => {}
                    }
                }
            }
        }
    });
    tx
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checksum_zeroes_over_complete_message() {
        let pkt = build_echo(ICMP_ECHO_REQUEST, 0x1234, 0x0001, b"ping payload");
        assert_eq!(checksum(&pkt), 0);
    }

    #[test]
    fn encode_parse_roundtrip() {
        let my = MyMsg {
            id: "conn-1".into(),
            r#type: 0,
            data: vec![1, 2, 3, 4, 5],
            rproto: -1,
            key: 123456,
            ..Default::default()
        };
        let wire = Wire::new(None, 0, false);
        let pkt = encode_packet(my, ICMP_ECHO_REQUEST, 0xBEEF, 0x00AA, &wire);
        // datagram=true: pkt - это уже сообщение без IP-заголовка
        let (got, id, seq) = parse_packet(&pkt, true, &wire).unwrap();
        assert_eq!(got.id, "conn-1");
        assert_eq!(got.rproto, -1);
        assert_eq!(got.key, 123456);
        assert_eq!(got.data, vec![1, 2, 3, 4, 5]);
        assert_eq!(id, 0xBEEF);
        assert_eq!(seq, 0x00AA);
    }

    fn sample_msg() -> MyMsg {
        MyMsg {
            id: "conn-xyz".into(),
            r#type: 0,
            data: vec![9; 20],
            rproto: -1,
            key: 42,
            ..Default::default()
        }
    }

    #[test]
    fn padding_randomizes_size_and_strips() {
        // Паддинг меняет размер пакета, но полезная нагрузка восстанавливается.
        let wire = Wire::new(None, 256, false);
        let mut sizes = std::collections::HashSet::new();
        for _ in 0..32 {
            let pkt = encode_packet(sample_msg(), ICMP_ECHO_REQUEST, 1, 1, &wire);
            sizes.insert(pkt.len());
            let (got, _, _) = parse_packet(&pkt, true, &wire).unwrap();
            assert_eq!(got.data, vec![9; 20]); // полезная нагрузка цела, pad игнорируется
        }
        // За 32 пакета при разбросе 0..256 размеры почти наверняка не совпадут все.
        assert!(sizes.len() > 1, "padding не рандомизирует размер");
    }

    #[test]
    fn obfs_roundtrip_no_echo_header() {
        // С обфускацией на проводе нет echo-заголовка; шифрование обязательно.
        let crypto = Crypto::new(crate::crypto::EncryptionMode::ChaCha20, "pass").unwrap();
        let wire = Wire::new(crypto, 0, true);
        let pkt = encode_packet(sample_msg(), ICMP_ECHO_REQUEST, 0xBEEF, 0x00AA, &wire);
        // datagram=true: pkt - тело IP без заголовка, т.е. nonce||ciphertext.
        let (got, id, seq) = parse_packet(&pkt, true, &wire).unwrap();
        assert_eq!(got.id, "conn-xyz");
        assert_eq!(got.data, vec![9; 20]);
        // echo_id/seq в obfs недоступны - нули.
        assert_eq!(id, 0);
        assert_eq!(seq, 0);
    }
}
