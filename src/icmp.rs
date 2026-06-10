//! Асинхронный ICMP-транспорт с батчингом syscalls.
//!
//! Главная цель — убрать «один syscall на пакет» (это давало ~72% sys CPU на
//! сервере). Чтение/запись идут пачками через `recvmmsg`/`sendmmsg` (десятки
//! пакетов за один вызов ядра), а сокет интегрирован в tokio через `AsyncFd`.
//!
//! Сборка/разбор echo-пакетов и упаковка `MyMsg` (с опц. шифрованием) — здесь же.

use crate::crypto::Crypto;
use crate::proto::{MyMsg, MAGIC};
use anyhow::Result;
use prost::Message;
use socket2::{Domain, Protocol, Socket, Type};
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::os::unix::io::AsRawFd;
use std::{mem, ptr};
use tokio::io::unix::AsyncFd;

pub const ICMP_ECHO_REQUEST: u8 = 8;
#[allow(dead_code)]
pub const ICMP_ECHO_REPLY: u8 = 0;

// Должен вмещать самый большой ICMP-датаграм (jumbo-кадр + IP/ICMP-заголовки
// после сборки IP-фрагментов ядром). 64 КБ покрывает любой допустимый размер.
const BUFSZ: usize = 65535;

/// Номер IP-протокола для ICMP (IANA). Транспорт по умолчанию.
pub const IP_PROTO_ICMP: u8 = 1;

/// Открывает транспортный raw-сокет на IP-протоколе `proto`.
///
/// `proto == 1` (ICMP): как раньше — RAW, при отказе непривилегированный
/// datagram-фоллбэк. Любой другой номер (напр. 253/254 из RFC 3692, под
/// эксперименты) — это кастомный IP-протокол: только RAW (нужен CAP_NET_RAW),
/// datagram-фоллбэка нет. Формат пакета (8-байтный псевдо-echo заголовок +
/// protobuf) одинаков для всех протоколов — меняется лишь поле protocol в
/// IP-заголовке, которое строит ядро.
///
/// ВНИМАНИЕ: кастомный протокол не переживает NAT (трансляция есть только для
/// TCP/UDP/ICMP) и режется большинством файрволов. Имеет смысл только при
/// прямой маршрутизации между клиентом и сервером без NAT по пути.
///
/// Делает сокет неблокирующим и тюнит буферы. Возвращает сокет и флаг datagram.
pub fn listen_icmp(addr: &str, proto: u8) -> Result<(Socket, bool)> {
    let ip: Ipv4Addr = if addr.is_empty() {
        Ipv4Addr::UNSPECIFIED
    } else {
        addr.parse().unwrap_or(Ipv4Addr::UNSPECIFIED)
    };
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
        log::info!("транспорт: кастомный IP-протокол {proto} (RAW, экспериментальный)");
        (s, false)
    };
    socket.bind(&bind.into())?;
    socket.set_nonblocking(true)?;
    let _ = socket.set_send_buffer_size(8 << 20);
    let _ = socket.set_recv_buffer_size(16 << 20);
    Ok((socket, datagram))
}

/// Асинхронный ICMP-сокет, разделяемый между read- и write-тасками.
pub struct IcmpIo {
    pub fd: AsyncFd<Socket>,
}

impl IcmpIo {
    pub fn new(socket: Socket) -> io::Result<IcmpIo> {
        Ok(IcmpIo {
            fd: AsyncFd::new(socket)?,
        })
    }
}

// ── Контрольная сумма и сборка echo ──────────────────────────────────────

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

/// Кодирует MyMsg в готовый ICMP-пакет (encode + шифрование + echo-обёртка).
pub fn encode_packet(
    mut my: MyMsg,
    sproto: u8,
    icmp_id: u16,
    seq: u16,
    crypto: Option<&Crypto>,
) -> Vec<u8> {
    my.magic = MAGIC;
    let mut payload = Vec::with_capacity(my.encoded_len());
    my.encode(&mut payload).expect("encode MyMsg");
    if let Some(c) = crypto {
        payload = c.encrypt(&payload).unwrap_or(payload);
    }
    build_echo(sproto, icmp_id, seq, &payload)
}

/// Разбирает входящий ICMP-пакет (RAW: с IP-заголовком; datagram: без него).
/// Возвращает (MyMsg, echo_id, echo_seq) либо None для чужих/битых.
pub fn parse_packet(
    raw: &[u8],
    datagram: bool,
    crypto: Option<&Crypto>,
) -> Option<(MyMsg, u16, u16)> {
    if raw.is_empty() {
        return None;
    }
    let icmp = if datagram {
        raw
    } else {
        let ihl = ((raw[0] & 0x0f) as usize) * 4;
        if raw.len() < ihl + 8 {
            return None;
        }
        &raw[ihl..]
    };
    if icmp.len() < 8 {
        return None;
    }
    let echo_id = u16::from_be_bytes([icmp[4], icmp[5]]);
    let echo_seq = u16::from_be_bytes([icmp[6], icmp[7]]);
    let mut payload = icmp[8..].to_vec();
    if let Some(c) = crypto {
        payload = c.decrypt(&payload).ok()?;
    }
    let my = MyMsg::decode(&payload[..]).ok()?;
    if my.magic != MAGIC {
        return None;
    }
    Some((my, echo_id, echo_seq))
}

// ── Батч приёма (recvmmsg) ───────────────────────────────────────────────

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
pub struct RecvBatch {
    cap: usize,
    bufs: Vec<[u8; BUFSZ]>,
    addrs: Vec<libc::sockaddr_in>,
    lens: Vec<usize>,
}

impl RecvBatch {
    pub fn new(cap: usize) -> RecvBatch {
        RecvBatch {
            cap,
            bufs: vec![[0u8; BUFSZ]; cap],
            addrs: vec![unsafe { mem::zeroed() }; cap],
            lens: vec![0usize; cap],
        }
    }

    /// Один вызов recvmmsg. Возвращает число принятых пакетов или Err(WouldBlock).
    pub fn recv(&mut self, sock: &Socket) -> io::Result<usize> {
        let n = self.cap;
        let mut iovs: Vec<libc::iovec> = Vec::with_capacity(n);
        for i in 0..n {
            iovs.push(libc::iovec {
                iov_base: self.bufs[i].as_mut_ptr() as *mut libc::c_void,
                iov_len: BUFSZ,
            });
        }
        let mut msgs: Vec<libc::mmsghdr> = Vec::with_capacity(n);
        for i in 0..n {
            let mut mh: libc::mmsghdr = unsafe { mem::zeroed() };
            mh.msg_hdr.msg_name = &mut self.addrs[i] as *mut _ as *mut libc::c_void;
            mh.msg_hdr.msg_namelen = mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
            mh.msg_hdr.msg_iov = &mut iovs[i] as *mut libc::iovec;
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
        for i in 0..r as usize {
            self.lens[i] = msgs[i].msg_len as usize;
        }
        Ok(r as usize)
    }

    pub fn get(&self, i: usize) -> (&[u8], Ipv4Addr) {
        let len = self.lens[i].min(BUFSZ);
        let ip = Ipv4Addr::from(self.addrs[i].sin_addr.s_addr.to_ne_bytes());
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

    pub fn len(&self) -> usize {
        self.bufs.len()
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
        let mut iovs: Vec<libc::iovec> = Vec::with_capacity(n);
        for i in 0..n {
            iovs.push(libc::iovec {
                iov_base: self.bufs[i].as_mut_ptr() as *mut libc::c_void,
                iov_len: self.bufs[i].len(),
            });
        }
        let mut msgs: Vec<libc::mmsghdr> = Vec::with_capacity(n);
        for i in 0..n {
            let mut mh: libc::mmsghdr = unsafe { mem::zeroed() };
            mh.msg_hdr.msg_name = &mut self.dsts[i] as *mut _ as *mut libc::c_void;
            mh.msg_hdr.msg_namelen = mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
            mh.msg_hdr.msg_iov = &mut iovs[i] as *mut libc::iovec;
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
            return Err(io::Error::last_os_error());
        }
        let sent = r as usize;
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

/// Готовый к отправке пакет: (адрес назначения, полные байты ICMP-сообщения).
pub type OutPkt = (Ipv4Addr, Vec<u8>);

/// Запускает единый write-таск: собирает исходящие пакеты из канала в пачки и
/// шлёт их через sendmmsg (минимум syscalls). Возвращает отправитель в канал.
pub fn spawn_writer(io: std::sync::Arc<IcmpIo>, chan: usize) -> tokio::sync::mpsc::Sender<OutPkt> {
    let (tx, mut rx) = tokio::sync::mpsc::channel::<OutPkt>(chan);
    tokio::spawn(async move {
        let mut batch = SendBatch::new();
        const MAX_BATCH: usize = 256;
        while let Some((ip, bytes)) = rx.recv().await {
            batch.push(ip, bytes);
            while batch.len() < MAX_BATCH {
                match rx.try_recv() {
                    Ok((ip, bytes)) => batch.push(ip, bytes),
                    Err(_) => break,
                }
            }
            while !batch.is_empty() {
                let mut guard = match io.fd.writable().await {
                    Ok(g) => g,
                    Err(_) => break,
                };
                match guard.try_io(|s| batch.send(s.get_ref())) {
                    Ok(Ok(_)) => {} // отправили часть/всё; если остаток — снова writable
                    Ok(Err(e)) => {
                        log::debug!("sendmmsg error: {e}");
                        break;
                    }
                    Err(_would_block) => {} // готовность снята, ждём снова
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
        let pkt = encode_packet(my, ICMP_ECHO_REQUEST, 0xBEEF, 0x00AA, None);
        // datagram=true: pkt — это уже ICMP-сообщение без IP-заголовка
        let (got, id, seq) = parse_packet(&pkt, true, None).unwrap();
        assert_eq!(got.id, "conn-1");
        assert_eq!(got.rproto, -1);
        assert_eq!(got.key, 123456);
        assert_eq!(got.data, vec![1, 2, 3, 4, 5]);
        assert_eq!(id, 0xBEEF);
        assert_eq!(seq, 0x00AA);
    }
}
