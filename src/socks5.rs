//! Реализация SOCKS5: серверное рукопожатие (с опциональной аутентификацией
//! по логину/паролю), разбор запроса CONNECT/UDP ASSOCIATE, кодирование адресов
//! и упаковка/разбор UDP-датаграмм SOCKS5. Порт socks5.go и gohome Sock5HandshakeBy.

use anyhow::{anyhow, bail, Result};
use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr};

pub const SOCKS5_VERSION: u8 = 0x05;

pub const CMD_CONNECT: u8 = 0x01;
pub const CMD_UDP_ASSOCIATE: u8 = 0x03;

pub const ATYP_IPV4: u8 = 0x01;
pub const ATYP_DOMAIN: u8 = 0x03;
pub const ATYP_IPV6: u8 = 0x04;

pub const REPLY_SUCCEEDED: u8 = 0x00;
pub const REPLY_GENERAL_FAILURE: u8 = 0x01;
pub const REPLY_COMMAND_NOT_SUPPORTED: u8 = 0x07;

const AUTH_VERSION: u8 = 0x01;

pub struct Socks5Request {
    pub command: u8,
    pub address: String,
}

fn read_full<R: Read>(r: &mut R, buf: &mut [u8]) -> Result<()> {
    r.read_exact(buf).map_err(|e| anyhow!("read: {e}"))
}

/// Серверное рукопожатие SOCKS5. Поддерживает no-auth и user/pass.
pub fn server_handshake<S: Read + Write>(
    conn: &mut S,
    username: &str,
    password: &str,
) -> Result<()> {
    let mut head = [0u8; 2];
    read_full(conn, &mut head)?;
    if head[0] != SOCKS5_VERSION {
        bail!("socks version not supported: {}", head[0]);
    }
    let nmethod = head[1] as usize;
    let mut methods = vec![0u8; nmethod];
    read_full(conn, &mut methods)?;

    if username.is_empty() && password.is_empty() {
        conn.write_all(&[SOCKS5_VERSION, 0x00])?; // no auth
    } else {
        conn.write_all(&[SOCKS5_VERSION, 0x02])?; // user/pass
        let mut header = [0u8; 2];
        read_full(conn, &mut header)?;
        if header[0] != AUTH_VERSION {
            bail!("unsupported auth version: {}", header[0]);
        }
        let ulen = header[1] as usize;
        let mut user = vec![0u8; ulen];
        read_full(conn, &mut user)?;
        let mut plen = [0u8; 1];
        read_full(conn, &mut plen)?;
        let mut pass = vec![0u8; plen[0] as usize];
        read_full(conn, &mut pass)?;
        let ok = user == username.as_bytes() && pass == password.as_bytes();
        conn.write_all(&[AUTH_VERSION, if ok { 0x00 } else { 0x01 }])?;
        if !ok {
            bail!("socks5 auth failed");
        }
    }
    Ok(())
}

/// Читает запрос SOCKS5 (после рукопожатия): команда + адрес назначения.
pub fn read_request<R: Read>(r: &mut R) -> Result<Socks5Request> {
    let mut header = [0u8; 4];
    read_full(r, &mut header)?;
    if header[0] != SOCKS5_VERSION {
        bail!("unsupported socks version: {}", header[0]);
    }
    if header[2] != 0x00 {
        bail!("invalid socks reserved byte: {}", header[2]);
    }
    let addr = read_address(r, header[3])?;
    Ok(Socks5Request {
        command: header[1],
        address: addr,
    })
}

/// Читает адрес из потока по типу адреса (используется и в запросе, и в ответах).
pub fn read_address<R: Read>(r: &mut R, atyp: u8) -> Result<String> {
    match atyp {
        ATYP_IPV4 => {
            let mut buf = [0u8; 4 + 2];
            read_full(r, &mut buf)?;
            let ip = std::net::Ipv4Addr::new(buf[0], buf[1], buf[2], buf[3]);
            let port = u16::from_be_bytes([buf[4], buf[5]]);
            Ok(format!("{ip}:{port}"))
        }
        ATYP_IPV6 => {
            let mut buf = [0u8; 16 + 2];
            read_full(r, &mut buf)?;
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&buf[..16]);
            let ip = std::net::Ipv6Addr::from(octets);
            let port = u16::from_be_bytes([buf[16], buf[17]]);
            Ok(format!("[{ip}]:{port}"))
        }
        ATYP_DOMAIN => {
            let mut lb = [0u8; 1];
            read_full(r, &mut lb)?;
            let dlen = lb[0] as usize;
            if dlen == 0 {
                bail!("invalid empty domain");
            }
            let mut buf = vec![0u8; dlen + 2];
            read_full(r, &mut buf)?;
            let host = String::from_utf8_lossy(&buf[..dlen]).to_string();
            let port = u16::from_be_bytes([buf[dlen], buf[dlen + 1]]);
            Ok(format!("{host}:{port}"))
        }
        other => bail!("unsupported socks5 address type: {other}"),
    }
}

/// Пишет ответ SOCKS5 (VER REP RSV ATYP BND.ADDR BND.PORT).
pub fn write_reply<W: Write>(w: &mut W, rep: u8, bind_addr: &str) -> Result<()> {
    let bind_addr = if bind_addr.is_empty() {
        "0.0.0.0:0"
    } else {
        bind_addr
    };
    let encoded = encode_address(bind_addr)?;
    let mut reply = Vec::with_capacity(3 + encoded.len());
    reply.extend_from_slice(&[SOCKS5_VERSION, rep, 0x00]);
    reply.extend_from_slice(&encoded);
    w.write_all(&reply)?;
    Ok(())
}

/// Кодирует "host:port" в формат адреса SOCKS5 (ATYP + ADDR + PORT).
pub fn encode_address(addr: &str) -> Result<Vec<u8>> {
    let (host, port) = split_host_port(addr)?;
    let port_hi = (port >> 8) as u8;
    let port_lo = (port & 0xff) as u8;

    if let Ok(ip) = host.parse::<IpAddr>() {
        match ip {
            IpAddr::V4(v4) => {
                let mut out = Vec::with_capacity(1 + 4 + 2);
                out.push(ATYP_IPV4);
                out.extend_from_slice(&v4.octets());
                out.push(port_hi);
                out.push(port_lo);
                return Ok(out);
            }
            IpAddr::V6(v6) => {
                let mut out = Vec::with_capacity(1 + 16 + 2);
                out.push(ATYP_IPV6);
                out.extend_from_slice(&v6.octets());
                out.push(port_hi);
                out.push(port_lo);
                return Ok(out);
            }
        }
    }

    if host.is_empty() || host.len() > 255 {
        bail!("invalid domain length for {host}");
    }
    let mut out = Vec::with_capacity(1 + 1 + host.len() + 2);
    out.push(ATYP_DOMAIN);
    out.push(host.len() as u8);
    out.extend_from_slice(host.as_bytes());
    out.push(port_hi);
    out.push(port_lo);
    Ok(out)
}

/// Разбирает адрес SOCKS5 из среза. Возвращает (адрес, число потреблённых байт).
pub fn parse_address(data: &[u8]) -> Result<(String, usize)> {
    if data.is_empty() {
        bail!("empty socks5 address payload");
    }
    match data[0] {
        ATYP_IPV4 => {
            let total = 1 + 4 + 2;
            if data.len() < total {
                bail!("truncated ipv4 socks5 address");
            }
            let ip = std::net::Ipv4Addr::new(data[1], data[2], data[3], data[4]);
            let port = u16::from_be_bytes([data[5], data[6]]);
            Ok((format!("{ip}:{port}"), total))
        }
        ATYP_IPV6 => {
            let total = 1 + 16 + 2;
            if data.len() < total {
                bail!("truncated ipv6 socks5 address");
            }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&data[1..17]);
            let ip = std::net::Ipv6Addr::from(octets);
            let port = u16::from_be_bytes([data[17], data[18]]);
            Ok((format!("[{ip}]:{port}"), total))
        }
        ATYP_DOMAIN => {
            if data.len() < 2 {
                bail!("truncated domain socks5 address");
            }
            let dlen = data[1] as usize;
            let total = 1 + 1 + dlen + 2;
            if data.len() < total || dlen == 0 {
                bail!("truncated/empty domain socks5 address");
            }
            let host = String::from_utf8_lossy(&data[2..2 + dlen]).to_string();
            let port = u16::from_be_bytes([data[2 + dlen], data[2 + dlen + 1]]);
            Ok((format!("{host}:{port}"), total))
        }
        other => bail!("unsupported socks5 address type: {other}"),
    }
}

/// Разбирает UDP-датаграмму SOCKS5: возвращает (адрес назначения, payload).
pub fn parse_udp_datagram(packet: &[u8]) -> Result<(String, Vec<u8>)> {
    if packet.len() < 4 {
        bail!("socks5 udp packet too short");
    }
    if packet[0] != 0x00 || packet[1] != 0x00 {
        bail!("invalid reserved bytes");
    }
    if packet[2] != 0x00 {
        bail!("fragmentation not supported");
    }
    let (addr, consumed) = parse_address(&packet[3..])?;
    let start = 3 + consumed;
    Ok((addr, packet[start..].to_vec()))
}

/// Строит UDP-датаграмму SOCKS5 из адреса назначения и payload.
pub fn build_udp_datagram(target: &str, payload: &[u8]) -> Result<Vec<u8>> {
    let addr = encode_address(target)?;
    let mut out = Vec::with_capacity(3 + addr.len() + payload.len());
    out.extend_from_slice(&[0x00, 0x00, 0x00]);
    out.extend_from_slice(&addr);
    out.extend_from_slice(payload);
    Ok(out)
}

/// Разбивает "host:port" (поддерживает IPv6 в скобках).
pub fn split_host_port(addr: &str) -> Result<(String, u16)> {
    if let Ok(sa) = addr.parse::<SocketAddr>() {
        return Ok((sa.ip().to_string(), sa.port()));
    }
    let idx = addr
        .rfind(':')
        .ok_or_else(|| anyhow!("invalid address {addr}"))?;
    let host = &addr[..idx];
    let port: u16 = addr[idx + 1..]
        .parse()
        .map_err(|_| anyhow!("invalid port in {addr}"))?;
    let host = host.trim_start_matches('[').trim_end_matches(']');
    Ok((host.to_string(), port))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_parse_ipv4() {
        let enc = encode_address("93.184.216.34:443").unwrap();
        assert_eq!(enc[0], ATYP_IPV4);
        let (addr, consumed) = parse_address(&enc).unwrap();
        assert_eq!(addr, "93.184.216.34:443");
        assert_eq!(consumed, enc.len());
    }

    #[test]
    fn encode_parse_domain() {
        let enc = encode_address("example.com:80").unwrap();
        assert_eq!(enc[0], ATYP_DOMAIN);
        let (addr, consumed) = parse_address(&enc).unwrap();
        assert_eq!(addr, "example.com:80");
        assert_eq!(consumed, enc.len());
    }

    #[test]
    fn udp_datagram_roundtrip() {
        let payload = b"payload-bytes";
        let dgram = build_udp_datagram("1.2.3.4:53", payload).unwrap();
        let (target, got) = parse_udp_datagram(&dgram).unwrap();
        assert_eq!(target, "1.2.3.4:53");
        assert_eq!(got, payload);
    }

    #[test]
    fn split_host_port_variants() {
        assert_eq!(split_host_port("host:1234").unwrap(), ("host".to_string(), 1234));
        assert_eq!(
            split_host_port("10.0.0.1:8080").unwrap(),
            ("10.0.0.1".to_string(), 8080)
        );
    }
}
