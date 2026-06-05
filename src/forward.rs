//! Форвардинг исходящих соединений сервера через прокси (socks5 или http CONNECT),
//! а также SOCKS5 UDP ASSOCIATE. Порт forward.go.

use crate::socks5;
use anyhow::{anyhow, bail, Result};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpStream, UdpSocket};
use std::time::Duration;

#[derive(Clone, Debug)]
pub struct ForwardConfig {
    pub scheme: String, // "socks5" | "http"
    pub host: String,
    pub port: u16,
}

impl ForwardConfig {
    pub fn address(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }
}

/// Разбирает URL вида socks5://host:port или http://host:port.
pub fn parse_forward_url(raw: &str) -> Result<Option<ForwardConfig>> {
    if raw.is_empty() {
        return Ok(None);
    }
    let (scheme, rest) = raw
        .split_once("://")
        .ok_or_else(|| anyhow!("invalid forward URL: {raw}"))?;
    if scheme != "socks5" && scheme != "http" {
        bail!("unsupported proxy scheme: {scheme} (supported: socks5, http)");
    }
    let hostport = rest.trim_end_matches('/');
    let (host, port) = socks5::split_host_port(hostport)?;
    if host.is_empty() {
        bail!("missing proxy host in forward URL");
    }
    Ok(Some(ForwardConfig {
        scheme: scheme.to_string(),
        host,
        port,
    }))
}

fn connect_proxy(config: &ForwardConfig, timeout: Duration) -> Result<TcpStream> {
    let addr: SocketAddr = config
        .address()
        .to_socket_addrs_first()
        .ok_or_else(|| anyhow!("cannot resolve proxy address"))?;
    let conn = TcpStream::connect_timeout(&addr, timeout)
        .map_err(|e| anyhow!("failed to connect to proxy: {e}"))?;
    conn.set_read_timeout(Some(timeout))?;
    conn.set_write_timeout(Some(timeout))?;
    Ok(conn)
}

/// Устанавливает TCP-соединение к target через прокси.
pub fn dial_through_proxy(
    config: &ForwardConfig,
    target: &str,
    timeout: Duration,
) -> Result<TcpStream> {
    let mut conn = connect_proxy(config, timeout)?;
    match config.scheme.as_str() {
        "socks5" => socks5_connect(&mut conn, target)?,
        "http" => http_connect(&mut conn, target)?,
        other => bail!("unsupported proxy scheme: {other}"),
    }
    // Снимаем таймауты после рукопожатия (блокирующий режим без дедлайнов).
    conn.set_read_timeout(None)?;
    conn.set_write_timeout(None)?;
    Ok(conn)
}

/// UDP-ассоциация через SOCKS5: держим управляющий TCP открытым на время жизни.
pub struct UdpForwardAssociation {
    pub control: TcpStream,
    pub udp: UdpSocket,
    pub relay: SocketAddr,
}

pub fn dial_udp_through_proxy(
    config: &ForwardConfig,
    timeout: Duration,
) -> Result<UdpForwardAssociation> {
    if config.scheme != "socks5" {
        bail!("unsupported proxy scheme for UDP: {}", config.scheme);
    }
    let udp = UdpSocket::bind("0.0.0.0:0")?;
    let mut tcp = connect_proxy(config, timeout)?;

    socks5_negotiate_no_auth(&mut tcp)?;
    let local = udp.local_addr()?;
    let associate = associate_addr(&local);
    socks5_send_command(&mut tcp, socks5::CMD_UDP_ASSOCIATE, &associate)?;

    let (rep, relay_str) = socks5_read_reply(&mut tcp)?;
    if rep != socks5::REPLY_SUCCEEDED {
        bail!("SOCKS5 UDP ASSOCIATE failed with code {rep}");
    }
    let relay: SocketAddr = relay_str
        .to_socket_addrs_first()
        .ok_or_else(|| anyhow!("cannot resolve relay address {relay_str}"))?;

    tcp.set_read_timeout(None)?;
    tcp.set_write_timeout(None)?;
    Ok(UdpForwardAssociation {
        control: tcp,
        udp,
        relay,
    })
}

fn associate_addr(local: &SocketAddr) -> String {
    if local.ip().is_unspecified() {
        format!("0.0.0.0:{}", local.port())
    } else {
        local.to_string()
    }
}

fn socks5_negotiate_no_auth(conn: &mut TcpStream) -> Result<()> {
    conn.write_all(&[socks5::SOCKS5_VERSION, 0x01, 0x00])?;
    let mut resp = [0u8; 2];
    conn.read_exact(&mut resp)?;
    if resp[0] != socks5::SOCKS5_VERSION {
        bail!("unexpected SOCKS version: {}", resp[0]);
    }
    if resp[1] == 0xFF {
        bail!("SOCKS5 proxy requires authentication (not supported)");
    }
    if resp[1] != 0x00 {
        bail!("unexpected SOCKS5 auth method: {}", resp[1]);
    }
    Ok(())
}

fn socks5_send_command(conn: &mut TcpStream, cmd: u8, target: &str) -> Result<()> {
    let encoded = socks5::encode_address(target)?;
    let mut req = Vec::with_capacity(3 + encoded.len());
    req.extend_from_slice(&[socks5::SOCKS5_VERSION, cmd, 0x00]);
    req.extend_from_slice(&encoded);
    conn.write_all(&req)?;
    Ok(())
}

fn socks5_read_reply(conn: &mut TcpStream) -> Result<(u8, String)> {
    let mut header = [0u8; 4];
    conn.read_exact(&mut header)?;
    if header[0] != socks5::SOCKS5_VERSION {
        bail!("unexpected SOCKS version in reply: {}", header[0]);
    }
    if header[2] != 0x00 {
        bail!("invalid socks reserved byte in reply");
    }
    let addr = socks5::read_address(conn, header[3])?;
    Ok((header[1], addr))
}

fn socks5_connect(conn: &mut TcpStream, target: &str) -> Result<()> {
    socks5_negotiate_no_auth(conn)?;
    socks5_send_command(conn, socks5::CMD_CONNECT, target)?;
    let (rep, _addr) = socks5_read_reply(conn)?;
    if rep != socks5::REPLY_SUCCEEDED {
        bail!("SOCKS5 connect failed with code {rep}");
    }
    Ok(())
}

fn http_connect(conn: &mut TcpStream, target: &str) -> Result<()> {
    let request = format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n");
    conn.write_all(request.as_bytes())?;

    let mut reader = BufReader::new(conn.try_clone()?);
    let mut status = String::new();
    reader.read_line(&mut status)?;
    let mut parts = status.split_whitespace();
    let _http = parts.next();
    let code: i32 = parts
        .next()
        .and_then(|c| c.parse().ok())
        .ok_or_else(|| anyhow!("invalid HTTP response: {status}"))?;
    if code != 200 {
        bail!("HTTP CONNECT failed with status {code}");
    }
    loop {
        let mut line = String::new();
        let n = reader.read_line(&mut line)?;
        if n == 0 || line == "\r\n" || line == "\n" {
            break;
        }
    }
    Ok(())
}

/// Удобный трейт: разрешить первый адрес из "host:port".
trait ToSocketAddrFirst {
    fn to_socket_addrs_first(&self) -> Option<SocketAddr>;
}

impl ToSocketAddrFirst for String {
    fn to_socket_addrs_first(&self) -> Option<SocketAddr> {
        use std::net::ToSocketAddrs;
        self.to_socket_addrs().ok().and_then(|mut it| it.next())
    }
}
