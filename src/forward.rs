//! Форвардинг исходящих TCP-соединений сервера через прокси (socks5 / http CONNECT).
//! Async-версия на tokio. UDP-через-прокси в этой итерации не поддержан.

use crate::socks5;
use anyhow::{anyhow, bail, Result};
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::time::timeout;

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

/// Устанавливает TCP-соединение к target через прокси.
pub async fn dial_through_proxy(
    config: &ForwardConfig,
    target: &str,
    to: Duration,
) -> Result<TcpStream> {
    let mut conn = timeout(to, TcpStream::connect(config.address()))
        .await
        .map_err(|_| anyhow!("proxy connect timeout"))??;
    match config.scheme.as_str() {
        "socks5" => timeout(to, socks5_connect(&mut conn, target))
            .await
            .map_err(|_| anyhow!("socks5 handshake timeout"))??,
        "http" => timeout(to, http_connect(&mut conn, target))
            .await
            .map_err(|_| anyhow!("http connect timeout"))??,
        other => bail!("unsupported proxy scheme: {other}"),
    }
    Ok(conn)
}

async fn socks5_connect(conn: &mut TcpStream, target: &str) -> Result<()> {
    conn.write_all(&[socks5::SOCKS5_VERSION, 0x01, 0x00]).await?;
    let mut resp = [0u8; 2];
    conn.read_exact(&mut resp).await?;
    if resp[0] != socks5::SOCKS5_VERSION {
        bail!("unexpected SOCKS version: {}", resp[0]);
    }
    if resp[1] != 0x00 {
        bail!("SOCKS5 proxy auth not supported (method {})", resp[1]);
    }
    let encoded = socks5::encode_address(target)?;
    let mut req = Vec::with_capacity(3 + encoded.len());
    req.extend_from_slice(&[socks5::SOCKS5_VERSION, socks5::CMD_CONNECT, 0x00]);
    req.extend_from_slice(&encoded);
    conn.write_all(&req).await?;

    let mut header = [0u8; 4];
    conn.read_exact(&mut header).await?;
    if header[1] != socks5::REPLY_SUCCEEDED {
        bail!("SOCKS5 connect failed code {}", header[1]);
    }
    // Дочитываем BND.ADDR/BND.PORT по типу адреса.
    let skip = match header[3] {
        socks5::ATYP_IPV4 => 4 + 2,
        socks5::ATYP_IPV6 => 16 + 2,
        socks5::ATYP_DOMAIN => {
            let mut l = [0u8; 1];
            conn.read_exact(&mut l).await?;
            l[0] as usize + 2
        }
        other => bail!("unexpected atyp {other}"),
    };
    let mut rest = vec![0u8; skip];
    conn.read_exact(&mut rest).await?;
    Ok(())
}

async fn http_connect(conn: &mut TcpStream, target: &str) -> Result<()> {
    let req = format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n");
    conn.write_all(req.as_bytes()).await?;
    let mut reader = BufReader::new(conn);
    let mut status = String::new();
    reader.read_line(&mut status).await?;
    let code: i32 = status
        .split_whitespace()
        .nth(1)
        .and_then(|c| c.parse().ok())
        .ok_or_else(|| anyhow!("invalid HTTP response: {status}"))?;
    if code != 200 {
        bail!("HTTP CONNECT failed status {code}");
    }
    loop {
        let mut line = String::new();
        let n = reader.read_line(&mut line).await?;
        if n == 0 || line == "\r\n" || line == "\n" {
            break;
        }
    }
    Ok(())
}
