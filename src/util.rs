//! Мелкие утилиты: время, генерация уникального id соединения, резолвинг адресов.

use anyhow::{anyhow, Result};
use rand::Rng;
use std::net::{Ipv4Addr, ToSocketAddrs};
use std::time::{SystemTime, UNIX_EPOCH};

pub fn now_ns() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as i64)
        .unwrap_or(0)
}

/// Уникальный идентификатор соединения (32 hex-символа).
pub fn unique_id() -> String {
    let mut b = [0u8; 16];
    rand::rng().fill_bytes(&mut b);
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Резолвит host (или host:port-подобную строку без порта) в первый IPv4-адрес.
pub fn resolve_ipv4(host: &str) -> Result<Ipv4Addr> {
    if let Ok(ip) = host.parse::<Ipv4Addr>() {
        return Ok(ip);
    }
    let iter = (host, 0u16)
        .to_socket_addrs()
        .map_err(|e| anyhow!("resolve {host}: {e}"))?;
    for sa in iter {
        if let std::net::IpAddr::V4(v4) = sa.ip() {
            return Ok(v4);
        }
    }
    Err(anyhow!("no IPv4 address for {host}"))
}
