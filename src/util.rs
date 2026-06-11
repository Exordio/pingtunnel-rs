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
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut b = [0u8; 16];
    rand::rng().fill_bytes(&mut b);
    // Один буфер на 32 символа вместо format! на каждый байт (16 аллокаций).
    let mut s = String::with_capacity(32);
    for x in b {
        s.push(HEX[(x >> 4) as usize] as char);
        s.push(HEX[(x & 0x0f) as usize] as char);
    }
    s
}

/// Возвращает ОС свободную память кучи. Надёжные соединения держат крупные
/// буферы (RBuffer по `tcp_bs` в каждую сторону + окна фреймов); при пике из
/// сотен соединений RSS вырастает до сотен МБ. После их закрытия буферы
/// освобождаются, но glibc malloc держит освобождённые страницы в своих аренах
/// (по одной на worker-поток) и не отдаёт их ядру сам - RSS застывает на
/// high-water mark. `malloc_trim(0)` обходит все арены и возвращает свободные
/// страницы ОС. Вызывается периодически из maintenance. Вне glibc - no-op.
pub fn trim_memory() {
    #[cfg(target_env = "gnu")]
    unsafe {
        libc::malloc_trim(0);
    }
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
