//! Мелкие утилиты: время, генерация уникального id соединения, резолвинг адресов.

use anyhow::{anyhow, Result};
use rand::RngCore;
use std::net::{Ipv4Addr, ToSocketAddrs};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Адаптивная пауза для циклов опроса: при активности — минимальная задержка,
/// на простое растёт до максимума (аналог adaptiveLoopWait в оригинале).
/// Снижает загрузку CPU при большом числе одновременных соединений.
pub struct Backoff {
    min: Duration,
    max: Duration,
    cur: Duration,
}

impl Backoff {
    pub fn new(min_ms: u64, max_ms: u64) -> Backoff {
        let min = Duration::from_millis(min_ms.max(1));
        Backoff {
            min,
            max: Duration::from_millis(max_ms).max(min),
            cur: min,
        }
    }

    /// Сбросить к минимуму (вызывать при наличии работы).
    pub fn reset(&mut self) {
        self.cur = self.min;
    }

    /// Поспать текущую паузу и увеличить её вдвое (до максимума).
    pub fn step(&mut self) {
        std::thread::sleep(self.cur);
        self.cur = (self.cur * 2).min(self.max);
    }
}

pub fn now_ns() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as i64)
        .unwrap_or(0)
}

/// Уникальный идентификатор соединения (32 hex-символа).
pub fn unique_id() -> String {
    let mut b = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut b);
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

/// Потокобезопасные счётчики трафика для периодической статистики.
#[derive(Default)]
pub struct Counters {
    pub send_packet: AtomicU64,
    pub recv_packet: AtomicU64,
    pub send_size: AtomicU64,
    pub recv_size: AtomicU64,
}

impl Counters {
    pub fn add_send(&self, size: usize) {
        self.send_packet.fetch_add(1, Ordering::Relaxed);
        self.send_size.fetch_add(size as u64, Ordering::Relaxed);
    }
    pub fn add_recv(&self, size: usize) {
        self.recv_packet.fetch_add(1, Ordering::Relaxed);
        self.recv_size.fetch_add(size as u64, Ordering::Relaxed);
    }
    /// Возвращает (sendPkt, sendKB, recvPkt, recvKB) и обнуляет счётчики.
    pub fn take(&self) -> (u64, u64, u64, u64) {
        let sp = self.send_packet.swap(0, Ordering::Relaxed);
        let ss = self.send_size.swap(0, Ordering::Relaxed);
        let rp = self.recv_packet.swap(0, Ordering::Relaxed);
        let rs = self.recv_size.swap(0, Ordering::Relaxed);
        (sp, ss / 1024, rp, rs / 1024)
    }
}
