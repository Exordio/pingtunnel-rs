//! Общие метрики для периодической статистики и интерактивного TUI
//! (см. [`crate::tui`], флаг `--interactive`).
//!
//! [`Stats`] держит кумулятивные счётчики трафика (не обнуляются) и реестр
//! активных соединений с метаданными (тип, цель, IP-протокол транспорта, объём в
//! каждую сторону). Кумулятивная модель позволяет нескольким независимым
//! потребителям (лог раз в секунду и TUI на своём такте) считать дельты, не мешая
//! друг другу: каждый хранит свой предыдущий снимок.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

/// Тип соединения для отображения в списке.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ConnKind {
    /// TCP-проброс (`-tcp 1`) или SOCKS5 CONNECT.
    Tcp,
    /// Простой UDP-проброс без гарантий доставки.
    Udp,
    /// Надёжный UDP (датаграммы через FrameMgr, `--udp_rel 1`).
    UdpReliable,
}

impl ConnKind {
    pub fn as_str(self) -> &'static str {
        match self {
            ConnKind::Tcp => "TCP",
            ConnKind::Udp => "UDP",
            ConnKind::UdpReliable => "UDP-REL",
        }
    }
}

/// Имя IP-протокола транспорта по номеру: 1 = ICMP, прочее - `ip/<n>`
/// (кастомный протокол или номер из ротации).
pub fn proto_name(proto: u8) -> String {
    if proto == 1 {
        "ICMP".to_string()
    } else {
        format!("ip/{proto}")
    }
}

/// Метаданные и счётчики одного активного соединения. Живёт за [`Arc`]: одна
/// копия в реестре [`Stats`], вторая - у владеющей задачи, которая инкрементит
/// `send_bytes`/`recv_bytes` без обращения к карте.
pub struct ConnInfo {
    pub kind: ConnKind,
    pub target: String,
    /// IP-протокол транспорта этого соединения (1 = ICMP, либо номер из ротации).
    pub proto: u8,
    pub opened: Instant,
    pub send_bytes: AtomicU64,
    pub recv_bytes: AtomicU64,
}

impl ConnInfo {
    pub fn add_send(&self, n: usize) {
        self.send_bytes.fetch_add(n as u64, Ordering::Relaxed);
    }
    pub fn add_recv(&self, n: usize) {
        self.recv_bytes.fetch_add(n as u64, Ordering::Relaxed);
    }
}

/// Снимок кумулятивных счётчиков для расчёта дельт.
#[derive(Clone, Copy, Default)]
pub struct Snapshot {
    pub send_packet: u64,
    pub recv_packet: u64,
    pub send_size: u64,
    pub recv_size: u64,
}

/// Строка для TUI: владеющая копия данных соединения на момент снимка.
pub struct ConnRow {
    pub id: String,
    pub kind: ConnKind,
    pub target: String,
    pub proto: u8,
    pub age_secs: u64,
    pub send_bytes: u64,
    pub recv_bytes: u64,
}

/// Потокобезопасные метрики: кумулятивный трафик + реестр соединений.
pub struct Stats {
    send_packet: AtomicU64,
    recv_packet: AtomicU64,
    send_size: AtomicU64,
    recv_size: AtomicU64,
    /// Предыдущий снимок для [`Stats::take`] (потребитель - лог-строка).
    log_last: Mutex<Snapshot>,
    conns: Mutex<HashMap<String, Arc<ConnInfo>>>,
}

impl Default for Stats {
    fn default() -> Self {
        Stats {
            send_packet: AtomicU64::new(0),
            recv_packet: AtomicU64::new(0),
            send_size: AtomicU64::new(0),
            recv_size: AtomicU64::new(0),
            log_last: Mutex::new(Snapshot::default()),
            conns: Mutex::new(HashMap::new()),
        }
    }
}

impl Stats {
    pub fn add_send(&self, size: usize) {
        self.send_packet.fetch_add(1, Ordering::Relaxed);
        self.send_size.fetch_add(size as u64, Ordering::Relaxed);
    }
    pub fn add_recv(&self, size: usize) {
        self.recv_packet.fetch_add(1, Ordering::Relaxed);
        self.recv_size.fetch_add(size as u64, Ordering::Relaxed);
    }

    /// Текущий кумулятивный снимок (не обнуляет счётчики).
    pub fn snapshot(&self) -> Snapshot {
        Snapshot {
            send_packet: self.send_packet.load(Ordering::Relaxed),
            recv_packet: self.recv_packet.load(Ordering::Relaxed),
            send_size: self.send_size.load(Ordering::Relaxed),
            recv_size: self.recv_size.load(Ordering::Relaxed),
        }
    }

    /// Возвращает (sendPkt, sendKB, recvPkt, recvKB) с момента прошлого вызова.
    /// При вызове раз в секунду это и есть скорости в секунду (как было раньше),
    /// но счётчики теперь кумулятивны и не сбрасываются для других потребителей.
    pub fn take(&self) -> (u64, u64, u64, u64) {
        let s = self.snapshot();
        let mut last = self.log_last.lock().unwrap();
        let d_sp = s.send_packet.wrapping_sub(last.send_packet);
        let d_ss = s.send_size.wrapping_sub(last.send_size);
        let d_rp = s.recv_packet.wrapping_sub(last.recv_packet);
        let d_rs = s.recv_size.wrapping_sub(last.recv_size);
        *last = s;
        (d_sp, d_ss / 1024, d_rp, d_rs / 1024)
    }

    /// Регистрирует новое соединение и возвращает его [`ConnInfo`] для прямого
    /// учёта байтов владеющей задачей.
    pub fn register(&self, id: String, kind: ConnKind, target: String, proto: u8) -> Arc<ConnInfo> {
        let info = Arc::new(ConnInfo {
            kind,
            target,
            proto,
            opened: Instant::now(),
            send_bytes: AtomicU64::new(0),
            recv_bytes: AtomicU64::new(0),
        });
        self.conns.lock().unwrap().insert(id, info.clone());
        info
    }

    pub fn unregister(&self, id: &str) {
        self.conns.lock().unwrap().remove(id);
    }

    /// Снимок всех соединений (владеющие копии) для отрисовки в TUI.
    pub fn conns_snapshot(&self) -> Vec<ConnRow> {
        let map = self.conns.lock().unwrap();
        map.iter()
            .map(|(id, info)| ConnRow {
                id: id.clone(),
                kind: info.kind,
                target: info.target.clone(),
                proto: info.proto,
                age_secs: info.opened.elapsed().as_secs(),
                send_bytes: info.send_bytes.load(Ordering::Relaxed),
                recv_bytes: info.recv_bytes.load(Ordering::Relaxed),
            })
            .collect()
    }
}
