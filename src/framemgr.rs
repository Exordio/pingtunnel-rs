//! Порт gohome/network.FrameMgr — надёжный транспорт поверх ненадёжного
//! ICMP-канала. Реализует скользящее окно, повторную отправку по таймауту и
//! по запросу (REQ), кумулятивные ACK, ping/pong для RTT, heartbeat и
//! опциональное zlib-сжатие фреймов. Используется только в TCP-режиме.
//!
//! Алгоритм и порядок вызовов в `update()` повторяют оригинал, чтобы
//! сохранить совместимость с Go-версией на уровне протокола фреймов.

use crate::proto::*;
use crate::ring::{ROBuffer, RBuffer};
use flate2::read::ZlibDecoder;
use flate2::write::ZlibEncoder;
use flate2::Compression;
use prost::Message;
use std::collections::HashMap;
use std::io::{Read, Write};
use std::time::{SystemTime, UNIX_EPOCH};

const MS: i64 = 1_000_000; // наносекунд в миллисекунде
const SECOND: i64 = 1_000_000_000;

fn now_ns() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as i64)
        .unwrap_or(0)
}

/// Сериализует фрейм в protobuf (совместимо с FrameMgr.MarshalFrame).
pub fn marshal_frame(f: &Frame) -> Vec<u8> {
    let mut buf = Vec::with_capacity(f.encoded_len());
    f.encode(&mut buf).expect("encode frame");
    buf
}

pub struct FrameMgr {
    frame_max_size: usize,
    frame_max_id: i64,

    sendb: RBuffer,
    recvb: RBuffer,

    windowsize: i64,
    resend_timems: i64,
    compress: usize,

    sendwin: ROBuffer,
    sendlist: Vec<Frame>,
    sendid: i64,

    recvwin: ROBuffer,
    recvlist: Vec<Frame>,
    recvid: i64,

    close: bool,
    remoteclosed: bool,
    closesend: bool,

    last_ping_time: i64,
    rttns: i64,

    last_send_hb_time: i64,
    last_recv_hb_time: i64,
    last_recv_data_time: i64,

    reqmap: HashMap<i64, i64>,
    connected: bool,
}

impl FrameMgr {
    pub fn new(
        frame_max_size: usize,
        frame_max_id: i64,
        buffersize: usize,
        windowsize: i64,
        resend_timems: i64,
        compress: usize,
    ) -> FrameMgr {
        let now = now_ns();
        FrameMgr {
            frame_max_size,
            frame_max_id,
            sendb: RBuffer::new(buffersize),
            recvb: RBuffer::new(buffersize),
            windowsize,
            resend_timems,
            compress,
            sendwin: ROBuffer::new(windowsize as usize, 0, frame_max_id),
            sendlist: Vec::new(),
            sendid: 0,
            recvwin: ROBuffer::new(windowsize as usize, 0, frame_max_id),
            recvlist: Vec::new(),
            recvid: 0,
            close: false,
            remoteclosed: false,
            closesend: false,
            last_ping_time: now,
            rttns: resend_timems * 1000,
            last_send_hb_time: now,
            last_recv_hb_time: now,
            last_recv_data_time: now,
            reqmap: HashMap::new(),
            connected: false,
        }
    }

    // ── Внешний интерфейс, используемый клиентом/сервером ────────────────

    pub fn get_send_buffer_left(&self) -> usize {
        self.sendb.capacity() - self.sendb.size()
    }

    pub fn write_send_buffer(&mut self, data: &[u8]) {
        self.sendb.write(data);
    }

    pub fn get_recv_buffer_size(&self) -> usize {
        self.recvb.size()
    }

    pub fn get_recv_read_line_buffer(&self) -> Vec<u8> {
        self.recvb.read_line_buffer()
    }

    pub fn skip_recv_buffer(&mut self, size: usize) {
        self.recvb.skip_read(size);
    }

    pub fn close(&mut self) {
        self.close = true;
    }

    pub fn is_remote_closed(&self) -> bool {
        self.remoteclosed
    }

    pub fn is_connected(&self) -> bool {
        self.connected
    }

    /// Забирает накопленный список фреймов на отправку (очищает sendlist).
    pub fn take_send_list(&mut self) -> Vec<Frame> {
        std::mem::take(&mut self.sendlist)
    }

    /// Принимает входящий фрейм (кладёт в очередь на обработку в update()).
    pub fn on_recv_frame(&mut self, f: Frame) {
        self.recvlist.push(f);
    }

    /// Инициирует соединение (фрейм CONN). Вызывается клиентом.
    pub fn connect(&mut self) {
        if self.sendwin.size() < self.windowsize as usize {
            let f = self.make_data_frame(FD_CONN, Vec::new(), false);
            let _ = self.sendwin.set(f.id as i64, f);
        }
    }

    // ── Главный тик ──────────────────────────────────────────────────────

    pub fn update(&mut self) -> bool {
        let cur = now_ns();
        self.cut_send_buffer_to_window();
        let active = self.process_recv_list();
        self.combine_window_to_recv_buffer(cur);
        self.cal_send_list(cur);
        self.ping(cur);
        self.hb(cur);
        active
    }

    /// Есть ли незавершённая работа: кадры в полёте (ждут ACK), данные в буферах
    /// отправки/приёма или дырки в окне приёма. Цикл соединения использует это,
    /// чтобы выбрать частоту тика: мелкий тик при работе, крупный — на простое
    /// (соединение всё равно просыпается на входящих фреймах/локальных данных
    /// немедленно, тик нужен лишь для таймеров resend/ping/hb).
    pub fn has_pending_work(&self) -> bool {
        self.sendwin.size() > 0
            || self.recvwin.size() > 0
            || self.sendb.size() > 0
            || self.recvb.size() > 0
    }

    // ── Отправка ───────────────────────────────────────────────────────

    fn next_sendid(&mut self) -> i64 {
        let id = self.sendid;
        self.sendid += 1;
        if self.sendid >= self.frame_max_id {
            self.sendid = 0;
        }
        id
    }

    fn make_data_frame(&mut self, fd_type: i32, data: Vec<u8>, compress: bool) -> Frame {
        let id = self.next_sendid();
        Frame {
            r#type: FRAME_DATA,
            resend: false,
            sendtime: 0,
            id: id as i32,
            data: Some(FrameData {
                r#type: fd_type,
                data,
                compress,
            }),
            dataid: Vec::new(),
            acked: false,
        }
    }

    fn cut_send_buffer_to_window(&mut self) {
        let sendall = self.sendb.size() < self.frame_max_size;

        while self.sendb.size() >= self.frame_max_size
            && self.sendwin.size() < self.windowsize as usize
        {
            let mut data = vec![0u8; self.frame_max_size];
            self.sendb.read(&mut data);
            let (data, compress) = self.maybe_compress(data);
            let f = self.make_data_frame(FD_USER_DATA, data, compress);
            let _ = self.sendwin.set(f.id as i64, f);
        }

        if sendall && self.sendb.size() > 0 && self.sendwin.size() < self.windowsize as usize {
            let mut data = vec![0u8; self.sendb.size()];
            self.sendb.read(&mut data);
            let (data, compress) = self.maybe_compress(data);
            let f = self.make_data_frame(FD_USER_DATA, data, compress);
            let _ = self.sendwin.set(f.id as i64, f);
        }

        if self.sendb.empty()
            && self.close
            && !self.closesend
            && self.sendwin.size() < self.windowsize as usize
        {
            let f = self.make_data_frame(FD_CLOSE, Vec::new(), false);
            let _ = self.sendwin.set(f.id as i64, f);
            self.closesend = true;
        }
    }

    fn maybe_compress(&self, data: Vec<u8>) -> (Vec<u8>, bool) {
        if self.compress > 0 && data.len() > self.compress {
            let mut enc = ZlibEncoder::new(Vec::new(), Compression::default());
            if enc.write_all(&data).is_ok() {
                if let Ok(compressed) = enc.finish() {
                    if compressed.len() < data.len() {
                        return (compressed, true);
                    }
                }
            }
        }
        (data, false)
    }

    fn cal_send_list(&mut self, cur: i64) {
        let resend_ns = self.resend_timems * MS;
        let rttns = self.rttns;
        let sendlist = &mut self.sendlist;
        self.sendwin.for_each_from_front(|f| {
            if !f.acked
                && (f.resend || cur - f.sendtime > resend_ns)
                && cur - f.sendtime > rttns
            {
                f.sendtime = cur;
                let mut clone = f.clone();
                clone.resend = false;
                sendlist.push(clone);
                f.resend = false;
            }
        });
    }

    fn ping(&mut self, cur: i64) {
        if cur - self.last_ping_time > SECOND {
            self.last_ping_time = cur;
            self.sendlist.push(Frame {
                r#type: FRAME_PING,
                resend: false,
                sendtime: cur,
                id: 0,
                data: None,
                dataid: Vec::new(),
                acked: false,
            });
        }
    }

    fn hb(&mut self, cur: i64) {
        if cur - self.last_send_hb_time > SECOND && self.sendwin.size() < self.windowsize as usize {
            self.last_send_hb_time = cur;
            let f = self.make_data_frame(FD_HB, Vec::new(), false);
            let _ = self.sendwin.set(f.id as i64, f);
        }
    }

    fn send_connect_rsp(&mut self) {
        if self.sendwin.size() < self.windowsize as usize {
            let f = self.make_data_frame(FD_CONNRSP, Vec::new(), false);
            let _ = self.sendwin.set(f.id as i64, f);
        }
    }

    // ── Приём ────────────────────────────────────────────────────────────

    /// Разбирает recvlist на REQ/ACK/DATA/PING/PONG и обрабатывает их.
    /// Возвращает true, если была какая-либо активность.
    fn process_recv_list(&mut self) -> bool {
        // Нет входящих фреймов — на простое не аллоцируем временные коллекции.
        // ACKed-фронт уже выгребается до конца в каждом вызове, так что без
        // новых фреймов делать нечего.
        if self.recvlist.is_empty() {
            return false;
        }
        let recvlist = std::mem::take(&mut self.recvlist);
        let mut tmpreq: Vec<i64> = Vec::new();
        let mut tmpack: Vec<i64> = Vec::new();
        let mut tmpackto: HashMap<i64, Frame> = HashMap::new();

        for f in recvlist {
            match f.r#type {
                x if x == FRAME_REQ => tmpreq.extend(f.dataid.iter().map(|&i| i as i64)),
                x if x == FRAME_ACK => tmpack.extend(f.dataid.iter().map(|&i| i as i64)),
                x if x == FRAME_DATA => {
                    tmpackto.insert(f.id as i64, f);
                }
                x if x == FRAME_PING => self.process_ping(&f),
                x if x == FRAME_PONG => self.process_pong(&f),
                _ => {}
            }
        }

        let active = tmpreq.len() + tmpack.len() + tmpackto.len();

        for id in &tmpreq {
            self.sendwin.mark_resend(*id);
        }
        for id in &tmpack {
            self.sendwin.mark_acked(*id);
        }
        while self.sendwin.front_acked() {
            self.sendwin.pop_front();
        }

        if !tmpackto.is_empty() {
            let tmpsize = std::cmp::min(tmpackto.len(), self.frame_max_size / 2 / 4);
            let mut acks: Vec<i32> = Vec::new();
            for (id, rf) in tmpackto {
                if self.add_to_recv_win(rf) {
                    acks.push(id as i32);
                    if acks.len() >= tmpsize {
                        self.push_ack(std::mem::take(&mut acks));
                    }
                }
            }
            if !acks.is_empty() {
                self.push_ack(acks);
            }
        }

        active > 0
    }

    fn push_ack(&mut self, dataid: Vec<i32>) {
        self.sendlist.push(Frame {
            r#type: FRAME_ACK,
            resend: false,
            sendtime: 0,
            id: 0,
            data: None,
            dataid,
            acked: false,
        });
    }

    fn process_ping(&mut self, f: &Frame) {
        self.sendlist.push(Frame {
            r#type: FRAME_PONG,
            resend: false,
            sendtime: f.sendtime,
            id: 0,
            data: None,
            dataid: Vec::new(),
            acked: false,
        });
    }

    fn process_pong(&mut self, f: &Frame) {
        let cur = now_ns();
        if cur > f.sendtime {
            let rtt = cur - f.sendtime;
            self.rttns = (self.rttns + rtt) / 2;
        }
    }

    fn add_to_recv_win(&mut self, rf: Frame) -> bool {
        if !self.is_id_in_range(rf.id as i64) {
            if self.is_id_old(rf.id as i64) {
                return true;
            }
            return false;
        }
        let id = rf.id as i64;
        self.recvwin.set(id, rf).is_ok()
    }

    fn combine_window_to_recv_buffer(&mut self, cur: i64) {
        // Окно приёма пусто — нечего собирать и не из чего строить REQ; на
        // простое не аллоцируем occupied/reqtmp.
        if self.recvwin.size() == 0 {
            return;
        }
        loop {
            let mut done = false;
            if let Some(fid) = self.recvwin.front_id() {
                if fid == self.recvid {
                    self.reqmap.remove(&fid);
                    if let Some(f) = self.recvwin.front_clone() {
                        if self.process_recv_frame(&f) {
                            self.recvwin.pop_front();
                            done = true;
                        }
                    }
                }
            }
            if !done {
                break;
            }
            self.recvid += 1;
            if self.recvid >= self.frame_max_id {
                self.recvid = 0;
            }
        }

        // Построение REQ для пропущенных id в окне приёма.
        let occupied = self.recvwin.occupied_ids_from_front();
        let mut reqtmp: Vec<i32> = Vec::new();
        let mut e_idx = 0usize;
        let mut id = self.recvid;
        let limit_count = self.windowsize as usize;
        let limit_size = self.frame_max_size / 2;
        while reqtmp.len() < limit_count && reqtmp.len() * 4 < limit_size && e_idx < occupied.len() {
            let fid = occupied[e_idx];
            if fid != id {
                let old = *self.reqmap.get(&fid).unwrap_or(&0);
                if cur - old > self.rttns {
                    reqtmp.push(id as i32);
                    self.reqmap.insert(fid, cur);
                }
            } else {
                e_idx += 1;
            }
            id += 1;
            if id >= self.frame_max_id {
                id = 0;
            }
        }

        if !reqtmp.is_empty() {
            self.sendlist.push(Frame {
                r#type: FRAME_REQ,
                resend: false,
                sendtime: 0,
                id: 0,
                data: None,
                dataid: reqtmp,
                acked: false,
            });
        }
    }

    fn process_recv_frame(&mut self, f: &Frame) -> bool {
        let fd = match &f.data {
            Some(d) => d,
            None => return false,
        };
        match fd.r#type {
            x if x == FD_USER_DATA => {
                let left = self.recvb.capacity() - self.recvb.size();
                let mut src: Vec<u8> = fd.data.clone();
                if left < src.len() {
                    return false;
                }
                if fd.compress {
                    let mut dec = ZlibDecoder::new(&fd.data[..]);
                    let mut old = Vec::new();
                    if dec.read_to_end(&mut old).is_err() {
                        return false;
                    }
                    if left < old.len() {
                        return false;
                    }
                    src = old;
                }
                self.last_recv_data_time = now_ns();
                self.recvb.write(&src);
                true
            }
            x if x == FD_CLOSE => {
                self.remoteclosed = true;
                true
            }
            x if x == FD_CONN => {
                self.send_connect_rsp();
                self.connected = true;
                true
            }
            x if x == FD_CONNRSP => {
                self.connected = true;
                true
            }
            x if x == FD_HB => {
                self.last_recv_hb_time = now_ns();
                true
            }
            _ => false,
        }
    }

    // ── Управление кольцом id ─────────────────────────────────────────────

    fn is_id_in_range(&self, id: i64) -> bool {
        let maxid = self.frame_max_id;
        let begin = self.recvid;
        let mut end = self.recvid + self.windowsize;
        if end >= maxid {
            if id >= 0 && id < end - maxid {
                return true;
            }
            end = maxid;
        }
        id >= begin && id < end
    }

    fn is_id_old(&self, id: i64) -> bool {
        let maxid = self.frame_max_id;
        let mut begin = self.recvid - self.windowsize;
        if begin < 0 {
            begin += maxid;
        }
        let end = self.recvid;
        if begin < end {
            id >= begin && id < end
        } else {
            (id >= begin && id < maxid) || (id >= 0 && id < end)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mk() -> FrameMgr {
        FrameMgr::new(FRAME_MAX_SIZE, FRAME_MAX_ID as i64, 1 << 20, 2000, 400, 0)
    }

    // Переносит фреймы из from в to (надёжная доставка, без потерь).
    fn step(from: &mut FrameMgr, to: &mut FrameMgr) {
        from.update();
        for f in from.take_send_list() {
            to.on_recv_frame(f);
        }
    }

    fn pump(a: &mut FrameMgr, b: &mut FrameMgr, n: usize) {
        for _ in 0..n {
            step(a, b);
            step(b, a);
        }
    }

    #[test]
    fn handshake() {
        let mut client = mk();
        let mut server = mk();
        client.connect();
        for _ in 0..100 {
            step(&mut client, &mut server);
            step(&mut server, &mut client);
            if client.is_connected() && server.is_connected() {
                break;
            }
        }
        assert!(client.is_connected(), "client must be connected");
        assert!(server.is_connected(), "server must be connected");
    }

    #[test]
    fn reliable_stream_both_ways() {
        let mut client = mk();
        let mut server = mk();
        client.connect();
        pump(&mut client, &mut server, 50);
        assert!(client.is_connected() && server.is_connected());

        // Многокадровая полезная нагрузка (> FRAME_MAX_SIZE).
        let payload: Vec<u8> = (0..5000u32).map(|i| (i % 251) as u8).collect();
        client.write_send_buffer(&payload);

        let mut got = Vec::new();
        for _ in 0..20000 {
            step(&mut client, &mut server);
            step(&mut server, &mut client);
            let n = server.get_recv_buffer_size();
            if n > 0 {
                let b = server.get_recv_read_line_buffer();
                let l = b.len();
                got.extend_from_slice(&b);
                server.skip_recv_buffer(l);
            }
            if got.len() >= payload.len() {
                break;
            }
        }
        assert_eq!(got, payload, "data must arrive intact and ordered");
    }

    #[test]
    fn reliable_stream_with_loss() {
        // Имитируем потери: каждый 3-й DATA-фрейм отбрасывается. Ретрансмиссия
        // гейтится по реальному времени (resend_timems/rttns), поэтому цикл
        // продвигает реальное время короткими паузами, как в боевом коде.
        let resend = 10; // мс
        let mut client = FrameMgr::new(FRAME_MAX_SIZE, FRAME_MAX_ID as i64, 1 << 20, 2000, resend, 0);
        let mut server = FrameMgr::new(FRAME_MAX_SIZE, FRAME_MAX_ID as i64, 1 << 20, 2000, resend, 0);
        client.connect();
        for _ in 0..50 {
            step(&mut client, &mut server);
            step(&mut server, &mut client);
            std::thread::sleep(std::time::Duration::from_millis(1));
            if client.is_connected() && server.is_connected() {
                break;
            }
        }

        let payload: Vec<u8> = (0..4000u32).map(|i| (i * 7 % 253) as u8).collect();
        client.write_send_buffer(&payload);

        let mut drop_counter = 0usize;
        let mut got = Vec::new();
        for _ in 0..2000 {
            client.update();
            for f in client.take_send_list() {
                if f.r#type == FRAME_DATA {
                    drop_counter += 1;
                    if drop_counter % 3 == 0 {
                        continue; // потеря
                    }
                }
                server.on_recv_frame(f);
            }
            server.update();
            for f in server.take_send_list() {
                client.on_recv_frame(f);
            }
            let n = server.get_recv_buffer_size();
            if n > 0 {
                let b = server.get_recv_read_line_buffer();
                let l = b.len();
                got.extend_from_slice(&b);
                server.skip_recv_buffer(l);
            }
            if got.len() >= payload.len() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(2));
        }
        assert_eq!(got, payload, "ретрансмиссия должна восстановить потерянные фреймы");
    }

    #[test]
    fn compression_roundtrip() {
        let mut client = FrameMgr::new(FRAME_MAX_SIZE, FRAME_MAX_ID as i64, 1 << 20, 2000, 400, 10);
        let mut server = mk();
        client.connect();
        pump(&mut client, &mut server, 50);

        let payload = vec![42u8; 5000]; // хорошо сжимается
        client.write_send_buffer(&payload);

        let mut got = Vec::new();
        for _ in 0..20000 {
            step(&mut client, &mut server);
            step(&mut server, &mut client);
            let n = server.get_recv_buffer_size();
            if n > 0 {
                let b = server.get_recv_read_line_buffer();
                let l = b.len();
                got.extend_from_slice(&b);
                server.skip_recv_buffer(l);
            }
            if got.len() >= payload.len() {
                break;
            }
        }
        assert_eq!(got, payload);
    }
}
