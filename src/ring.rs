//! Кольцевые буферы, портированные из gohome/list:
//! - `RBuffer`  — байтовый кольцевой буфер (RBuffergo, без внутренней блокировки);
//! - `ROBuffer` — кольцевой буфер фреймов с адресацией по id (ROBuffergo).
//!
//! FrameMgr целиком защищён внешним Mutex, поэтому внутренние блокировки не нужны.

use crate::proto::Frame;

/// Байтовый кольцевой буфер фиксированной ёмкости.
pub struct RBuffer {
    buffer: Vec<u8>,
    datasize: usize,
    begin: usize,
    end: usize,
}

impl RBuffer {
    pub fn new(cap: usize) -> RBuffer {
        RBuffer {
            buffer: vec![0u8; cap],
            datasize: 0,
            begin: 0,
            end: 0,
        }
    }

    pub fn capacity(&self) -> usize {
        self.buffer.len()
    }

    pub fn size(&self) -> usize {
        self.datasize
    }

    pub fn empty(&self) -> bool {
        self.datasize == 0
    }

    /// Записывает данные, если они помещаются. Возвращает false при переполнении.
    pub fn write(&mut self, data: &[u8]) -> bool {
        let cap = self.buffer.len();
        if self.datasize + data.len() > cap {
            return false;
        }
        if self.end >= self.begin {
            if cap - self.end >= data.len() {
                self.buffer[self.end..self.end + data.len()].copy_from_slice(data);
            } else {
                let first = cap - self.end;
                self.buffer[self.end..].copy_from_slice(&data[..first]);
                self.buffer[..data.len() - first].copy_from_slice(&data[first..]);
            }
        } else {
            self.buffer[self.end..self.end + data.len()].copy_from_slice(data);
        }
        self.datasize += data.len();
        self.end += data.len();
        if self.end >= cap {
            self.end -= cap;
        }
        true
    }

    /// Читает ровно `out.len()` байт, если они есть, продвигая указатель чтения.
    pub fn read(&mut self, out: &mut [u8]) -> bool {
        let cap = self.buffer.len();
        let outlen = out.len();
        if self.datasize < outlen {
            return false;
        }
        if self.begin >= self.end {
            if cap - self.begin >= outlen {
                out.copy_from_slice(&self.buffer[self.begin..self.begin + outlen]);
            } else {
                let first = cap - self.begin;
                out[..first].copy_from_slice(&self.buffer[self.begin..]);
                out[first..].copy_from_slice(&self.buffer[..outlen - first]);
            }
        } else {
            out.copy_from_slice(&self.buffer[self.begin..self.begin + outlen]);
        }
        self.datasize -= outlen;
        self.begin += outlen;
        if self.begin >= cap {
            self.begin -= cap;
        }
        if self.datasize == 0 {
            self.begin = 0;
            self.end = 0;
        }
        true
    }

    pub fn skip_read(&mut self, size: usize) {
        if self.datasize < size {
            return;
        }
        self.datasize -= size;
        self.begin += size;
        let cap = self.buffer.len();
        if self.begin >= cap {
            self.begin -= cap;
        }
        if self.datasize == 0 {
            self.begin = 0;
            self.end = 0;
        }
    }

    /// Возвращает непрерывный читаемый участок от текущего begin.
    pub fn read_line_buffer(&self) -> Vec<u8> {
        let cap = self.buffer.len();
        if self.datasize < cap - self.begin {
            self.buffer[self.begin..self.begin + self.datasize].to_vec()
        } else {
            self.buffer[self.begin..cap].to_vec()
        }
    }
}

/// Кольцевой буфер фреймов, адресуемых по id (по модулю maxid).
pub struct ROBuffer {
    buffer: Vec<Option<Frame>>,
    flag: Vec<bool>,
    id: Vec<i64>,
    len: usize,
    maxid: i64,
    begin: usize,
    size: usize,
}

impl ROBuffer {
    pub fn new(len: usize, startid: i64, maxid: i64) -> ROBuffer {
        let mut id = vec![0i64; len];
        for (i, slot) in id.iter_mut().enumerate() {
            *slot = startid + i as i64;
        }
        ROBuffer {
            buffer: (0..len).map(|_| None).collect(),
            flag: vec![false; len],
            id,
            len,
            maxid,
            begin: 0,
            size: 0,
        }
    }

    pub fn size(&self) -> usize {
        self.size
    }

    #[allow(dead_code)]
    pub fn empty(&self) -> bool {
        self.size == 0
    }

    fn index_of(&self, id: i64) -> Option<usize> {
        if self.begin >= self.flag.len() {
            return None;
        }
        let cur = self.id[self.begin];
        if id >= self.maxid {
            return None;
        }
        let index = if id < cur {
            (self.begin + (id + self.maxid - cur) as usize) % self.len
        } else {
            (self.begin + (id - cur) as usize) % self.len
        };
        if self.id[index] != id {
            return None;
        }
        Some(index)
    }

    /// Устанавливает фрейм по его id. Возвращает Err при выходе за окно.
    pub fn set(&mut self, id: i64, frame: Frame) -> Result<(), String> {
        let index = self
            .index_of(id)
            .ok_or_else(|| format!("set id error {id}"))?;
        self.buffer[index] = Some(frame);
        if !self.flag[index] {
            self.size += 1;
        }
        self.flag[index] = true;
        Ok(())
    }

    /// Помечает фрейм с данным id как Acked, если он присутствует.
    pub fn mark_acked(&mut self, id: i64) {
        if let Some(index) = self.index_of(id) {
            if self.flag[index] {
                if let Some(f) = self.buffer[index].as_mut() {
                    f.acked = true;
                }
            }
        }
    }

    /// Помечает фрейм с данным id для повторной отправки.
    pub fn mark_resend(&mut self, id: i64) {
        if let Some(index) = self.index_of(id) {
            if self.flag[index] {
                if let Some(f) = self.buffer[index].as_mut() {
                    f.resend = true;
                }
            }
        }
    }

    pub fn front_acked(&self) -> bool {
        self.begin < self.flag.len()
            && self.flag[self.begin]
            && self.buffer[self.begin].as_ref().map_or(false, |f| f.acked)
    }

    pub fn front_id(&self) -> Option<i64> {
        if self.begin < self.flag.len() && self.flag[self.begin] {
            self.buffer[self.begin].as_ref().map(|f| f.id as i64)
        } else {
            None
        }
    }

    /// Клонирует фронтовый фрейм (для передачи в обработку).
    pub fn front_clone(&self) -> Option<Frame> {
        if self.begin < self.flag.len() && self.flag[self.begin] {
            self.buffer[self.begin].clone()
        } else {
            None
        }
    }

    pub fn pop_front(&mut self) {
        if !self.flag[self.begin] {
            return;
        }
        let old = self.begin;
        self.begin += 1;
        if self.begin >= self.len {
            self.begin = 0;
        }
        let cur = self.id[self.begin];
        self.buffer[old] = None;
        self.flag[old] = false;
        let mut newid = cur + self.len as i64 - 1;
        if newid >= self.maxid {
            newid %= self.maxid;
        }
        self.id[old] = newid;
        self.size -= 1;
    }

    /// Итерация по занятым слотам, начиная с фронта. Возвращает (id, &mut Frame)
    /// и значение текущего поля resend/acked/sendtime через замыкание.
    pub fn for_each_from_front<F: FnMut(&mut Frame)>(&mut self, mut f: F) {
        if self.begin >= self.flag.len() || !self.flag[self.begin] {
            return;
        }
        let start = self.begin;
        let mut index = self.begin;
        loop {
            if self.flag[index] {
                if let Some(frame) = self.buffer[index].as_mut() {
                    f(frame);
                }
            }
            index += 1;
            if index >= self.len {
                index %= self.len;
            }
            if index == start {
                break;
            }
        }
    }

    #[cfg(test)]
    pub fn get(&self, id: i64) -> Option<&Frame> {
        self.index_of(id)
            .and_then(|i| if self.flag[i] { self.buffer[i].as_ref() } else { None })
    }

    /// Перечисляет id занятых слотов начиная с фронта (для построения REQ по дыркам).
    pub fn occupied_ids_from_front(&self) -> Vec<i64> {
        let mut out = Vec::new();
        if self.begin >= self.flag.len() || !self.flag[self.begin] {
            return out;
        }
        let start = self.begin;
        let mut index = self.begin;
        loop {
            if self.flag[index] {
                if let Some(frame) = self.buffer[index].as_ref() {
                    out.push(frame.id as i64);
                }
            }
            index += 1;
            if index >= self.len {
                index %= self.len;
            }
            if index == start {
                break;
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::{Frame, FRAME_DATA};

    #[test]
    fn rbuffer_write_read_wraparound() {
        let mut b = RBuffer::new(8);
        assert!(b.write(b"abcde"));
        let mut out = [0u8; 3];
        assert!(b.read(&mut out));
        assert_eq!(&out, b"abc");
        // Должно перенестись через край кольца.
        assert!(b.write(b"fghij"));
        let mut out2 = vec![0u8; b.size()];
        assert!(b.read(&mut out2));
        assert_eq!(&out2, b"defghij");
    }

    #[test]
    fn rbuffer_rejects_overflow() {
        let mut b = RBuffer::new(4);
        assert!(b.write(b"abcd"));
        assert!(!b.write(b"e"));
    }

    fn frame(id: i32) -> Frame {
        Frame {
            r#type: FRAME_DATA,
            id,
            ..Default::default()
        }
    }

    #[test]
    fn robuffer_set_get_pop() {
        let mut w = ROBuffer::new(8, 0, 1_000_000);
        w.set(0, frame(0)).unwrap();
        w.set(1, frame(1)).unwrap();
        w.set(2, frame(2)).unwrap();
        assert_eq!(w.size(), 3);
        assert_eq!(w.get(1).unwrap().id, 1);
        assert_eq!(w.front_id(), Some(0));
        w.mark_acked(0);
        assert!(w.front_acked());
        w.pop_front();
        assert_eq!(w.front_id(), Some(1));
        assert_eq!(w.size(), 2);
    }

    #[test]
    fn robuffer_out_of_window() {
        let mut w = ROBuffer::new(4, 0, 1_000_000);
        // id за пределами окна [0,4) → ошибка установки.
        assert!(w.set(100, frame(100)).is_err());
    }
}
