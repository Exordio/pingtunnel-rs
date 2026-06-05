//! Сгенерированные prost-ом типы protobuf (MyMsg, Frame, FrameData).
//! Wire-формат совпадает с оригинальным Go-проектом, поэтому Rust- и
//! Go-версии совместимы между собой на уровне протокола.

include!(concat!(env!("OUT_DIR"), "/pingtunnel.rs"));

/// Магическое число протокола (MyMsg.MAGIC = 0xdead).
pub const MAGIC: i32 = 0xdead;

// Значения MyMsg.TYPE
pub const MSG_DATA: i32 = 0;
pub const MSG_PING: i32 = 1;
pub const MSG_KICK: i32 = 2;

// Значения Frame.TYPE
pub const FRAME_DATA: i32 = 0;
pub const FRAME_REQ: i32 = 1;
pub const FRAME_ACK: i32 = 2;
pub const FRAME_PING: i32 = 3;
pub const FRAME_PONG: i32 = 4;

// Значения FrameData.TYPE
pub const FD_USER_DATA: i32 = 0;
pub const FD_CONN: i32 = 1;
pub const FD_CONNRSP: i32 = 2;
pub const FD_CLOSE: i32 = 3;
pub const FD_HB: i32 = 4;

/// Максимальный размер полезной нагрузки одного фрейма.
pub const FRAME_MAX_SIZE: usize = 888;
/// Максимальный идентификатор фрейма (кольцо id).
pub const FRAME_MAX_ID: i32 = 1_000_000;
