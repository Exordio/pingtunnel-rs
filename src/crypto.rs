//! Шифрование полезной нагрузки ICMP: AES-128-GCM, AES-256-GCM,
//! ChaCha20-Poly1305. Совместимо с Go-версией: к шифртексту впереди
//! приписывается случайный nonce, ключ выводится из base64 или через PBKDF2.

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes128Gcm, Aes256Gcm, Nonce};
use anyhow::{anyhow, bail, Result};
use base64::Engine;
use chacha20poly1305::ChaCha20Poly1305;
use rand::Rng;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EncryptionMode {
    None,
    Aes128,
    Aes256,
    ChaCha20,
}

impl EncryptionMode {
    pub fn parse(s: &str) -> Result<EncryptionMode> {
        match s {
            "" | "none" => Ok(EncryptionMode::None),
            "aes128" => Ok(EncryptionMode::Aes128),
            "aes256" => Ok(EncryptionMode::Aes256),
            "chacha20" | "chacha20-poly1305" => Ok(EncryptionMode::ChaCha20),
            other => bail!("invalid encryption mode: {}", other),
        }
    }

    fn key_size(&self) -> usize {
        match self {
            EncryptionMode::None => 0,
            EncryptionMode::Aes128 => 16,
            EncryptionMode::Aes256 => 32,
            EncryptionMode::ChaCha20 => 32,
        }
    }
}

enum Cipher {
    Aes128(Box<Aes128Gcm>),
    Aes256(Box<Aes256Gcm>),
    Cha(Box<ChaCha20Poly1305>),
}

/// Конфигурация шифрования. `None`-режим обрабатывается на уровне Option<Crypto>.
pub struct Crypto {
    cipher: Cipher,
}

impl Crypto {
    /// Создаёт конфигурацию шифрования. Возвращает None для режима без шифрования.
    pub fn new(mode: EncryptionMode, key_input: &str) -> Result<Option<Crypto>> {
        if mode == EncryptionMode::None {
            return Ok(None);
        }
        let key = derive_key(key_input, mode.key_size())?;
        let cipher = match mode {
            EncryptionMode::Aes128 => Cipher::Aes128(Box::new(
                Aes128Gcm::new_from_slice(&key).map_err(|e| anyhow!("aes128: {e}"))?,
            )),
            EncryptionMode::Aes256 => Cipher::Aes256(Box::new(
                Aes256Gcm::new_from_slice(&key).map_err(|e| anyhow!("aes256: {e}"))?,
            )),
            EncryptionMode::ChaCha20 => Cipher::Cha(Box::new(
                ChaCha20Poly1305::new_from_slice(&key).map_err(|e| anyhow!("chacha20: {e}"))?,
            )),
            EncryptionMode::None => unreachable!(),
        };
        Ok(Some(Crypto { cipher }))
    }

    pub fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>> {
        let mut nonce_bytes = [0u8; 12];
        rand::rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext = match &self.cipher {
            Cipher::Aes128(c) => c.encrypt(nonce, data),
            Cipher::Aes256(c) => c.encrypt(nonce, data),
            Cipher::Cha(c) => c.encrypt(nonce, data),
        }
        .map_err(|e| anyhow!("encrypt failed: {e}"))?;

        let mut out = Vec::with_capacity(12 + ciphertext.len());
        out.extend_from_slice(&nonce_bytes);
        out.extend_from_slice(&ciphertext);
        Ok(out)
    }

    pub fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>> {
        if data.len() < 12 {
            bail!("ciphertext too short");
        }
        let nonce = Nonce::from_slice(&data[..12]);
        let ct = &data[12..];
        let plaintext = match &self.cipher {
            Cipher::Aes128(c) => c.decrypt(nonce, ct),
            Cipher::Aes256(c) => c.decrypt(nonce, ct),
            Cipher::Cha(c) => c.decrypt(nonce, ct),
        }
        .map_err(|e| anyhow!("decryption failed: {e}"))?;
        Ok(plaintext)
    }
}

/// Выводит ключ нужного размера: сперва пытается декодировать как base64,
/// иначе использует PBKDF2-HMAC-SHA256 с фиксированной солью (как в Go-версии).
fn derive_key(key_input: &str, key_size: usize) -> Result<Vec<u8>> {
    if key_input.is_empty() {
        bail!("encryption key cannot be empty");
    }
    if let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(key_input) {
        if decoded.len() == key_size {
            return Ok(decoded);
        }
    }
    let salt = b"pingtunnel-salt";
    let iterations = 10_000u32;
    let mut out = vec![0u8; key_size];
    pbkdf2::pbkdf2_hmac::<sha2::Sha256>(key_input.as_bytes(), salt, iterations, &mut out);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(mode: EncryptionMode) {
        let c = Crypto::new(mode, "secret-pass-phrase").unwrap().unwrap();
        let data = b"the quick brown fox jumps over the lazy dog".repeat(10);
        let enc = c.encrypt(&data).unwrap();
        assert_ne!(enc, data);
        let dec = c.decrypt(&enc).unwrap();
        assert_eq!(dec, data);
    }

    #[test]
    fn aes128_roundtrip() {
        roundtrip(EncryptionMode::Aes128);
    }
    #[test]
    fn aes256_roundtrip() {
        roundtrip(EncryptionMode::Aes256);
    }
    #[test]
    fn chacha20_roundtrip() {
        roundtrip(EncryptionMode::ChaCha20);
    }

    #[test]
    fn wrong_key_fails() {
        let a = Crypto::new(EncryptionMode::Aes256, "key-a").unwrap().unwrap();
        let b = Crypto::new(EncryptionMode::Aes256, "key-b").unwrap().unwrap();
        let enc = a.encrypt(b"hello").unwrap();
        assert!(b.decrypt(&enc).is_err());
    }

    #[test]
    fn none_mode_returns_none() {
        assert!(Crypto::new(EncryptionMode::None, "").unwrap().is_none());
    }
}
