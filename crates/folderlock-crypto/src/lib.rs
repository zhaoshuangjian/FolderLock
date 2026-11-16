//! FolderLock 保险箱的密码学与文件格式。
//!
//! 每个保险箱有一把随机主密钥。密码经 Argon2id 派生后只用来包装主密钥，
//! 恢复密钥是另一把独立的 256 位随机密钥，同样只包装主密钥。
//! 文件内容按块做 AES-256-GCM；原始路径只出现在加密清单里。

#![deny(unsafe_code)]

mod header;
mod manifest;
mod recovery;

pub use header::{Header, HEADER_LEN};
pub use manifest::{validate_manifest, validate_rel_path, Entry, Manifest};
pub use recovery::{format_recovery_key, parse_recovery_key};

use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use argon2::{Algorithm, Argon2, Params, Version};
use rand::{rngs::OsRng, RngCore};
use zeroize::Zeroize;

pub const DEFAULT_ARGON_M_KIB: u32 = 64 * 1024;
pub const DEFAULT_ARGON_T: u32 = 3;
pub const DEFAULT_ARGON_P: u32 = 1;
pub const DEFAULT_CHUNK_PLAIN: u32 = 1024 * 1024;

pub const MIN_ARGON_M_KIB: u32 = 8;
pub const MAX_ARGON_M_KIB: u32 = 256 * 1024;
pub const MAX_ARGON_T: u32 = 8;
pub const MAX_ARGON_P: u32 = 4;
pub const MIN_CHUNK_PLAIN: u32 = 16;
pub const MAX_CHUNK_PLAIN: u32 = 16 * 1024 * 1024;

const MANIFEST_AAD: &[u8] = b"flck-manifest-v1";
const WRAP_PASSWORD_AAD: &[u8] = b"flck-wrap-pw-v1";
const WRAP_RECOVERY_AAD: &[u8] = b"flck-wrap-rk-v1";

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("不是 FolderLock 保险箱")]
    BadMagic,
    #[error("不支持的保险箱版本")]
    BadVersion,
    #[error("保险箱头已损坏")]
    BadHeader,
    #[error("密钥派生参数超出允许范围")]
    BadKdfParams,
    #[error("密钥派生失败")]
    Kdf,
    #[error("加密失败")]
    Encrypt,
    #[error("解密失败，密码或恢复密钥不正确，或文件已损坏")]
    Decrypt,
    #[error("恢复密钥格式不正确")]
    BadRecoveryKey,
    #[error("清单已损坏")]
    BadManifest,
    #[error("清单中的路径不安全")]
    BadPath,
    #[error("清单条目与数据区不一致")]
    BadLayout,
}

pub fn random_array<const N: usize>() -> [u8; N] {
    let mut buf = [0u8; N];
    OsRng.fill_bytes(&mut buf);
    buf
}

pub fn chunk_aad(rel: &str, index: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(rel.len() + 9);
    out.extend_from_slice(rel.as_bytes());
    out.push(0);
    out.extend_from_slice(&index.to_le_bytes());
    out
}

/// 校验调用方准备写入的参数。读旧保险箱时用 [`check_stored_params`]。
pub fn check_kdf_params(m_kib: u32, t: u32, p: u32, chunk_plain: u32) -> Result<(), Error> {
    if !(MIN_ARGON_M_KIB..=MAX_ARGON_M_KIB).contains(&m_kib) {
        return Err(Error::BadKdfParams);
    }
    if t == 0 || t > MAX_ARGON_T || p == 0 || p > MAX_ARGON_P {
        return Err(Error::BadKdfParams);
    }
    if !(MIN_CHUNK_PLAIN..=MAX_CHUNK_PLAIN).contains(&chunk_plain) {
        return Err(Error::BadKdfParams);
    }
    Ok(())
}

pub fn derive_kek(password: &[u8], salt: &[u8], m_kib: u32, t: u32, p: u32) -> Result<[u8; 32], Error> {
    check_kdf_params(m_kib, t, p, DEFAULT_CHUNK_PLAIN)?;
    let params = Params::new(m_kib, t, p, Some(32)).map_err(|_| Error::Kdf)?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut kek = [0u8; 32];
    argon
        .hash_password_into(password, salt, &mut kek)
        .map_err(|_| Error::Kdf)?;
    Ok(kek)
}

pub fn seal(key: &[u8; 32], nonce: &[u8; 12], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, Error> {
    let cipher = Aes256Gcm::new(key.into());
    cipher
        .encrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| Error::Encrypt)
}

pub fn open(key: &[u8; 32], nonce: &[u8; 12], ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>, Error> {
    let cipher = Aes256Gcm::new(key.into());
    cipher
        .decrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| Error::Decrypt)
}

pub fn wrap_master(kek: &[u8; 32], nonce: &[u8; 12], master: &[u8; 32], recovery: bool) -> Result<[u8; 48], Error> {
    let aad = if recovery { WRAP_RECOVERY_AAD } else { WRAP_PASSWORD_AAD };
    let ct = seal(kek, nonce, master, aad)?;
    let mut out = [0u8; 48];
    if ct.len() != out.len() {
        return Err(Error::Encrypt);
    }
    out.copy_from_slice(&ct);
    Ok(out)
}

pub fn unwrap_master(kek: &[u8; 32], nonce: &[u8; 12], wrapped: &[u8; 48], recovery: bool) -> Result<[u8; 32], Error> {
    let aad = if recovery { WRAP_RECOVERY_AAD } else { WRAP_PASSWORD_AAD };
    let plain = open(kek, nonce, wrapped, aad)?;
    if plain.len() != 32 {
        plain_zeroize(plain);
        return Err(Error::Decrypt);
    }
    let mut master = [0u8; 32];
    master.copy_from_slice(&plain);
    plain_zeroize(plain);
    Ok(master)
}

fn plain_zeroize(mut buf: Vec<u8>) {
    buf.zeroize();
}

pub fn seal_manifest(key: &[u8; 32], nonce: &[u8; 12], manifest: &Manifest) -> Result<Vec<u8>, Error> {
    let json = serde_json::to_vec(manifest).map_err(|_| Error::BadManifest)?;
    let ct = seal(key, nonce, &json, MANIFEST_AAD)?;
    plain_zeroize(json);
    Ok(ct)
}

pub fn open_manifest(key: &[u8; 32], nonce: &[u8; 12], ciphertext: &[u8]) -> Result<Manifest, Error> {
    let json = open(key, nonce, ciphertext, MANIFEST_AAD)?;
    let manifest = serde_json::from_slice(&json).map_err(|_| Error::BadManifest)?;
    plain_zeroize(json);
    Ok(manifest)
}

/// 明文长度对应的密文载荷长度（含每块的 nonce 与 GCM 标签）。
pub fn expected_payload_len(plain_len: u64, chunk_plain: u64) -> Result<u64, Error> {
    if chunk_plain == 0 {
        return Err(Error::BadKdfParams);
    }
    if plain_len == 0 {
        return Ok(0);
    }
    let full = plain_len / chunk_plain;
    let rem = plain_len % chunk_plain;
    let per_full = 12u64
        .checked_add(chunk_plain)
        .and_then(|n| n.checked_add(16))
        .ok_or(Error::BadLayout)?;
    let mut total = full.checked_mul(per_full).ok_or(Error::BadLayout)?;
    if rem > 0 {
        let tail = 12u64.checked_add(rem).and_then(|n| n.checked_add(16)).ok_or(Error::BadLayout)?;
        total = total.checked_add(tail).ok_or(Error::BadLayout)?;
    }
    Ok(total)
}

pub struct NonceGen {
    n: u128,
}

impl NonceGen {
    pub fn new() -> Self {
        Self { n: 0 }
    }

    pub fn next(&mut self) -> [u8; 12] {
        self.n = self.n.checked_add(1).expect("nonce counter exhausted");
        let bytes = self.n.to_le_bytes();
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&bytes[..12]);
        nonce
    }
}

impl Default for NonceGen {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aead_roundtrip_and_tamper() {
        let key = random_array::<32>();
        let nonce = random_array::<12>();
        let ct = seal(&key, &nonce, b"hello", b"aad").unwrap();
        let pt = open(&key, &nonce, &ct, b"aad").unwrap();
        assert_eq!(pt, b"hello");
        let mut bad = ct.clone();
        bad[0] ^= 1;
        assert!(open(&key, &nonce, &bad, b"aad").is_err());
        assert!(open(&key, &nonce, &ct, b"other").is_err());
    }

    #[test]
    fn wrap_rejects_swapped_password_and_recovery() {
        let master = random_array::<32>();
        let kek = random_array::<32>();
        let nonce = random_array::<12>();
        let wrapped = wrap_master(&kek, &nonce, &master, false).unwrap();
        assert!(unwrap_master(&kek, &nonce, &wrapped, true).is_err());
        assert_eq!(unwrap_master(&kek, &nonce, &wrapped, false).unwrap(), master);
    }

    #[test]
    fn payload_len_matches_chunks() {
        assert_eq!(expected_payload_len(0, 64).unwrap(), 0);
        assert_eq!(expected_payload_len(64, 64).unwrap(), 12 + 64 + 16);
        assert_eq!(expected_payload_len(65, 64).unwrap(), (12 + 64 + 16) + (12 + 1 + 16));
    }

    #[test]
    fn nonce_generator_is_unique() {
        let mut g = NonceGen::new();
        let a = g.next();
        let b = g.next();
        assert_ne!(a, b);
        assert_ne!(a, [0u8; 12]);
    }
}
