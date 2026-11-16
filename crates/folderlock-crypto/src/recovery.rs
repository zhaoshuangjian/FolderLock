use sha2::{Digest, Sha256};

use crate::Error;

const ALPH: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// 把 32 字节恢复密钥格式化成可抄写的字符串。
///
/// 载荷是密钥本身加上 SHA-256 前 3 字节，用来在输入时发现抄写错误。
/// 真正的认证仍由 AES-GCM 完成。
pub fn format_recovery_key(key: &[u8; 32]) -> String {
    let material = material(key);
    let raw = encode_base32(&material);
    debug_assert_eq!(raw.chars().count(), 56);
    let chars: Vec<char> = raw.chars().collect();
    let groups: Vec<String> = chars.chunks(4).map(|c| c.iter().collect()).collect();
    format!("FLRK-{}", groups.join("-"))
}

pub fn parse_recovery_key(input: &str) -> Result<[u8; 32], Error> {
    let mut compact = String::new();
    for c in input.chars() {
        if c.is_ascii_alphanumeric() {
            compact.push(c.to_ascii_uppercase());
        }
    }
    // 前缀只在总长度正好多出 "FLRK" 时去掉，避免密钥正文碰巧以这四个字母开头时被截断。
    if compact.len() == 60 && compact.starts_with("FLRK") {
        compact = compact[4..].to_string();
    }
    if compact.len() != 56 {
        return Err(Error::BadRecoveryKey);
    }
    let bytes = decode_base32(&compact)?;
    if bytes.len() != 35 {
        return Err(Error::BadRecoveryKey);
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&bytes[..32]);
    let digest = Sha256::digest(key);
    if bytes[32..35] != digest[..3] {
        return Err(Error::BadRecoveryKey);
    }
    Ok(key)
}

fn material(key: &[u8; 32]) -> [u8; 35] {
    let mut out = [0u8; 35];
    out[..32].copy_from_slice(key);
    let digest = Sha256::digest(key);
    out[32..35].copy_from_slice(&digest[..3]);
    out
}

fn encode_base32(data: &[u8]) -> String {
    let mut bits: u32 = 0;
    let mut nbits: u32 = 0;
    let mut out = String::new();
    for &byte in data {
        bits = (bits << 8) | u32::from(byte);
        nbits += 8;
        while nbits >= 5 {
            nbits -= 5;
            let idx = ((bits >> nbits) & 31) as usize;
            out.push(ALPH[idx] as char);
        }
    }
    if nbits > 0 {
        let idx = ((bits << (5 - nbits)) & 31) as usize;
        out.push(ALPH[idx] as char);
    }
    out
}

fn decode_base32(text: &str) -> Result<Vec<u8>, Error> {
    let mut bits: u32 = 0;
    let mut nbits: u32 = 0;
    let mut out = Vec::new();
    for c in text.chars() {
        let value = alphabet_value(c)?;
        bits = (bits << 5) | u32::from(value);
        nbits += 5;
        if nbits >= 8 {
            nbits -= 8;
            out.push((bits >> nbits) as u8);
            bits &= (1 << nbits) - 1;
        }
    }
    if nbits > 0 && bits != 0 {
        return Err(Error::BadRecoveryKey);
    }
    Ok(out)
}

fn alphabet_value(c: char) -> Result<u8, Error> {
    let c = match c {
        'I' | 'L' => '1',
        'O' => '0',
        'U' => 'V',
        other => other,
    };
    ALPH
        .iter()
        .position(|b| *b as char == c)
        .map(|i| i as u8)
        .ok_or(Error::BadRecoveryKey)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::random_array;

    #[test]
    fn recovery_key_roundtrip_and_typos() {
        let key = random_array::<32>();
        let shown = format_recovery_key(&key);
        assert!(shown.starts_with("FLRK-"));
        assert_eq!(shown.split('-').count(), 15);
        assert_eq!(parse_recovery_key(&shown).unwrap(), key);

        let messy = shown.to_lowercase().replace('-', " ");
        assert_eq!(parse_recovery_key(&messy).unwrap(), key);
        let body = shown.split_once('-').unwrap().1.replace('-', "");
        assert_eq!(body.len(), 56);
        assert_eq!(parse_recovery_key(&body).unwrap(), key);

        let mut chars: Vec<char> = shown.chars().collect();
        let idx = chars.iter().rposition(|c| *c != '-' && *c != 'K').unwrap();
        let orig = chars[idx];
        chars[idx] = if orig == '0' { '2' } else { '0' };
        let tampered: String = chars.into_iter().collect();
        assert!(parse_recovery_key(&tampered).is_err());
    }

    #[test]
    fn accepts_ambiguous_characters() {
        let key = random_array::<32>();
        let shown = format_recovery_key(&key).replace('0', "O").replace('1', "I");
        assert_eq!(parse_recovery_key(&shown).unwrap(), key);
    }
}
