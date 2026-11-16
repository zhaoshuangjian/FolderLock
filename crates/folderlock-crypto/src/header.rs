use crate::{check_kdf_params, Error};

pub const HEADER_LEN: usize = 512;
const MAGIC: &[u8; 4] = b"FLCK";
const VERSION: u16 = 1;
const KDF_ARGON2ID: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    pub argon_m_kib: u32,
    pub argon_t: u32,
    pub argon_p: u32,
    pub chunk_plain: u32,
    pub salt: [u8; 16],
    pub pw_nonce: [u8; 12],
    pub pw_wrapped: [u8; 48],
    pub rk_nonce: [u8; 12],
    pub rk_wrapped: [u8; 48],
    pub manifest_nonce: [u8; 12],
    pub manifest_offset: u64,
    pub manifest_len: u64,
    pub data_offset: u64,
}

impl Header {
    pub fn serialize(&self) -> Result<[u8; HEADER_LEN], Error> {
        check_kdf_params(self.argon_m_kib, self.argon_t, self.argon_p, self.chunk_plain)?;
        if self.data_offset != HEADER_LEN as u64 {
            return Err(Error::BadHeader);
        }
        let mut buf = [0u8; HEADER_LEN];
        let mut w = Writer { buf: &mut buf, i: 0 };
        w.bytes(MAGIC);
        w.u16(VERSION);
        w.u16(0);
        w.u32(HEADER_LEN as u32);
        w.u32(KDF_ARGON2ID);
        w.u32(self.argon_m_kib);
        w.u32(self.argon_t);
        w.u32(self.argon_p);
        w.u32(self.chunk_plain);
        w.bytes(&self.salt);
        w.bytes(&self.pw_nonce);
        w.bytes(&self.pw_wrapped);
        w.bytes(&self.rk_nonce);
        w.bytes(&self.rk_wrapped);
        w.bytes(&self.manifest_nonce);
        w.u64(self.manifest_offset);
        w.u64(self.manifest_len);
        w.u64(self.data_offset);
        debug_assert!(w.i <= HEADER_LEN);
        Ok(buf)
    }

    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() < HEADER_LEN {
            return Err(Error::BadHeader);
        }
        let mut r = Reader { buf: &bytes[..HEADER_LEN], i: 0 };
        let mut magic = [0u8; 4];
        r.bytes(&mut magic)?;
        if &magic != MAGIC {
            return Err(Error::BadMagic);
        }
        let version = r.u16()?;
        if version != VERSION {
            return Err(Error::BadVersion);
        }
        let flags = r.u16()?;
        if flags != 0 {
            return Err(Error::BadVersion);
        }
        let header_len = r.u32()?;
        if header_len != HEADER_LEN as u32 {
            return Err(Error::BadHeader);
        }
        let kdf = r.u32()?;
        if kdf != KDF_ARGON2ID {
            return Err(Error::BadVersion);
        }
        let header = Header {
            argon_m_kib: r.u32()?,
            argon_t: r.u32()?,
            argon_p: r.u32()?,
            chunk_plain: r.u32()?,
            salt: r.array()?,
            pw_nonce: r.array()?,
            pw_wrapped: r.array()?,
            rk_nonce: r.array()?,
            rk_wrapped: r.array()?,
            manifest_nonce: r.array()?,
            manifest_offset: r.u64()?,
            manifest_len: r.u64()?,
            data_offset: r.u64()?,
        };
        check_kdf_params(header.argon_m_kib, header.argon_t, header.argon_p, header.chunk_plain)?;
        if header.data_offset != HEADER_LEN as u64 {
            return Err(Error::BadHeader);
        }
        Ok(header)
    }

    pub fn validate_bounds(&self, file_len: u64) -> Result<(), Error> {
        if self.manifest_len == 0 || self.manifest_len > 64 * 1024 * 1024 {
            return Err(Error::BadLayout);
        }
        let manifest_end = self
            .manifest_offset
            .checked_add(self.manifest_len)
            .ok_or(Error::BadLayout)?;
        if self.manifest_offset < self.data_offset || manifest_end != file_len {
            return Err(Error::BadLayout);
        }
        Ok(())
    }
}

struct Writer<'a> {
    buf: &'a mut [u8],
    i: usize,
}

impl Writer<'_> {
    fn bytes(&mut self, data: &[u8]) {
        let end = self.i + data.len();
        self.buf[self.i..end].copy_from_slice(data);
        self.i = end;
    }
    fn u16(&mut self, v: u16) {
        self.bytes(&v.to_le_bytes());
    }
    fn u32(&mut self, v: u32) {
        self.bytes(&v.to_le_bytes());
    }
    fn u64(&mut self, v: u64) {
        self.bytes(&v.to_le_bytes());
    }
}

struct Reader<'a> {
    buf: &'a [u8],
    i: usize,
}

impl Reader<'_> {
    fn bytes(&mut self, out: &mut [u8]) -> Result<(), Error> {
        let end = self.i.checked_add(out.len()).ok_or(Error::BadHeader)?;
        if end > self.buf.len() {
            return Err(Error::BadHeader);
        }
        out.copy_from_slice(&self.buf[self.i..end]);
        self.i = end;
        Ok(())
    }
    fn array<const N: usize>(&mut self) -> Result<[u8; N], Error> {
        let mut out = [0u8; N];
        self.bytes(&mut out)?;
        Ok(out)
    }
    fn u16(&mut self) -> Result<u16, Error> {
        Ok(u16::from_le_bytes(self.array()?))
    }
    fn u32(&mut self) -> Result<u32, Error> {
        Ok(u32::from_le_bytes(self.array()?))
    }
    fn u64(&mut self) -> Result<u64, Error> {
        Ok(u64::from_le_bytes(self.array()?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::random_array;

    fn sample() -> Header {
        Header {
            argon_m_kib: 64 * 1024,
            argon_t: 3,
            argon_p: 1,
            chunk_plain: crate::DEFAULT_CHUNK_PLAIN,
            salt: random_array(),
            pw_nonce: random_array(),
            pw_wrapped: random_array(),
            rk_nonce: random_array(),
            rk_wrapped: random_array(),
            manifest_nonce: random_array(),
            manifest_offset: 4096,
            manifest_len: 128,
            data_offset: HEADER_LEN as u64,
        }
    }

    #[test]
    fn header_roundtrip() {
        let header = sample();
        let bytes = header.serialize().unwrap();
        assert_eq!(bytes.len(), 512);
        assert_eq!(&bytes[0..4], b"FLCK");
        let parsed = Header::parse(&bytes).unwrap();
        assert_eq!(parsed, header);
        parsed.validate_bounds(4096 + 128).unwrap();
    }

    #[test]
    fn bad_magic() {
        let mut bytes = sample().serialize().unwrap();
        bytes[0] = b'X';
        assert!(matches!(Header::parse(&bytes), Err(Error::BadMagic)));
    }

    #[test]
    fn manifest_must_end_at_eof() {
        let header = sample();
        assert!(header.validate_bounds(9999).is_err());
    }
}
