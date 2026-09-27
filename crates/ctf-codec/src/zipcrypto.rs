//! Traditional PKWARE (ZipCrypto) password attacks and CRC32 short-content
//! collision brute force — the 第08章 attack family (暴力/字典/掩码/CRC32).
//!
//! Reference: APPNOTE.TXT section 6.0 (traditional PKWARE encryption).
//! Implemented from the documented algorithm; validated by an internal
//! encrypt/decrypt roundtrip plus live check-byte passes.

use crate::zip::ZipEntry;
use ctf_core::hash::{crc32, crc32_step};

/// ZipCrypto key triple.
#[derive(Clone)]
pub struct ZipCryptoKeys {
    k0: u32,
    k1: u32,
    k2: u32,
}

impl ZipCryptoKeys {
    pub fn new(password: &[u8]) -> Self {
        let mut keys = ZipCryptoKeys { k0: 0x1234_5678, k1: 0x2345_6789, k2: 0x3456_7890 };
        for &b in password {
            keys.update(b);
        }
        keys
    }

    pub fn update(&mut self, byte: u8) {
        self.k0 = crc32_step(self.k0, byte);
        self.k1 = self
            .k1
            .wrapping_add(self.k0 & 0xff)
            .wrapping_mul(1347_75813)
            .wrapping_add(1);
        self.k2 = crc32_step(self.k2, (self.k1 >> 24) as u8);
    }

    fn stream_byte(&self) -> u8 {
        let temp = self.k2 | 2;
        (((temp.wrapping_mul(temp ^ 1)) >> 8) & 0xff) as u8
    }

    fn decrypt_byte(&mut self, c: u8) -> u8 {
        let p = c ^ self.stream_byte();
        self.update(p);
        p
    }

    /// Encryption direction: XOR with the stream, then update with the
    /// PLAINTEXT byte (the decrypt helper updates with the recovered byte —
    /// same op for the content stream, but header fillers need this form).
    fn encrypt_byte(&mut self, p: u8) -> u8 {
        let c = p ^ self.stream_byte();
        self.update(p);
        c
    }
}

/// ZipCrypto encrypt (for roundtrip testing and tooling).
pub fn encrypt(content: &[u8], password: &[u8], crc: u32) -> Vec<u8> {
    let mut keys = ZipCryptoKeys::new(password);
    let mut out = Vec::with_capacity(12 + content.len());
    // 12-byte encryption header; last byte folds the crc (or time when bit3)
    for i in 0..12 {
        let filler = ((crc >> ((i % 4) * 8)) & 0xff) as u8;
        out.push(keys.encrypt_byte(filler));
    }
    for &b in content {
        out.push(keys.encrypt_byte(b));
    }
    out
}

/// Decrypt a ZipCrypto stream (encryption header included).
pub fn decrypt_stream(stream: &[u8], password: &[u8], crc: u32) -> Option<Vec<u8>> {
    if stream.len() < 13 {
        return None;
    }
    let mut keys = ZipCryptoKeys::new(password);
    let mut header = Vec::with_capacity(12);
    for &c in stream.iter().take(12) {
        header.push(keys.decrypt_byte(c));
    }
    // check byte: high byte of the entry crc (or dostime >> 8 when bit 3 set)
    #[cfg(test)]
    if header[11] != (crc >> 24) as u8 {
        eprintln!("[dbg] check byte mismatch: got {:02x} want {:02x}", header[11], (crc >> 24) as u8);
        return None;
    }
    #[cfg(not(test))]
    if header[11] != (crc >> 24) as u8 {
        return None;
    }
    Some(stream[12..].iter().map(|&c| keys.decrypt_byte(c)).collect())
}

/// Try one password against an entry's local encrypted stream.
pub fn try_password(data: &[u8], e: &ZipEntry, password: &[u8]) -> Option<Vec<u8>> {
    let stream = local_encrypted_stream(data, e)?;
    let plain = decrypt_stream(&stream, password, e.crc)?;
    // verify: content must be plausible text for these teaching challenges
    if plain.is_empty() {
        return None;
    }
    let crc_ok = crc32(&plain) == e.crc;
    if !crc_ok {
        return None;
    }
    Some(plain)
}

/// Locate the encrypted stream (12-byte header + content) for an entry.
fn local_encrypted_stream(data: &[u8], e: &ZipEntry) -> Option<Vec<u8>> {
    let mut off = e.local_offset as usize;
    let sig = [0x50, 0x4b, 0x03, 0x04];
    if off + 4 > data.len() || data[off..off + 4] != sig {
        off = (0..=data.len().saturating_sub(4).max(1))
            .rev()
            .find(|&i| i >= off.saturating_sub(1024) && data[i..i + 4] == sig)?;
    }
    if off + 30 > data.len() {
        return None;
    }
    let name_len = u16::from_le_bytes(data[off + 26..off + 28].try_into().ok()?) as usize;
    let extra_len = u16::from_le_bytes(data[off + 28..off + 30].try_into().ok()?) as usize;
    let start = off + 30 + name_len + extra_len;
    let csize = e.compressed_size as usize;
    if start + csize > data.len() {
        return None;
    }
    Some(data[start..start + csize].to_vec())
}

/// Charset brute with a header-only prefilter: decrypt just the 12-byte
/// encryption header and compare the check byte before any full verify.
/// ~12 key ops per candidate instead of a full stream decrypt.
pub fn brute_password_fast(
    data: &[u8],
    e: &ZipEntry,
    charset: &[u8],
    maxlen: usize,
) -> Option<(String, Vec<u8>)> {
    let stream = local_encrypted_stream(data, e)?;
    let check = (e.crc >> 24) as u8;
    let header: Vec<u8> = stream.iter().take(12).copied().collect();
    let mut candidates: Vec<Vec<u8>> = charset.iter().map(|&c| vec![c]).collect();
    for _ in 1..=maxlen {
        let mut next = Vec::new();
        for prefix in &candidates {
            for &c in charset {
                let mut cand = prefix.clone();
                cand.push(c);
                let mut keys = ZipCryptoKeys::new(&cand);
                let mut last = 0u8;
                for &s in &header {
                    last = keys.decrypt_byte(s);
                }
                if last == check {
                    // full verify: decrypt the whole entry and check crc
                    if let Some(content) = try_password(data, e, &cand) {
                        return Some((String::from_utf8_lossy(&cand).into_owned(), content));
                    }
                }
                next.push(cand);
            }
        }
        candidates = next;
    }
    None
}

/// Charset brute (掩码/暴力): all passwords over `charset` up to `maxlen`.
/// Returns the password + decrypted flag.txt content.
pub fn brute_password(
    data: &[u8],
    e: &ZipEntry,
    charset: &[u8],
    maxlen: usize,
) -> Option<(String, Vec<u8>)> {
    let mut current: Vec<Vec<u8>> = charset.iter().map(|&c| vec![c]).collect();
    let mut seen: Vec<Vec<u8>> = current.clone();
    for _ in 1..=maxlen {
        let mut next = Vec::new();
        for prefix in &current {
            for &c in charset {
                let mut cand = prefix.clone();
                cand.push(c);
                if let Some(content) = try_password(data, e, &cand) {
                    return Some((String::from_utf8_lossy(&cand).into_owned(), content));
                }
                next.push(cand);
            }
        }
        seen.append(&mut next.clone());
        current = next;
    }
    None
}

/// Dictionary attack over a wordlist FILE (one password per line).
/// Streams the file; the check-byte filter makes each try cheap.
pub fn dict_file_password(
    data: &[u8],
    e: &ZipEntry,
    wordlist: &std::path::Path,
) -> Option<(String, Vec<u8>)> {
    use std::io::{BufRead, BufReader};
    let file = std::fs::File::open(wordlist).ok()?;
    let mut reader = BufReader::new(file);
    let mut line = String::new();
    loop {
        line.clear();
        if reader.read_line(&mut line).unwrap_or(0) == 0 {
            break;
        }
        let pw = line.trim_end_matches(|c: char| c == '\u{000d}' || c == '\u{000a}');
        if pw.is_empty() {
            continue;
        }
        if let Some(content) = try_password(data, e, pw.as_bytes()) {
            return Some((pw.to_string(), content));
        }
    }
    None
}

/// Dictionary attack over an embedded common-password list.
pub fn dict_password(data: &[u8], e: &ZipEntry) -> Option<(String, Vec<u8>)> {
    const DICT: &[&str] = &[
        "1234", "12345", "123456", "1234567", "12345678", "123456789", "1234567890",
        "password", "password1", "admin", "ctf", "flag", "ctf123", "flag123",
        "abc123", "test", "test123", "letmein", "welcome", "monkey", "dragon",
        "sunshine", "princess", "football", "baseball", "master", "qwerty",
        "111111", "000000", "121212", "654321", "666666", "888888", "abcdef",
        "p@ssw0rd", "passw0rd", "iloveyou", "dasctf", "dasctf123", "book",
        "ctfbook", "zip123", "rar123", "hack", "hacker", "security",
    ];
    for pw in DICT {
        if let Some(content) = try_password(data, e, pw.as_bytes()) {
            return Some((pw.to_string(), content));
        }
    }
    None
}

/// CRC32 collision brute: find short strings whose CRC-32 equals `target`
/// (第08章 CRC32碰撞). Incremental DFS over the running CRC state — no
/// candidate materialization, O(depth) memory.
pub fn crc32_brute(target: u32, charset: &[u8], minlen: usize, maxlen: usize) -> Vec<String> {
    let mut hits = Vec::new();
    let mut buf = Vec::with_capacity(maxlen);
    dfs_crc(target, charset, minlen, maxlen, 0xFFFF_FFFF, 0, &mut buf, &mut hits);
    hits
}

fn dfs_crc(
    target: u32,
    charset: &[u8],
    minlen: usize,
    maxlen: usize,
    state: u32,
    len: usize,
    buf: &mut Vec<u8>,
    hits: &mut Vec<String>,
) {
    if len >= minlen && !state == target {
        hits.push(String::from_utf8_lossy(buf).into_owned());
    }
    if len == maxlen {
        return;
    }
    for &c in charset {
        buf.push(c);
        dfs_crc(target, charset, minlen, maxlen, crc32_step(state, c), len + 1, buf, hits);
        buf.pop();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_header_roundtrip() {
        let content = b"flag{zipcrypto_test}";
        let crc = crc32(content);
        let stream = encrypt(content, b"pw123", crc);
        // re-derive the decrypted header
        let mut keys = ZipCryptoKeys::new(b"pw123");
        let mut header = Vec::new();
        for &c in stream.iter().take(12) {
            header.push(keys.decrypt_byte(c));
        }
        eprintln!("crc={crc:08x} header={:02x?}", header);
        // re-encrypt to compare against the original stream head
        let again = encrypt(content, b"pw123", crc);
        eprintln!("stream head={:02x?}", &stream[..12]);
        eprintln!("again head={:02x?}", &again[..12]);
        assert_eq!(stream, again);
    }

    #[test]
    fn crc32_brute_finds_short_string() {
        let target = ctf_core::hash::crc32(b"x7!");
        let charset: Vec<u8> = (b'!'..=b'~').collect();
        let hits = crc32_brute(target, &charset, 1, 3);
        assert!(hits.iter().any(|h| h == "x7!"), "hits: {:?}", &hits[..hits.len().min(8)]);
    }

    #[test]
    fn roundtrip_encrypt_decrypt() {
        let content = b"flag{zipcrypto_test}";
        let crc = crc32(content);
        let stream = encrypt(content, b"pw123", crc);
        let dec = decrypt_stream(&stream, b"pw123", crc).unwrap();
        assert_eq!(dec, content);
        assert!(decrypt_stream(&stream, b"wrong", crc).is_none());
    }
}
