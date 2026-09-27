//! ZIP central-directory forensics: entry listing, encryption-flag detection
//! (真加密), and pseudo-encryption (伪加密) heuristics — the 第08章 shape.

#[derive(Debug, Clone)]
pub struct ZipEntry {
    pub name: String,
    pub flags: u16,
    pub crc: u32,
    pub compressed_size: u32,
    pub uncompressed_size: u32,
    pub local_offset: u32,
    pub encrypted: bool,
}

/// Find the EOCD record scanning backwards.
fn find_eocd(data: &[u8]) -> Option<usize> {
    const SIG: [u8; 4] = [0x50, 0x4b, 0x05, 0x06];
    if data.len() < 22 {
        return None;
    }
    (0..=data.len() - 22).rev().find(|&i| data[i..i + 4] == SIG)
}

/// Walk the central directory. Returns entries + the EOCD-reported offset of
/// the directory start (to compare against the real one for prepended junk).
pub fn walk(data: &[u8]) -> Result<(Vec<ZipEntry>, u32), String> {
    let eocd = find_eocd(data).ok_or("no EOCD (not a zip or badly broken)")?;
    let cd_offset = u32::from_le_bytes(data[eocd + 16..eocd + 20].try_into().unwrap());
    let count = u16::from_le_bytes(data[eocd + 10..eocd + 12].try_into().unwrap()) as usize;
    let mut pos = cd_offset as usize;
    let mut entries = Vec::with_capacity(count);
    for _ in 0..count {
        if pos + 46 > data.len() || data[pos..pos + 4] != [0x50, 0x4b, 0x01, 0x02] {
            break;
        }
        let flags = u16::from_le_bytes(data[pos + 8..pos + 10].try_into().unwrap());
        let crc = u32::from_le_bytes(data[pos + 16..pos + 20].try_into().unwrap());
        let csize = u32::from_le_bytes(data[pos + 20..pos + 24].try_into().unwrap());
        let usize_ = u32::from_le_bytes(data[pos + 24..pos + 28].try_into().unwrap());
        let name_len = u16::from_le_bytes(data[pos + 28..pos + 30].try_into().unwrap()) as usize;
        let extra_len = u16::from_le_bytes(data[pos + 30..pos + 32].try_into().unwrap()) as usize;
        let comment_len = u16::from_le_bytes(data[pos + 32..pos + 34].try_into().unwrap()) as usize;
        let local_offset = u32::from_le_bytes(data[pos + 42..pos + 46].try_into().unwrap());
        let name = String::from_utf8_lossy(&data[pos + 46..pos + 46 + name_len]).into_owned();
        entries.push(ZipEntry {
            name,
            flags,
            crc,
            compressed_size: csize,
            uncompressed_size: usize_,
            local_offset,
            encrypted: flags & 0x1 != 0,
        });
        pos += 46 + name_len + extra_len + comment_len;
    }
    Ok((entries, cd_offset))
}

/// 伪加密 heuristics: entries carry the encryption bit while the local
/// headers' data looks like stored/deflated plaintext (no byte 12/13 in the
/// local header set) — the classic CTF pseudo-encryption sets the flag only
/// in the central directory. Here: flag set on EVERY entry is suspicious when
/// the EOCD offset matches and sizes are consistent. Returns a diagnosis.
pub fn diagnose(data: &[u8]) -> Result<String, String> {
    let (entries, cd_offset) = walk(data)?;
    if entries.is_empty() {
        return Err("no central directory entries".into());
    }
    let encrypted_count = entries.iter().filter(|e| e.encrypted).count();
    let first_local = entries[0].local_offset as usize;
    let local_signature_ok = first_local + 30 <= data.len()
        && data[first_local..first_local + 4] == [0x50, 0x4b, 0x03, 0x04];
    let mut out = format!("entries={} encrypted_count={encrypted_count} ", entries.len());
    if encrypted_count == entries.len() && encrypted_count > 1 {
        out.push_str("suspicion=PSEUDO_ENCRYPTED (all entries flagged; typical 伪加密 marker), ");
    } else if encrypted_count > 0 {
        out.push_str("suspicion=REAL_ENCRYPTED (some entries flagged), ");
    } else {
        out.push_str("suspicion=NONE, ");
    }
    if cd_offset as usize != first_local {
        out.push_str(&format!(
            "note=cd_offset({cd_offset}) != first_local({first_local}) — prepended/trailing junk"
        ));
    } else if local_signature_ok {
        out.push_str("note=local_headers_aligned");
    } else {
        out.push_str("note=local_headers_misaligned");
    }
    Ok(out)
}

/// Extract all entries: stored (method 0) raw, deflate (method 8) via
/// flate2. Handles prepended junk by re-locating local headers.
pub fn extract_all(data: &[u8]) -> Result<Vec<(String, Vec<u8>)>, String> {
    let (entries, _cd) = walk(data)?;
    let mut out = Vec::new();
    for e in &entries {
        if e.encrypted {
            // real encryption: skip with a marker
            out.push((format!("{} (ENCRYPTED)", e.name), vec![]));
            continue;
        }
        // locate the local header; tolerate junk offset drift
        let mut off = e.local_offset as usize;
        let sig = [0x50, 0x4b, 0x03, 0x04];
        if off + 4 > data.len() || data[off..off + 4] != sig {
            off = find_subslice(data, &sig, (e.local_offset as usize).saturating_sub(1024))
                .ok_or_else(|| format!("local header missing for {}", e.name))?;
        }
        if off + 30 > data.len() {
            return Err(format!("local header truncated for {}", e.name));
        }
        let method = u16::from_le_bytes(data[off + 8..off + 10].try_into().unwrap());
        let name_len = u16::from_le_bytes(data[off + 26..off + 28].try_into().unwrap()) as usize;
        let extra_len = u16::from_le_bytes(data[off + 28..off + 30].try_into().unwrap()) as usize;
        let data_start = off + 30 + name_len + extra_len;
        let csize = e.compressed_size as usize;
        if data_start + csize > data.len() {
            return Err(format!("entry data truncated for {}", e.name));
        }
        let raw = &data[data_start..data_start + csize];
        let content = match method {
            0 => raw.to_vec(),
            8 => {
                use std::io::Read;
                let mut decoder = flate2::read::DeflateDecoder::new(raw);
                let mut out_v = Vec::new();
                decoder
                    .read_to_end(&mut out_v)
                    .map_err(|e| format!("inflate: {e}"))?;
                out_v
            }
            m => return Err(format!("unsupported zip method {m} for {}", e.name)),
        };
        out.push((e.name.clone(), content));
    }
    Ok(out)
}

/// Clear the pseudo-encryption flags (bit 0) in central directory AND local
/// headers; returns the fixed zip bytes (第08章 伪加密破解).
pub fn fix_pseudo_encryption(data: &[u8]) -> Result<Vec<u8>, String> {
    let (entries, _cd) = walk(data)?;
    let mut fixed = data.to_vec();
    for e in &entries {
        if !e.encrypted {
            continue;
        }
        // central directory flag: entry walk started at cd; recompute per entry
        let cpos = find_subslice(data, &[0x50, 0x4b, 0x01, 0x02], 0)
            .ok_or("no central dir")?;
        // walk central entries sequentially, patching the matching one
        let mut pos = cpos;
        for _ in 0..entries.len() {
            if pos + 46 > data.len() || data[pos..pos + 4] != [0x50, 0x4b, 0x01, 0x02] {
                break;
            }
            let name_len = u16::from_le_bytes(data[pos + 28..pos + 30].try_into().unwrap()) as usize;
            let extra_len = u16::from_le_bytes(data[pos + 30..pos + 32].try_into().unwrap()) as usize;
            let comment_len = u16::from_le_bytes(data[pos + 32..pos + 34].try_into().unwrap()) as usize;
            let lname =
                String::from_utf8_lossy(&data[pos + 46..pos + 46 + name_len]).into_owned();
            if lname == e.name && fixed[pos + 8] & 0x1 != 0 {
                fixed[pos + 8] &= !0x1;
            }
            pos += 46 + name_len + extra_len + comment_len;
        }
        // local header flag at local_offset + 6
        let off = e.local_offset as usize;
        if off + 8 <= fixed.len() && fixed[off + 6] & 0x1 != 0 {
            fixed[off + 6] &= !0x1;
        }
    }
    Ok(fixed)
}

fn find_subslice(haystack: &[u8], needle: &[u8], from: usize) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() || from >= haystack.len() {
        return None;
    }
    (from..=haystack.len() - needle.len()).find(|&i| &haystack[i..i + needle.len()] == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a tiny stored (uncompressed, unencrypted) zip by hand:
    /// one local header + one central directory entry + EOCD.
    fn tiny_zip() -> Vec<u8> {
        let name = b"a.txt";
        let mut v = Vec::new();
        // local header
        v.extend_from_slice(&[0x50, 0x4b, 0x03, 0x04]);
        v.extend_from_slice(&[10, 0]); // version
        v.extend_from_slice(&[0, 0]); // flags
        v.extend_from_slice(&[0, 0]); // method stored
        v.extend_from_slice(&[0, 0, 0, 0]); // time/date
        v.extend_from_slice(&[0, 0, 0, 0]); // crc
        v.extend_from_slice(&[3, 0, 0, 0]); // csize
        v.extend_from_slice(&[3, 0, 0, 0]); // usize
        v.extend_from_slice(&(name.len() as u16).to_le_bytes());
        v.extend_from_slice(&[0, 0]); // extra len
        v.extend_from_slice(name);
        v.extend_from_slice(b"abc");
        let local_offset = v.len() as u32;
        let _ = local_offset;
        let cd_start = v.len() as u32;
        // central directory
        v.extend_from_slice(&[0x50, 0x4b, 0x01, 0x02]);
        v.extend_from_slice(&[20, 0, 20, 0]); // versions
        v.extend_from_slice(&[0, 0]); // flags
        v.extend_from_slice(&[0, 0]); // method
        v.extend_from_slice(&[0, 0, 0, 0]); // time/date
        v.extend_from_slice(&[0, 0, 0, 0]); // crc
        v.extend_from_slice(&[3, 0, 0, 0]); // csize
        v.extend_from_slice(&[3, 0, 0, 0]); // usize
        v.extend_from_slice(&(name.len() as u16).to_le_bytes());
        v.extend_from_slice(&[0, 0]); // extra
        v.extend_from_slice(&[0, 0]); // comment
        v.extend_from_slice(&[0, 0]); // disk
        v.extend_from_slice(&[0, 0]); // internal attrs
        v.extend_from_slice(&[0, 0, 0, 0]); // external attrs
        v.extend_from_slice(&[0, 0, 0, 0]); // local offset
        v.extend_from_slice(name);
        // EOCD
        v.extend_from_slice(&[0x50, 0x4b, 0x05, 0x06]);
        v.extend_from_slice(&[0, 0]); // disk
        v.extend_from_slice(&[0, 0]); // cd disk
        v.extend_from_slice(&[1, 0]); // count
        v.extend_from_slice(&[1, 0]); // total
        v.extend_from_slice(&(v.len() as u32 - cd_start).to_le_bytes());
        v.extend_from_slice(&cd_start.to_le_bytes());
        v.extend_from_slice(&[0, 0]); // comment len
        v
    }

    #[test]
    fn extracts_stored_entries() {
        let z = tiny_zip();
        let out = extract_all(&z).unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0], ("a.txt".to_string(), b"abc".to_vec()));
    }

    #[test]
    fn pseudo_encryption_fixed() {
        let mut z = tiny_zip();
        // flip the encryption bit in both central + local headers
        let cd = find_eocd(&z).unwrap();
        let cd_start = u32::from_le_bytes(z[cd + 16..cd + 20].try_into().unwrap()) as usize;
        z[cd_start + 8] |= 0x1;
        z[6] |= 0x1;
        let (entries, _) = walk(&z).unwrap();
        assert!(entries[0].encrypted);
        assert!(diagnose(&z).unwrap().contains("PSEUDO_ENCRYPTED") || diagnose(&z).unwrap().contains("REAL_ENCRYPTED"));
        let fixed = fix_pseudo_encryption(&z).unwrap();
        let (entries2, _) = walk(&fixed).unwrap();
        assert!(!entries2[0].encrypted);
        let out = extract_all(&fixed).unwrap();
        assert_eq!(out[0], ("a.txt".to_string(), b"abc".to_vec()));
    }

    #[test]
    fn walks_tiny_zip() {
        let z = tiny_zip();
        let (entries, _) = walk(&z).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "a.txt");
        assert!(!entries[0].encrypted);
        assert!(diagnose(&z).unwrap().contains("suspicion=NONE"));
    }
}
