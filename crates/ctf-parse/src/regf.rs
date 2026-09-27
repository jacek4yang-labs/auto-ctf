//! Windows registry hive (regf) parsing — key tree walk + value extraction.
//!
//! Registry hives (SYSTEM/SAM/SOFTWARE/NTUSER.DAT) appear in BOTH disk images
//! (C:\Windows\System32\config) and memory dumps (pages of the hive file) —
//! CTF forensics chains use them for Run-keys, last-mounted devices, user
//! activity. This module walks the nk key tree and decodes values, plus a
//! `find_hives` scanner that carves "regf" images out of raw memory.
//!
//! Capability coverage: domain 7 (memory forensics — hive carving) and
//! disk forensics (registry).
//!
//! Provenance: the regf format is publicly documented (Linux-NTFS project
//! forensicswiki); independent implementation, no code copied. Supports the
//! version 5.x nk layout (Windows XP and later — the CTF norm).

use ctf_core::error::{CoreError, Result};

fn invalid(what: &str) -> CoreError {
    CoreError::Invalid(what.into())
}

/// REG_* value types
pub const REG_SZ: u32 = 1;
pub const REG_EXPAND_SZ: u32 = 2;
pub const REG_BINARY: u32 = 3;
pub const REG_DWORD: u32 = 4;
pub const REG_MULTI_SZ: u32 = 7;
pub const REG_QWORD: u32 = 11;

const HIVE_BASE: usize = 0x1000; // first hbin offset

#[derive(Debug, Clone)]
pub struct RegValue {
    pub name: String,
    pub vtype: u32,
    pub data: Vec<u8>,
}

impl RegValue {
    /// decode REG_SZ/EXPAND_SZ/MULTI_SZ as text (UTF-16LE, NUL-trimmed)
    pub fn as_string(&self) -> String {
        if self.vtype == REG_SZ || self.vtype == REG_EXPAND_SZ || self.vtype == REG_MULTI_SZ {
            let units: Vec<u16> = self
                .data
                .chunks_exact(2)
                .map(|b| u16::from_le_bytes(b.try_into().unwrap()))
                .collect();
            let s: String = units
                .iter()
                .take_while(|&&u| u != 0)
                .filter_map(|&u| char::from_u32(u as u32))
                .collect();
            s
        } else {
            String::new()
        }
    }

    /// decode REG_DWORD / REG_QWORD
    pub fn as_int(&self) -> Option<u64> {
        match self.vtype {
            REG_DWORD if self.data.len() >= 4 => {
                Some(u32::from_le_bytes(self.data[..4].try_into().unwrap()) as u64)
            }
            REG_QWORD if self.data.len() >= 8 => {
                Some(u64::from_le_bytes(self.data[..8].try_into().unwrap()))
            }
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct RegKey {
    pub name: String,
    pub last_write: u64,
    pub subkeys: Vec<RegKey>,
    pub values: Vec<RegValue>,
}

fn rd_u16(d: &[u8], p: usize) -> Result<u16> {
    d.get(p..p + 2)
        .map(|b| u16::from_le_bytes(b.try_into().unwrap()))
        .ok_or_else(|| invalid("hive truncated (u16)"))
}

fn rd_u32(d: &[u8], p: usize) -> Result<u32> {
    d.get(p..p + 4)
        .map(|b| u32::from_le_bytes(b.try_into().unwrap()))
        .ok_or_else(|| invalid("hive truncated (u32)"))
}

fn rd_u64(d: &[u8], p: usize) -> Result<u64> {
    d.get(p..p + 8)
        .map(|b| u64::from_le_bytes(b.try_into().unwrap()))
        .ok_or_else(|| invalid("hive truncated (u64)"))
}

pub struct Hive<'a> {
    data: &'a [u8],
    major_version: u32,
}

impl<'a> Hive<'a> {
    pub fn parse(data: &'a [u8]) -> Result<Hive<'a>> {
        if data.len() < HIVE_BASE + 0x30 || &data[0..4] != b"regf" {
            return Err(invalid("not a registry hive (regf)"));
        }
        let major = rd_u32(data, 0x0C)?;
        Ok(Hive { data, major_version: major })
    }

    /// cell content start for a relative cell offset
    fn cell_data(&self, rel: usize) -> Result<&'a [u8]> {
        let off = HIVE_BASE + rel;
        // cell: i32 size (positive = allocated) then content
        let sz = rd_u32(self.data, off)? as usize;
        if sz == 0 || off + 4 + sz > self.data.len() {
            return Err(CoreError::Invalid(format!(
                "cell out of range: rel={:#x} off={:#x} sz={} dlen={:#x}",
                rel, off, sz, self.data.len()
            )));
        }
        Ok(&self.data[off + 4..(off + 4 + sz).min(self.data.len())])
    }

    fn key_name_slice<'b>(&self, nk: &'b [u8]) -> Result<&'b [u8]> {
        // v5 layout: name length @0x48, name @0x4A
        let (len_off, name_off) = if self.major_version >= 5 {
            (0x48usize, 0x4Ausize)
        } else {
            (0x38usize, 0x3Ausize)
        };
        if nk.len() < name_off {
            return Err(invalid("nk record too short"));
        }
        let len = rd_u16(nk, len_off)? as usize;
        Ok(nk
            .get(name_off..name_off + len * 2)
            .ok_or_else(|| invalid("key name beyond nk"))?)
    }

    fn parse_nk(&self, rel: usize, depth: u32) -> Result<RegKey> {
        if depth > 64 {
            return Err(invalid("nk tree too deep (cycle?)"));
        }
        let cell = self.cell_data(rel)?;
        if cell.len() < 0x50 || &cell[0..2] != b"nk" {
            return Err(invalid("cell is not an nk record"));
        }
        let name_units = self.key_name_slice(cell)?;
        let name_units: Vec<u16> = name_units
            .chunks_exact(2)
            .map(|b| u16::from_le_bytes(b.try_into().unwrap()))
            .collect();
        let name = String::from_utf16_lossy(&name_units);
        let last_write = rd_u64(cell, 0x04)?;
        let subkey_count = rd_u32(cell, 0x14)? as usize;
        let subkey_list_rel = rd_u32(cell, 0x1C)? as usize;
        let value_count = rd_u32(cell, 0x24)? as usize;
        let value_list_rel = rd_u32(cell, 0x28)? as usize;

        let mut subkeys = Vec::new();
        if subkey_count > 0 && subkey_list_rel != 0xFFFFFFFF {
            self.collect_subkeys(subkey_list_rel, &mut subkeys, depth)?;
        }

        let mut values = Vec::new();
        if value_count > 0 && value_list_rel != 0xFFFFFFFF {
            let list = self.cell_data(value_list_rel)?;
            if list.len() >= 4 + value_count * 4 {
                for i in 0..value_count {
                    let vrel = rd_u32(list, 4 + i * 4)? as usize;
                    if let Some(v) = self.parse_vk(vrel)? {
                        values.push(v);
                    }
                }
            }
        }

        Ok(RegKey { name, last_write, subkeys, values })
    }

    /// subkey list cells: "lf"/"lh" (offset+hash), "li" (offset), "ri" (indirect)
    fn collect_subkeys(&self, list_rel: usize, subkeys: &mut Vec<RegKey>, depth: u32) -> Result<()> {
        let cell = self.cell_data(list_rel)?;
        if cell.len() < 6 {
            return Ok(());
        }
        let tag = &cell[0..2];
        let count = rd_u16(cell, 2)? as usize;
        match tag {
            b"lf" | b"lh" => {
                // count × (offset u32, hash u32)
                for i in 0..count {
                    let off = rd_u32(cell, 4 + i * 8)? as usize;
                    if let Ok(k) = self.parse_nk(off, depth + 1) {
                        subkeys.push(k);
                    }
                }
            }
            b"li" => {
                for i in 0..count {
                    let off = rd_u32(cell, 4 + i * 4)? as usize;
                    if let Ok(k) = self.parse_nk(off, depth + 1) {
                        subkeys.push(k);
                    }
                }
            }
            b"ri" => {
                // indirect: offsets to lf/lh/li lists
                for i in 0..count {
                    let off = rd_u32(cell, 4 + i * 4)? as usize;
                    let mut inner = Vec::new();
                    self.collect_subkeys(off, &mut inner, depth + 1)?;
                    subkeys.extend(inner);
                }
            }
            _ => {}
        }
        Ok(())
    }

    /// vk value record: name (inline/compressed), type, data (inline or cell)
    fn parse_vk(&self, rel: usize) -> Result<Option<RegValue>> {
        let cell = self.cell_data(rel)?;
        if cell.len() < 0x18 || &cell[0..2] != b"vk" {
            return Ok(None);
        }
        let name_len = rd_u16(cell, 2)? as usize;
        let data_size = rd_u32(cell, 4)?;
        let data_off = rd_u32(cell, 8)?;
        let vtype = rd_u32(cell, 0x0C)?;
        let compressed = rd_u16(cell, 0x10)? & 1 != 0;
        let name = if compressed {
            // ASCII name, high bit of each byte set in some hives
            cell.get(0x14..0x14 + name_len)
                .map(|b| b.iter().map(|&c| (c & 0x7f) as char).collect())
                .unwrap_or_default()
        } else {
            let units: Vec<u16> = cell
                .get(0x14..0x14 + name_len * 2)
                .unwrap_or(&[])
                .chunks_exact(2)
                .map(|b| u16::from_le_bytes(b.try_into().unwrap()))
                .collect();
            String::from_utf16_lossy(&units)
        };
        let is_inline = data_size & 0x8000_0000 != 0;
        let real_len = (data_size & 0x3FFF_FFFF) as usize;
        let data = if is_inline {
            // data lives in the 4-byte offset field
            data_off.to_le_bytes()[..real_len.min(4)].to_vec()
        } else {
            let base = HIVE_BASE + data_off as usize;
            self.data
                .get(base..base + real_len)
                .unwrap_or(&[])
                .to_vec()
        };
        Ok(Some(RegValue { name, vtype: vtype, data }))
    }
}

/// carve "regf" hive images out of a raw memory dump: returns (offset, tree)
/// for each 4096-aligned or raw occurrence whose header validates.
pub fn find_hives(data: &[u8]) -> Vec<(usize, RegKey)> {
    let mut out = Vec::new();
    for off in crate::rawmem::find_all(data, b"regf") {
        if let Ok(hive) = Hive::parse(&data[off..]) {
            // walk lazily — a valid root nk is enough to report
            if let Ok(root) = hive.parse_nk(rd_u32(data, off + 0x24).unwrap_or(0) as usize, 0) {
                out.push((off, root));
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// build a minimal hive: root "SOFTWARE" → subkey "Flag" with REG_SZ value
    fn build_hive() -> Vec<u8> {
        let mut d = vec![0u8; 0x2000];
        d[0..4].copy_from_slice(b"regf");
        d[0x0C..0x10].copy_from_slice(&5u32.to_le_bytes()); // major version 5
        // root cell at relative 0x10
        d[0x24..0x28].copy_from_slice(&0x10u32.to_le_bytes());
        // first hbin at 0x1000
        d[0x1000..0x1004].copy_from_slice(b"hbin");
        d[0x1004..0x1008].copy_from_slice(&0u32.to_le_bytes());
        d[0x1008..0x100C].copy_from_slice(&0x1000u32.to_le_bytes());

        // helper: place a cell at `rel`, returns nothing; cell = size i32 + payload
        let place = |d: &mut Vec<u8>, rel: usize, payload: &[u8]| {
            let size = (payload.len() + 4 + 7) & !7; // 8-byte aligned
            d[HIVE_BASE + rel..HIVE_BASE + rel + 4]
                .copy_from_slice(&(size as i32).to_le_bytes());
            d[HIVE_BASE + rel + 4..HIVE_BASE + rel + 4 + payload.len()]
                .copy_from_slice(payload);
        };

        // root nk "SOFTWARE" at rel 0x10: cell payload = nk record
        let mut root_nk: Vec<u8> = Vec::new();
        root_nk.extend_from_slice(b"nk");
        root_nk.extend_from_slice(&0x0020u16.to_le_bytes()); // root flag
        root_nk.extend_from_slice(&0u64.to_le_bytes()); // timestamp
        root_nk.extend_from_slice(&0u32.to_le_bytes()); // spare
        root_nk.extend_from_slice(&0u32.to_le_bytes()); // parent
        root_nk.extend_from_slice(&1u32.to_le_bytes()); // 1 subkey
        root_nk.extend_from_slice(&0u32.to_le_bytes()); // volatile subkeys
        root_nk.extend_from_slice(&0x180u32.to_le_bytes()); // subkey list rel (lf at 0x180)
        root_nk.extend_from_slice(&0xFFFFFFFFu32.to_le_bytes());
        root_nk.extend_from_slice(&0u32.to_le_bytes()); // value count
        root_nk.extend_from_slice(&0xFFFFFFFFu32.to_le_bytes()); // value list
        root_nk.extend_from_slice(&0xFFFFFFFFu32.to_le_bytes());
        root_nk.extend_from_slice(&0xFFFFFFFFu32.to_le_bytes());
        root_nk.extend_from_slice(&vec![0u8; 0x48 - root_nk.len()]);
        let nm = "SOFTWARE".encode_utf16().collect::<Vec<u16>>();
        root_nk.extend_from_slice(&(nm.len() as u16).to_le_bytes());
        for u in nm {
            root_nk.extend_from_slice(&u.to_le_bytes());
        }
        place(&mut d, 0x10, &root_nk);

        // subkey nk "Flag" at rel 0x100: values 1, value list at 0x200
        let mut sub_nk: Vec<u8> = Vec::new();
        sub_nk.extend_from_slice(b"nk");
        sub_nk.extend_from_slice(&0u16.to_le_bytes()); // normal key
        sub_nk.extend_from_slice(&0u64.to_le_bytes());
        sub_nk.extend_from_slice(&0u32.to_le_bytes());
        sub_nk.extend_from_slice(&0x10u32.to_le_bytes()); // parent = root
        sub_nk.extend_from_slice(&0u32.to_le_bytes()); // 0 subkeys
        sub_nk.extend_from_slice(&0u32.to_le_bytes());
        sub_nk.extend_from_slice(&0xFFFFFFFFu32.to_le_bytes());
        sub_nk.extend_from_slice(&0xFFFFFFFFu32.to_le_bytes());
        sub_nk.extend_from_slice(&1u32.to_le_bytes()); // 1 value
        sub_nk.extend_from_slice(&0x200u32.to_le_bytes()); // value list rel
        sub_nk.extend_from_slice(&0xFFFFFFFFu32.to_le_bytes());
        sub_nk.extend_from_slice(&0xFFFFFFFFu32.to_le_bytes());
        sub_nk.extend_from_slice(&vec![0u8; 0x48 - sub_nk.len()]);
        let nm2 = "Flag".encode_utf16().collect::<Vec<u16>>();
        sub_nk.extend_from_slice(&(nm2.len() as u16).to_le_bytes());
        for u in nm2 {
            sub_nk.extend_from_slice(&u.to_le_bytes());
        }
        place(&mut d, 0x100, &sub_nk);

        // lf subkey list at 0x180: count 1, [offset 0x100, hash]
        let mut lf: Vec<u8> = Vec::new();
        lf.extend_from_slice(b"lf");
        lf.extend_from_slice(&1u16.to_le_bytes());
        lf.extend_from_slice(&0x100u32.to_le_bytes());
        lf.extend_from_slice(b"FLAG"); // hash = first 4 name chars
        place(&mut d, 0x180, &lf);

        // value list at 0x200: count 1, [vk rel 0x220]
        let mut vl: Vec<u8> = Vec::new();
        vl.extend_from_slice(&1u32.to_le_bytes());
        vl.extend_from_slice(&0x220u32.to_le_bytes());
        place(&mut d, 0x200, &vl);

        // vk at 0x220: name "Version" (compressed ascii), REG_SZ inline "CTF\0"
        let mut vk: Vec<u8> = Vec::new();
        vk.extend_from_slice(b"vk");
        vk.extend_from_slice(&7u16.to_le_bytes()); // name len
        vk.extend_from_slice(&(0x8000_0004u32).to_le_bytes()); // inline, 4 bytes
        vk.extend_from_slice(b"C\0T\0"); // inline REG_SZ "CT" (UTF-16LE)
        vk.extend_from_slice(&REG_SZ.to_le_bytes());
        vk.extend_from_slice(&1u16.to_le_bytes()); // compressed flag
        vk.extend_from_slice(&0u16.to_le_bytes());
        vk.extend_from_slice(b"Version");
        place(&mut d, 0x220, &vk);

        d
    }

    #[test]
    fn walks_key_tree_and_values() {
        let data = build_hive();
        let hive = Hive::parse(&data).expect("parse");
        let root = hive.parse_nk(0x10, 0).expect("root");
        assert_eq!(root.name, "SOFTWARE");
        assert_eq!(root.subkeys.len(), 1);
        let flag = &root.subkeys[0];
        assert_eq!(flag.name, "Flag");
        assert_eq!(flag.values.len(), 1);
        let v = &flag.values[0];
        assert_eq!(v.name, "Version");
        assert_eq!(v.vtype, REG_SZ);
        assert_eq!(v.as_string(), "CT");
    }

    #[test]
    fn carves_hive_from_memory() {
        let hive = build_hive();
        let mut mem = b"memorypadding".to_vec();
        let off = mem.len();
        mem.extend(hive);
        let found = find_hives(&mem);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].0, off);
        assert_eq!(found[0].1.name, "SOFTWARE");
    }

    #[test]
    fn rejects_non_hive() {
        assert!(Hive::parse(b"not a hive at all.......").is_err());
    }
}
