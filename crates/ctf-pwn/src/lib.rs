//! ctf-pwn — pwntools-class primitives, Rust-native (see docs/UPSTREAM.md
//! for the pwntools gap table and docs/DEPS.md for crate provenance).
//!
//! Coverage now: pack/unpack (p32/p64/u32/u64 le/be), cyclic patterns +
//! offset finding, ELF-lite symbol/GOT/PLT reading via goblin, and ROP
//! gadget search over plain-text disassembly dumps (reverse-mcp
//! ida_disassemble/ida_bytes output). No process tubes here — use ctf-tube.

use num_bigint::BigUint;
use num_traits::ToPrimitive;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum PwnError {
    #[error("value too large for {0} bytes")]
    TooLarge(usize),
    #[error("not enough bytes: need {0}, have {1}")]
    Short(usize, usize),
    #[error("{0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, PwnError>;

// ------------------------------------------------------------------ //
// pack / unpack                                                      //
// ------------------------------------------------------------------ //

/// little-endian unsigned integer -> bytes (pwntools p32/p64)
pub fn pack_le(value: u64, width: usize) -> Result<Vec<u8>> {
    if width == 0 || width > 8 {
        return Err(PwnError::Other("width must be 1..=8".into()));
    }
    let mask = if width == 8 { u64::MAX } else { (1u64 << (8 * width)) - 1 };
    if value & !mask != 0 {
        return Err(PwnError::TooLarge(width));
    }
    Ok(value.to_le_bytes()[..width].to_vec())
}

/// bytes -> little-endian unsigned integer (pwntools u32/u64)
pub fn unpack_le(bytes: &[u8]) -> u64 {
    let mut v = 0u64;
    for (i, &b) in bytes.iter().take(8).enumerate() {
        v |= (b as u64) << (8 * i);
    }
    v
}

/// big-endian unsigned integer -> bytes
pub fn pack_be(value: u64, width: usize) -> Result<Vec<u8>> {
    Ok(pack_le(value, width)?.into_iter().rev().collect())
}

/// bytes -> big-endian unsigned integer
pub fn unpack_be(bytes: &[u8]) -> u64 {
    bytes.iter().take(8).fold(0u64, |acc, &b| (acc << 8) | b as u64)
}

/// p64/u64 with a power-of-two-or-odd width, on BigUint for wide values.
pub fn pack_big(value: &BigUint, width: usize, little: bool) -> Result<Vec<u8>> {
    if width == 0 {
        return Err(PwnError::Other("width must be >= 1".into()));
    }
    let mut bytes = Vec::with_capacity(width);
    let mut v = value.clone();
    let zero = BigUint::from(0u32);
    for _ in 0..width {
        let byte = (&v & BigUint::from(0xFFu32)).to_u8().unwrap_or(0);
        bytes.push(byte);
        v >>= 8;
        if v == zero {
            break;
        }
    }
    while bytes.len() < width {
        bytes.push(0);
    }
    if !little {
        bytes.reverse();
    }
    Ok(bytes)
}

// ------------------------------------------------------------------ //
// cyclic patterns (pwntools-compatible generator)                    //
// ------------------------------------------------------------------ //

/// pwntools default alphabet chunks: lowercase letters groups of 4.
const CYCLIC_ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz";

/// Generate the pwntools-compatible cyclic pattern: group j is the base-26
/// little-endian encoding of j over the alphabet (group 0 = "aaaa",
/// group 1 = "baaa", ...), so offsets are cross-tool compatible.
pub fn cyclic(length: usize, chunk: usize) -> Vec<u8> {
    let chunk = if chunk == 0 { 4 } else { chunk };
    let alpha_len = CYCLIC_ALPHABET.len();
    let mut out = Vec::with_capacity(length);
    let mut group = 0usize;
    while out.len() < length {
        let mut v = group;
        for _ in 0..chunk {
            let digit = v % alpha_len;
            v /= alpha_len;
            out.push(CYCLIC_ALPHABET[digit]);
            if out.len() == length {
                break;
            }
        }
        group += 1;
    }
    out
}

/// Find the byte offset of `sub` (length == chunk) in the canonical pattern.
pub fn cyclic_find(sub: &[u8]) -> Result<usize> {
    if sub.is_empty() {
        return Err(PwnError::Other("empty subsequence".into()));
    }
    let alpha_len = CYCLIC_ALPHABET.len();
    let mut index = 0usize;
    for (i, &b) in sub.iter().enumerate() {
        let pos = CYCLIC_ALPHABET
            .iter()
            .position(|&a| a == b)
            .ok_or_else(|| PwnError::Other(format!("byte {b:#x} outside cyclic alphabet")))?;
        index += pos * alpha_len.pow(i as u32);
    }
    Ok(index * sub.len())
}

// ------------------------------------------------------------------ //
// ELF-lite via goblin                                                //
// ------------------------------------------------------------------ //

#[derive(Debug, Clone)]
pub struct ElfSymbols {
    pub functions: Vec<(String, u64)>,
    pub got_entries: Vec<(String, u64)>,
}

/// Parse ELF64/ELF32 symbols (FUNC + OBJECT) from a raw ELF binary.
pub fn elf_symbols(bytes: &[u8]) -> Result<ElfSymbols> {
    let elf = goblin::elf::Elf::parse(bytes).map_err(|e| PwnError::Other(e.to_string()))?;
    let mut functions = Vec::new();
    let mut got_entries = Vec::new();
    for sym in elf.syms.iter() {
        let name = elf
            .strtab
            .get_at(sym.st_name)
            .unwrap_or_default()
            .to_string();
        if name.is_empty() {
            continue;
        }
        match sym.st_info & 0xf {
            2 => functions.push((name, sym.st_value)), // STT_FUNC
            1 => got_entries.push((name, sym.st_value)), // STT_OBJECT
            _ => {}
        }
    }
    functions.sort();
    got_entries.sort();
    Ok(ElfSymbols { functions, got_entries })
}

/// Extract the dynamic PLT relocations (JMPREL) as (name, got_offset).
pub fn elf_plt_entries(bytes: &[u8]) -> Result<Vec<(String, u64)>> {
    let elf = goblin::elf::Elf::parse(bytes).map_err(|e| PwnError::Other(e.to_string()))?;
    let mut out = Vec::new();
    for reloc in elf.pltrelocs.iter() {
        if let Some(name) = elf.dynstrtab.get_at(reloc.r_sym) {
            out.push((name.to_string(), reloc.r_offset));
        }
    }
    out.sort();
    Ok(out)
}

// ------------------------------------------------------------------ //
// ROP gadget search over disassembly text                            //
// ------------------------------------------------------------------ //

/// A parsed gadget from a text disassembly dump (one instruction per line).
#[derive(Debug, Clone)]
pub struct Gadget {
    pub address: u64,
    pub instructions: Vec<String>,
}

/// Search lines like "  0x401234: ret" / "0x401234    pop rdi ; ret" for
/// `ret`-terminated gadget tails. `dump` is plain text from
/// reverse-mcp ida_disassemble or any objdump-style listing.
pub fn find_gadgets(dump: &str, max_len: usize) -> Vec<Gadget> {
    let mut entries: Vec<(u64, String)> = Vec::new();
    for line in dump.lines() {
        let line = line.trim();
        let Some(colon_pos) = line.find(':') else { continue };
        let addr_part = line[..colon_pos].trim();
        let addr_str = addr_part.trim_start_matches("0x").trim();
        let Ok(addr) = u64::from_str_radix(addr_str, 16) else { continue };
        let insn = line[colon_pos + 1..].trim().to_string();
        if !insn.is_empty() {
            entries.push((addr, insn));
        }
    }
    let mut gadgets = Vec::new();
    for i in 0..entries.len() {
        let mut chain = Vec::new();
        for j in i..entries.len().min(i + max_len) {
            chain.push(entries[j].1.clone());
            let last = chain.last().unwrap().to_lowercase();
            if last == "ret" || last.starts_with("ret ") {
                gadgets.push(Gadget { address: entries[i].0, instructions: chain.clone() });
                break;
            }
            // stop extending across a non-ret terminator we cannot chain past
            if last.starts_with("call") || last.starts_with("jmp") {
                break;
            }
        }
    }
    gadgets
}

/// Filter gadgets containing all given instruction snippets.
pub fn filter_gadgets<'a>(gadgets: &'a [Gadget], needles: &[&str]) -> Vec<&'a Gadget> {
    gadgets
        .iter()
        .filter(|g| {
            needles.iter().all(|n| {
                g.instructions.iter().any(|i| i.to_lowercase().contains(&n.to_lowercase()))
            })
        })
        .collect()
}

// ------------------------------------------------------------------ //
// context (pwntools-shaped global defaults)                          //
// ------------------------------------------------------------------ //

/// Target context: architecture word size and endianness for pack helpers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Arch {
    Amd64,
    I386,
}

impl Arch {
    pub fn bits(self) -> usize {
        match self {
            Arch::Amd64 => 8,
            Arch::I386 => 4,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Context {
    pub arch: Arch,
    pub little_endian: bool,
}

impl Default for Context {
    fn default() -> Self {
        Self { arch: Arch::Amd64, little_endian: true }
    }
}

impl Context {
    /// p64/p32 equivalent honoring context endianness.
    pub fn pack(&self, value: u64) -> Result<Vec<u8>> {
        if self.little_endian {
            pack_le(value, self.arch.bits())
        } else {
            pack_be(value, self.arch.bits())
        }
    }

    /// u64/u32 equivalent honoring context endianness.
    pub fn unpack(&self, bytes: &[u8]) -> u64 {
        if self.little_endian {
            unpack_le(bytes)
        } else {
            unpack_be(bytes)
        }
    }
}

// ------------------------------------------------------------------ //
// ROP chain building over found gadgets                              //
// ------------------------------------------------------------------ //

/// Assemble a chain: for each gadget, emit its address, then 8-byte values
/// for every `pop <reg>` it contains (x64 calling convention). Values are
/// consumed in order; missing values become 0.
pub fn build_chain_x64(chain: &[&Gadget], values: &[u64]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut vi = 0usize;
    for g in chain {
        out.extend_from_slice(&g.address.to_le_bytes());
        for insn in &g.instructions {
            let low = insn.to_lowercase();
            if low.starts_with("pop ") && low != "popad" {
                let v = values.get(vi).copied().unwrap_or(0);
                out.extend_from_slice(&v.to_le_bytes());
                vi += 1;
            }
        }
    }
    out
}

/// Consume the first popped value of the chain as `rdi` — convenience for
/// the classic pop rdi; ret; / binsh; / system layout.
pub fn pop_rdi_payload(pop_rdi: &Gadget, rdi: u64, next: u64) -> Vec<u8> {
    build_chain_x64(&[pop_rdi], &[rdi]).tap_extend(next)
}

trait TapExtend {
    fn tap_extend(self, next: u64) -> Vec<u8>;
}
impl TapExtend for Vec<u8> {
    fn tap_extend(mut self, next: u64) -> Vec<u8> {
        self.extend_from_slice(&next.to_le_bytes());
        self
    }
}

// ------------------------------------------------------------------ //
// format-string offset (pwntools fmtstr_offset)                      //
// ------------------------------------------------------------------ //

/// Given a leaked 4/8-byte window of the cyclic pattern, compute the
/// positional argument index. `start` is the first stack index occupied by
/// caller-controlled data (6 on x86-64 printf, 1 on x86).
pub fn fmtstr_offset(leaked: &[u8], start: usize) -> Result<usize> {
    let w = leaked.len();
    if w != 4 && w != 8 {
        return Err(PwnError::Other("leak must be 4 or 8 bytes".into()));
    }
    let slot = if w == 8 { 8 } else { 4 };
    let off = cyclic_find(leaked)? / slot + start;
    Ok(off)
}

#[cfg(test)]
pub mod fmtstr;
pub mod stackvm;

mod tests {
    use super::*;

    #[test]
    fn pack_unpack_roundtrip() {
        assert_eq!(pack_le(0xdeadbeef, 4).unwrap(), vec![0xef, 0xbe, 0xad, 0xde]);
        assert_eq!(unpack_le(&[0xef, 0xbe, 0xad, 0xde]), 0xdeadbeef);
        assert_eq!(pack_be(0xdeadbeef, 4).unwrap(), vec![0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(unpack_be(&[0xde, 0xad, 0xbe, 0xef]), 0xdeadbeef);
        assert!(pack_le(0x1_0000, 2).is_err()); // overflow
        assert_eq!(pack_le(0x1234, 8).unwrap().len(), 8);
    }

    #[test]
    fn pack_big_wide() {
        let v = BigUint::from(0x1122334455667788u64);
        let le = pack_big(&v, 16, true).unwrap();
        assert_eq!(le.len(), 16);
        assert_eq!(le[0], 0x88);
        assert_eq!(le[15], 0);
        let be = pack_big(&v, 16, false).unwrap();
        assert_eq!(be[0], 0);
    }

    #[test]
    fn cyclic_is_prefix_consistent() {
        let pat = cyclic(64, 4);
        assert_eq!(&pat[..4], b"aaaa");
        // pwntools order: aaaabaaacaaadaaa...
        assert_eq!(&pat[..16], b"aaaabaaacaaadaaa");
        // longer pattern is an extension of the shorter one
        let longer = cyclic(128, 4);
        assert_eq!(&longer[..64], &pat[..]);
    }

    #[test]
    fn cyclic_find_locates_offset() {
        let pat = cyclic(1024, 4);
        // find by 4-byte slice taken from the pattern at offset 12
        let off = 12usize;
        assert_eq!(cyclic_find(&pat[off..off + 4]).unwrap(), off);
    }

    #[test]
    fn elf_symbols_and_plt() {
        // minimal sanity: parse a hand-built ELF is overkill here; exercise
        // the error path on garbage input.
        assert!(elf_symbols(b"not an elf").is_err());
        assert!(elf_plt_entries(b"not an elf").is_err());
    }

    #[test]
    fn context_packs_by_arch() {
        let ctx = Context::default();
        assert_eq!(ctx.pack(0x41424344).unwrap(), vec![0x44, 0x43, 0x42, 0x41, 0, 0, 0, 0]);
        let x86 = Context { arch: Arch::I386, little_endian: false };
        assert_eq!(x86.pack(0x41424344).unwrap(), vec![0x41, 0x42, 0x43, 0x44]);
        assert_eq!(x86.unpack(&[0x41, 0x42, 0x43, 0x44]), 0x41424344);
    }

    #[test]
    fn rop_chain_emits_pops() {
        let gadgets = find_gadgets(
            "0x401020: pop rdi
0x401021: ret
0x401030: pop rsi
0x401031: pop r15
0x401033: ret",
            4,
        );
        let pop_rdi = filter_gadgets(&gadgets, &["pop rdi"])[0];
        let pop_rsi_r15 = filter_gadgets(&gadgets, &["pop rsi", "pop r15"])[0];
        let chain = build_chain_x64(&[pop_rdi, pop_rsi_r15], &[0xdead, 0xbee, 0xef]);
        // gadget addr + pop values; the final ret consumes the NEXT stack
        // entry, which the caller appends when chaining further gadgets.
        let mut expected = Vec::new();
        expected.extend_from_slice(&0x401020u64.to_le_bytes());
        expected.extend_from_slice(&0xdeadu64.to_le_bytes());
        expected.extend_from_slice(&0x401030u64.to_le_bytes());
        expected.extend_from_slice(&0xbeeu64.to_le_bytes());
        expected.extend_from_slice(&0xefu64.to_le_bytes());
        assert_eq!(chain, expected);
    }

    #[test]
    fn fmtstr_offset_standard() {
        // fmtstr leaks use chunk=8 cyclic patterns (pwntools n=8)
        let pat = cyclic(512, 8);
        let leak = &pat[48..56]; // group 6 -> slot 48/8 + 6 = 12
        assert_eq!(fmtstr_offset(leak, 6).unwrap(), 12);
    }

    #[test]
    fn gadget_search_finds_ret_tail() {
        let dump = "\
0x401010: ret
0x401020: pop rdi
0x401021: ret
0x401030: pop rsi
0x401031: pop r15
0x401033: ret
0x401040: call rax
0x401041: ret";
        let gadgets = find_gadgets(dump, 4);
        assert!(gadgets.iter().any(|g| g.address == 0x401010
            && g.instructions == vec!["ret"]));
        let pop_rdi = filter_gadgets(&gadgets, &["pop rdi"]);
        assert_eq!(pop_rdi.len(), 1);
        assert_eq!(pop_rdi[0].address, 0x401020);
        let pop_rsi_r15 = filter_gadgets(&gadgets, &["pop rsi", "pop r15"]);
        assert_eq!(pop_rsi_r15.len(), 1);
        assert_eq!(pop_rsi_r15[0].address, 0x401030);
    }
}
