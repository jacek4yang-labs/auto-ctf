//! USB HID keyboard report decoding (traffic-analysis misc challenges).
//!
//! A keyboard sends 8-byte reports: [modifier][reserved][key1..key6]. A key
//! produces its character on the 0→pressed transition; the shift modifier
//! (left 0x02 / right 0x20) selects the shifted symbol. The decoder is
//! pure — feed it the report stream extracted from USB pcap/pcapng traffic
//! (in USBPcap captures the 8-byte report sits at a fixed offset from the
//! end of each packet; slice before calling).
//!
//! Provenance: standard USB HID Usage Tables (public specification);
//! independent implementation, vectors generated locally.

/// (unshifted, shifted) printable pair per HID usage id; specials included
fn key_char(k: u8, shift: bool) -> Option<char> {
    let (base, shifted) = match k {
        0x04..=0x1d => {
            // a-z
            let b = b'a' + (k - 0x04);
            (b as char, (b - 32) as char)
        }
        0x1e..=0x27 => {
            // 1..9, 0
            let n = k - 0x1e;
            let d = if n == 9 { b'0' } else { b'1' + n };
            let sym = [b'!', b'@', b'#', b'$', b'%', b'^', b'&', b'*', b'('][n as usize];
            (d as char, sym as char)
        }
        0x28 => ('\n', '\n'),   // enter
        0x29 => ('\x1b', '\x1b'), // escape
        0x2a => ('\x08', '\x08'), // backspace
        0x2c => (' ', ' '),     // space
        0x2d => ('-', '_'),
        0x2e => ('=', '+'),
        0x2f => ('[', '{'),
        0x30 => (']', '}'),
        0x31 => ('\\', '|'),
        0x33 => (';', ':'),
        0x34 => ('\'', '"'),
        0x35 => ('`', '~'),
        0x36 => (',', '<'),
        0x37 => ('.', '>'),
        0x38 => ('/', '?'),
        _ => return None,
    };
    Some(if shift { shifted } else { base })
}

/// Decode a sequence of 8-byte HID keyboard reports into the typed string.
/// `reports` is a flat slice; every `stride` bytes starting at `offset` is one
/// report (stride 8 for raw streams). Key-repeat suppression: a keycode held
/// down only types once.
pub fn decode_keyboard_reports(reports: &[u8], offset: usize, stride: usize) -> Option<String> {
    if stride < 8 || offset + 8 > reports.len() {
        return None;
    }
    let mut out = String::new();
    let mut prev: Vec<u8> = Vec::new();
    let mut pos = offset;
    while pos + 8 <= reports.len() {
        let r = &reports[pos..pos + 8];
        pos += stride;
        let shift = r[0] & 0x22 != 0;
        for &k in &r[2..8] {
            if k == 0 || prev.contains(&k) {
                continue;
            }
            if let Some(c) = key_char(k, shift) {
                out.push(c);
            }
        }
        prev = r[2..8].to_vec();
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn report(modifier: u8, keys: [u8; 6]) -> Vec<u8> {
        let mut v = vec![modifier, 0];
        v.extend_from_slice(&keys);
        v
    }

    #[test]
    fn decodes_hello_world() {
        // h e l l o (space) w o r l d — repeats suppressed
        let mut stream = Vec::new();
        for r in [
            [0x0b, 0, 0, 0, 0, 0],              // h
            [0x08, 0, 0, 0, 0, 0],              // e
            [0x0f, 0, 0, 0, 0, 0],              // l
            [0, 0, 0, 0, 0, 0],                 // release (l repeat guard)
            [0x0f, 0, 0, 0, 0, 0],              // l again
            [0x12, 0, 0, 0, 0, 0],              // o
            [0x2c, 0, 0, 0, 0, 0],              // space
            [0x1a, 0, 0, 0, 0, 0],              // w
            [0x12, 0, 0, 0, 0, 0],              // o
            [0x15, 0, 0, 0, 0, 0],              // r
            [0, 0, 0, 0, 0, 0],                 // release
            [0x0f, 0, 0, 0, 0, 0],              // l
            [0x07, 0, 0, 0, 0, 0],              // d
        ] {
            stream.extend(report(0, r));
        }
        let text = decode_keyboard_reports(&stream, 0, 8).unwrap();
        assert_eq!(text, "hello world");
    }

    #[test]
    fn shift_produces_uppercase() {
        let mut stream = Vec::new();
        stream.extend(report(0x02, [0x0b, 0, 0, 0, 0, 0])); // shift+h = H
        stream.extend(report(0, [0x08, 0, 0, 0, 0, 0])); // e
        let text = decode_keyboard_reports(&stream, 0, 8).unwrap();
        assert_eq!(text, "He");
    }

    #[test]
    fn number_row_symbols() {
        let mut stream = Vec::new();
        stream.extend(report(0, [0x20, 0, 0, 0, 0, 0])); // 3
        stream.extend(report(0x02, [0x1e, 0, 0, 0, 0, 0])); // shift+1 = !
        let text = decode_keyboard_reports(&stream, 0, 8).unwrap();
        assert_eq!(text, "3!");
    }

    #[test]
    fn stride_and_offset_slicing() {
        // simulate USBPcap-style packets: 4 junk bytes then the 8-byte report
        let mut stream = Vec::new();
        for r in [[0x17, 0, 0, 0, 0, 0], [0x08, 0, 0, 0, 0, 0]] {
            // 0x17 = t
            stream.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
            stream.extend(report(0, r));
        }
        let text = decode_keyboard_reports(&stream, 4, 12).unwrap();
        assert_eq!(text, "te");
    }
}
