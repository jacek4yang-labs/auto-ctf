//! Classic ciphers and byte transforms from the encoding decision tree.

use ctf_core::error::{CoreError, Result};

fn invalid(what: &str) -> CoreError {
    CoreError::Invalid(what.into())
}

/// ROT-n over ASCII letters (case preserving); other bytes unchanged.
pub fn rot_n(data: &[u8], n: i32) -> Vec<u8> {
    let n = n.rem_euclid(26);
    data.iter()
        .map(|&b| match b {
            b'a'..=b'z' => b'a' + (b - b'a' + n as u8) % 26,
            b'A'..=b'Z' => b'A' + (b - b'A' + n as u8) % 26,
            _ => b,
        })
        .collect()
}

/// Brute-force all 26 rotations; returns (shift, text) pairs.
pub fn rot_brute(data: &[u8]) -> Vec<(i32, String)> {
    (0..26)
        .map(|n| (n, String::from_utf8_lossy(&rot_n(data, n)).into_owned()))
        .collect()
}

/// Reverse the whole byte string.
pub fn reverse_bytes(data: &[u8]) -> Vec<u8> {
    let mut v = data.to_vec();
    v.reverse();
    v
}

/// Swap adjacent byte pairs (used by the 泥坑 collector multi-layer decode).
pub fn swap_adjacent(data: &[u8]) -> Vec<u8> {
    let mut v = data.to_vec();
    for i in (0..v.len() - v.len() % 2).step_by(2) {
        v.swap(i, i + 1);
    }
    v
}

/// Reverse each line independently (common multi-layer variant).
pub fn reverse_lines(data: &str) -> String {
    data.lines()
        .map(|l| l.chars().rev().collect::<String>())
        .collect::<Vec<_>>()
        .join("\n")
}

/// Vigenere over ASCII letters with an alphabetic key.
pub fn vigenere(data: &[u8], key: &str, decrypt: bool) -> Result<Vec<u8>> {
    if key.is_empty() || !key.bytes().all(|b| b.is_ascii_alphabetic()) {
        return Err(invalid("vigenere key must be alphabetic and non-empty"));
    }
    let shifts: Vec<i32> = key
        .bytes()
        .map(|b| (b.to_ascii_lowercase() - b'a') as i32)
        .collect();
    let mut ki = 0usize;
    Ok(data
        .iter()
        .map(|&b| {
            let out = match b {
                b'a'..=b'z' => {
                    let s = shifts[ki % shifts.len()];
                    ki += 1;
                    b'a' + (b - b'a' + if decrypt { 26 - s as u8 } else { s as u8 }) % 26
                }
                b'A'..=b'Z' => {
                    let s = shifts[ki % shifts.len()];
                    ki += 1;
                    b'A' + (b - b'A' + if decrypt { 26 - s as u8 } else { s as u8 }) % 26
                }
                _ => b,
            };
            out
        })
        .collect())
}

/// Hill cipher decrypt on the letter stream (non-letters pass through).
/// `key_flat` is row-major size×size over Z/modulus.
pub fn hill_decrypt(
    ct: &str,
    key_flat: &[i64],
    size: usize,
    modulus: i64,
) -> Result<String> {
    use ctf_core::matrix::Matrix;
    let key = Matrix::new(size, modulus, key_flat).ok_or_else(|| {
        invalid("hill key size mismatch")
    })?;
    let inv = key.inverse().ok_or_else(|| invalid("hill key not invertible"))?;
    let letters: Vec<char> = ct
        .chars()
        .map(|c| if c.is_ascii_alphabetic() { c.to_ascii_lowercase() } else { c })
        .collect();
    let mut out = String::new();
    let mut block = vec![0i64; size];
    let mut filled = 0usize;
    for c in letters {
        if !c.is_ascii_lowercase() {
            out.push(c);
            continue;
        }
        block[filled] = c as i64 - 'a' as i64;
        filled += 1;
        if filled == size {
            let dec = inv.mul_vec(&block).ok_or_else(|| invalid("hill mul failed"))?;
            for v in dec {
                out.push(char::from_u32('a' as u32 + v as u32).unwrap_or('?'));
            }
            filled = 0;
        }
    }
    Ok(out)
}

/// Brute-force all invertible 2x2 Hill keys mod 26 on the letter stream.
/// Returns (key-flat, plaintext) for hits containing any needle.
pub fn hill_brute_2x2(ct: &str, needles: &[&str]) -> Vec<([i64; 4], String)> {
    let letters: Vec<i64> = ct
        .chars()
        .filter(|c| c.is_ascii_alphabetic())
        .map(|c| c.to_ascii_lowercase() as i64 - 'a' as i64)
        .collect();
    let mut hits = Vec::new();
    for a in 0..26i64 {
        for b in 0..26i64 {
            for c in 0..26i64 {
                for d in 0..26i64 {
                    let det = (a * d - b * c).rem_euclid(26);
                    if ctf_core::num::mod_inverse_small(det, 26).is_none() {
                        continue;
                    }
                    let inv = match ctf_core::matrix::Matrix::new(2, 26, &[a, b, c, d])
                        .and_then(|m| m.inverse())
                    {
                        Some(iv) => iv,
                        None => continue,
                    };
                    let mut plain = String::new();
                    for chunk in letters.chunks(2) {
                        let v = if chunk.len() == 2 {
                            [chunk[0], chunk[1]]
                        } else {
                            [chunk[0], 0]
                        };
                        let dec = inv.mul_vec(&v).unwrap();
                        for x in dec.iter().take(chunk.len()) {
                            plain.push(char::from_u32('a' as u32 + *x as u32).unwrap_or('?'));
                        }
                    }
                    let low = plain.to_lowercase();
                    if needles.iter().any(|n| low.contains(n)) {
                        hits.push(([a, b, c, d], plain));
                    }
                }
            }
        }
    }
    hits
}

/// Playfair decrypt with a 5x5 square (i/j merged) built from the key.
pub fn playfair_decrypt(ct: &str, key: &str) -> Result<String> {
    // build the square
    let mut square = Vec::with_capacity(25);
    let mut seen = std::collections::BTreeSet::new();
    for c in key.chars().chain('a'..='z') {
        let lc = c.to_ascii_lowercase();
        let c = if lc == 'j' { 'i' } else { lc };
        if !c.is_ascii_lowercase() || c == 'j' {
            continue;
        }
        if seen.insert(c) {
            square.push(c);
        }
        if square.len() == 25 {
            break;
        }
    }
    if square.len() < 25 {
        return Err(invalid("playfair square incomplete"));
    }
    let pos = |c: char| -> Option<(usize, usize)> {
        let c = if c == 'j' { 'i' } else { c };
        let idx = square.iter().position(|&s| s == c)?;
        Some((idx / 5, idx % 5))
    };
    let letters: Vec<char> = ct
        .chars()
        .filter(|c| c.is_ascii_alphabetic())
        .map(|c| {
            let lc = c.to_ascii_lowercase();
            if lc == 'j' { 'i' } else { lc }
        })
        .collect();
    if letters.len() % 2 != 0 {
        return Err(invalid("playfair ciphertext must have even length"));
    }
    let mut out = String::new();
    for pair in letters.chunks(2) {
        let (r1, c1) = pos(pair[0]).ok_or_else(|| invalid("letter missing"))?;
        let (r2, c2) = pos(pair[1]).ok_or_else(|| invalid("letter missing"))?;
        if r1 == r2 {
            out.push(square[r1 * 5 + (c1 + 4) % 5]);
            out.push(square[r2 * 5 + (c2 + 4) % 5]);
        } else if c1 == c2 {
            out.push(square[((r1 + 4) % 5) * 5 + c1]);
            out.push(square[((r2 + 4) % 5) * 5 + c2]);
        } else {
            out.push(square[r1 * 5 + c2]);
            out.push(square[r2 * 5 + c1]);
        }
    }
    Ok(out)
}

/// Morse decode over `. - / ` and whitespace; unknown tokens map to '?'.
pub fn morse_decode(data: &str) -> String {
    const TABLE: &[(&str, &str)] = &[
        (".-", "A"), ("-...", "B"), ("-.-.", "C"), ("-..", "D"), (".", "E"),
        ("..-.", "F"), ("--.", "G"), ("....", "H"), ("..", "I"), (".---", "J"),
        ("-.-", "K"), (".-..", "L"), ("--", "M"), ("-.", "N"), ("---", "O"),
        (".--.", "P"), ("--.-", "Q"), (".-.", "R"), ("...", "S"), ("-", "T"),
        ("..-", "U"), ("...-", "V"), (".--", "W"), ("-..-", "X"), ("-.--", "Y"),
        ("--..", "Z"),
        ("-----", "0"), (".----", "1"), ("..---", "2"), ("...--", "3"),
        ("....-", "4"), (".....", "5"), ("-....", "6"), ("--...", "7"),
        ("---..", "8"), ("----.", "9"),
    ];
    data.split('/')
        .map(|word| {
            word.split_whitespace()
                .map(|token| {
                    TABLE
                        .iter()
                        .find(|(code, _)| *code == token)
                        .map(|(_, ch)| *ch)
                        .unwrap_or("?")
                })
                .collect::<String>()
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// Affine cipher decrypt over ASCII letters: D(x) = a^-1 * (x - b) mod 26.
pub fn affine_decrypt(data: &str, a: u8, b: u8) -> Result<String> {
    // modular inverse of a mod 26 by trial (26 is tiny)
    let a = (a % 26) as usize;
    let inv = (1..26usize).find(|&i| (i * a) % 26 == 1).ok_or_else(|| {
        invalid("affine key a has no inverse mod 26")
    })?;
    let b = (b % 26) as usize;
    Ok(data
        .chars()
        .map(|c| match c {
            'a'..='z' => {
                let x = (c as usize - 'a' as usize + 26 - b) % 26;
                char::from_u32(((inv * x) % 26) as u32 + 'a' as u32).unwrap()
            }
            'A'..='Z' => {
                let x = (c as usize - 'A' as usize + 26 - b) % 26;
                char::from_u32(((inv * x) % 26) as u32 + 'A' as u32).unwrap()
            }
            other => other,
        })
        .collect())
}

/// Caesar solve: try all 25 shifts, return the first text containing a
/// flag-shaped brace (flag{, ctf{, dasctf{ case-insensitive).
pub fn caesar_solve(data: &str) -> Option<(i32, String)> {
    for shift in 1..26 {
        let cand = String::from_utf8_lossy(&rot_n(data.as_bytes(), shift)).into_owned();
        let low = cand.to_lowercase();
        for prefix in ["flag{", "ctf{", "dasctf{", "nctf{", "sctf{"] {
            if low.contains(prefix) {
                return Some((shift, cand));
            }
        }
    }
    None
}

/// QWERTY-keyboard-order substitution: keyboard position i maps to letter i
/// ("qwertyuiopasdfghjklzxcvbnm" -> "abc...z"). "ysqu" -> "flag".
pub fn qwe_keyboard_decrypt(data: &str) -> String {
    const KB: &[u8] = b"qwertyuiopasdfghjklzxcvbnm";
    data.chars()
        .map(|c| match c {
            'a'..='z' => {
                let pos = KB.iter().position(|&k| k as char == c.to_ascii_lowercase()).unwrap_or(0);
                char::from_u32('a' as u32 + pos as u32).unwrap_or(c)
            }
            'A'..='Z' => {
                let pos = KB.iter().position(|&k| k as char == c.to_ascii_lowercase()).unwrap_or(0);
                char::from_u32('A' as u32 + pos as u32).unwrap_or(c)
            }
            other => other,
        })
        .collect()
}

/// Old phone multi-tap decode: space-separated pairs (key, presses), e.g.
/// "42" -> key 4 "GHI" pressed twice -> H.
pub fn phone_decode(data: &str) -> String {
    const KEYS: [&str; 10] = ["", "", "ABC", "DEF", "GHI", "JKL", "MNO", "PQRS", "TUV", "WXYZ"];
    data.split_whitespace()
        .filter_map(|pair| {
            let b = pair.as_bytes();
            if b.len() != 2 || !b.iter().all(|c| c.is_ascii_digit()) {
                return None;
            }
            let key = (b[0] - b'0') as usize;
            let presses = (b[1] - b'0') as usize;
            let letters = KEYS.get(key)?;
            if letters.is_empty() || presses == 0 {
                return None;
            }
            letters.bytes().nth((presses - 1) % letters.len()).map(|c| c as char)
        })
        .collect()
}

/// Autokey cipher decrypt: keystream = keyword + recovered plaintext.
pub fn autokey_decrypt(ct: &str, key: &str) -> Result<String> {
    if key.bytes().any(|b| !b.is_ascii_alphabetic()) || key.is_empty() {
        return Err(invalid("autokey key must be alphabetic"));
    }
    let mut ks: Vec<u8> = key.bytes().map(|b| b.to_ascii_lowercase()).collect();
    let mut plain = Vec::new();
    for c in ct.chars() {
        if !c.is_ascii_alphabetic() {
            continue;
        }
        let ci = c.to_ascii_lowercase() as u8 - b'a';
        let k = ks[plain.len()];
        let pi = (ci + 26 - (k - b'a')) % 26;
        let pc = b'a' + pi;
        ks.push(pc);
        plain.push(pc);
    }
    Ok(String::from_utf8(plain).unwrap_or_default())
}

/// Rail-fence (栅栏) decrypt: ct is rails concatenated rows of the zigzag.
pub fn rail_fence_decrypt(ct: &str, rails: usize) -> String {
    if rails < 2 {
        return ct.to_string();
    }
    let n = ct.len();
    let mut rail_of = Vec::with_capacity(n);
    let mut r = 0usize;
    let mut down = false;
    for _ in 0..n {
        rail_of.push(r);
        if r == 0 {
            down = true;
        } else if r == rails - 1 {
            down = false;
        }
        r = if down { r + 1 } else { r - 1 };
    }
    let bytes = ct.as_bytes();
    let mut counts = vec![0usize; rails];
    for &r in &rail_of {
        counts[r] += 1;
    }
    let mut offsets = vec![0usize; rails];
    let mut acc = 0usize;
    for i in 0..rails {
        offsets[i] = acc;
        acc += counts[i];
    }
    let mut plain = vec![0u8; n];
    for (i, &r) in rail_of.iter().enumerate() {
        plain[i] = bytes[offsets[r]];
        offsets[r] += 1;
    }
    String::from_utf8_lossy(&plain).into_owned()
}

/// Route (曲路) cipher decode: letters fill a rows×cols grid column-major
/// (as the ciphertext words suggest) and are read back in the four traversal
/// variants; returns all candidates.
pub fn route_decrypt(ct: &str, rows: usize, cols: usize) -> Vec<String> {
    let letters: Vec<u8> = ct.chars().filter(|c| c.is_ascii_alphabetic()).map(|c| c as u8).collect();
    if letters.len() != rows * cols || rows == 0 || cols == 0 {
        return vec![];
    }
    // grid[col-major fill]: grid[r][c] = letters[c * rows + r]
    let at = |r: usize, c: usize| letters[c * rows + r] as char;
    let mut out = Vec::new();
    // row-major straight
    let mut s = String::new();
    for r in 0..rows {
        for c in 0..cols {
            s.push(at(r, c));
        }
    }
    out.push(s);
    // row-major boustrophedon (winding path, odd rows reversed)
    let mut s = String::new();
    for r in 0..rows {
        for c in 0..cols {
            let cc = if r % 2 == 0 { c } else { cols - 1 - c };
            s.push(at(r, cc));
        }
    }
    out.push(s);
    // column-major boustrophedon
    let mut s = String::new();
    for c in 0..cols {
        for r in 0..rows {
            let rr = if c % 2 == 0 { r } else { rows - 1 - r };
            s.push(at(rr, c));
        }
    }
    out.push(s);
    out
}

#[cfg(test)]
mod hill_tests {
    use super::*;

    #[test]
    fn hill_brute_finds_known_key() {
        // encrypt "utflagdngerouscpher" with key [[1,2],[3,3]] (det -3 = 23 inv)
        let key = [1i64, 2, 3, 3];
        let plain = "utflagdngerouscpher";
        let letters: Vec<i64> = plain.bytes().map(|b| (b - b'a') as i64).collect();
        let mut enc = Vec::new();
        for chunk in letters.chunks(2) {
            let v = if chunk.len() == 2 { [chunk[0], chunk[1]] } else { [chunk[0], 0] };
            enc.push((key[0] * v[0] + key[1] * v[1]).rem_euclid(26));
            enc.push((key[2] * v[0] + key[3] * v[1]).rem_euclid(26));
        }
        let ct: String = enc.iter().map(|&x| char::from_u32('a' as u32 + x as u32).unwrap()).collect();
        let hits = hill_brute_2x2(&ct, &["utflag"]);
        assert!(
            hits.iter()
                .any(|(k, p)| k == &key && p.starts_with(plain)),
            "hits: {:?}",
            hits
        );
    }

    #[test]
    fn hill_decrypt_matches_reference() {
        // known example: "act" encrypted with the wikipedia key = "POH"
        let key = [6i64, 24, 1, 13, 16, 10, 20, 17, 15];
        let dec = hill_decrypt("POH", &key, 3, 26).unwrap();
        assert_eq!(dec, "act");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rot_roundtrip() {
        assert_eq!(rot_n(b"Hello, World!", 13), b"Uryyb, Jbeyq!");
        assert_eq!(rot_n(&rot_n(b"Abc", 5), 21), b"Abc");
        assert_eq!(rot_brute(b"Ifmmp")[25].1, "Hello");
    }

    #[test]
    fn transforms() {
        assert_eq!(reverse_bytes(b"1234"), b"4321");
        assert_eq!(swap_adjacent(b"1234567"), b"2143657");
        assert_eq!(reverse_lines("abc\nde"), "cba\ned");
    }

    #[test]
    fn morse_decodes() {
        assert_eq!(morse_decode(".. .-- .- -. - - --- --. . - ..-. .-.. .- --."), "IWANTTOGETFLAG");
        assert_eq!(morse_decode(".... .. / - .... . .-. ."), "HI THERE");
    }

    #[test]
    fn affine_decrypts() {
        // E(x) = 3x + 11 over letters: "affine" -> "ly laajyx" per challenge
        let enc = affine_decrypt("ly laajyx rjegxk", 3, 11).unwrap();
        assert_eq!(enc, "an affine cipher");
        assert!(affine_decrypt("x", 2, 1).is_err()); // a=2 not invertible
    }

    #[test]
    fn qwe_keyboard_maps_flag() {
        assert_eq!(qwe_keyboard_decrypt("ysqu"), "flag");
        assert_eq!(qwe_keyboard_decrypt("itssg"), "hello");
        assert_eq!(qwe_keyboard_decrypt("rql"), "das");
    }

    #[test]
    fn phone_decode_pairs() {
        assert_eq!(phone_decode("42 74 43 91 23 33 43 41"), "HSIWCFIG");
    }

    #[test]
    fn rail_fence_roundtrip() {
        // encrypt by hand: plain "abcdefgh" rails 3 -> rail0 "ae", rail1 "bdfh", rail2 "cg"
        let ct = format!("{}{}{}", "ae", "bdfh", "cg");
        assert_eq!(rail_fence_decrypt(&ct, 3), "abcdefgh");
    }

    #[test]
    fn route_decrypt_shapes() {
        let cands = route_decrypt("rirts ecuie twceh pvhta", 5, 4);
        assert_eq!(cands.len(), 3);
        assert!(cands[0].starts_with("retp")); // row-major from column fill
    }

    #[test]
    fn autokey_roundtrip() {
        // encrypt "helloworld" with key "pass" by hand:
        // keystream p,a,s,s,h,e,l,l,o ; plain h->w? compute via decrypt inverse
        // use decrypt on a self-consistent pair instead:
        let ct = "zsinhodj"; // encrypt("iloveyou","key") by hand is complex; verify decrypt is deterministic
        let p1 = autokey_decrypt(ct, "key").unwrap();
        let p2 = autokey_decrypt(ct, "key").unwrap();
        assert_eq!(p1, p2);
        // real relation: encrypt(plain,key) then decrypt -> plain
        // encrypt: c_i = p_i + k_i where ks = key ++ plain
        let plain = b"attackatdawn";
        let mut ks: Vec<u8> = b"queen".to_vec();
        let mut enc = Vec::new();
        for &pc in plain {
            let pi = pc - b'a';
            let k = ks[enc.len()];
            enc.push(b'a' + (pi + (k - b'a')) % 26);
            ks.push(pc);
        }
        let dec = autokey_decrypt(std::str::from_utf8(&enc).unwrap(), "queen").unwrap();
        assert_eq!(dec, "attackatdawn");
    }

    #[test]
    fn vigenere_roundtrip() {
        let enc = vigenere(b"ATTACKATDAWN", "LEMON", false).unwrap();
        assert_eq!(enc, b"LXFOPVEFRNHR");
        assert_eq!(vigenere(&enc, "LEMON", true).unwrap(), b"ATTACKATDAWN");
        assert!(vigenere(b"x", "a1", false).is_err());
    }
}
