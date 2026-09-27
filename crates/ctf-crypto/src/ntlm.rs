//! MD4 + NetNTLMv2 hash construction — Windows authentication forensics.
//!
//! CTF traffic challenges hand out a DCERPC/NTLMSSP capture; recovering the
//! plaintext requires building the NetNTLMv2 hash string for hashcat (`-m
//! 5600`). This module generates the hash from (user, domain, password,
//! challenge, blob) so a self-made capture can be validated offline, and so
//! candidate passwords recovered from a dictionary run can be re-verified.
//!
//! Provenance: NTLMv2 per the publicly documented NT LAN Manager
//! authentication protocol (MS-NLMP); MD4 per RFC 1320 (expired public spec).
//! Independent implementation on num-bigint-free plain u32 arithmetic; no
//! code copied. Cross-verified against the Python reference generator in
//! `work/y2025r/gen_ntlmv2.py` (华为杯 2025 EZ_ATEXEC).

use ctf_core::error::{CoreError, Result};

fn invalid(what: &str) -> CoreError {
    CoreError::Invalid(what.into())
}

/// MD4 message digest (RFC 1320)
pub fn md4(data: &[u8]) -> [u8; 16] {
    let mut h: [u32; 4] = [0x6745_2301, 0xefcd_ab89, 0x98ba_dcfe, 0x1032_5476];
    // padding: 0x80, zeros, 64-bit little-endian bit length
    let mut msg = data.to_vec();
    let bit_len = (data.len() as u64).wrapping_mul(8);
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_le_bytes());

    const R1: [u32; 4] = [3, 7, 11, 19];
    const R2: [u32; 4] = [3, 5, 9, 13];
    const R3: [u32; 4] = [3, 9, 11, 15];
    const ORDER2: [usize; 16] = [
        0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15,
    ];
    const ORDER3: [usize; 16] = [
        0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15,
    ];
    for chunk in msg.chunks(64) {
        let mut m = [0u32; 16];
        for (i, w) in chunk.chunks(4).enumerate() {
            m[i] = u32::from_le_bytes(w.try_into().unwrap());
        }
        let (mut a, mut b, mut c, mut d) = (h[0], h[1], h[2], h[3]);
        // round 1: F = (x&y)|(!x&z)
        for i in 0..16 {
            let f = (b & c) | ((!b) & d);
            let s = R1[i % 4];
            (a, b, c, d) = (d, a.wrapping_add(f).wrapping_add(m[i]).rotate_left(s), b, c);
        }
        // round 2: G = (x&y)|(x&z)|(y&z)
        for (i, mi) in ORDER2.iter().enumerate() {
            let g = (b & c) | (b & d) | (c & d);
            let s = R2[i % 4];
            (a, b, c, d) = (
                d,
                a.wrapping_add(g).wrapping_add(m[*mi]).wrapping_add(0x5a82_7999).rotate_left(s),
                b,
                c,
            );
        }
        // round 3: H = x^y^z
        for (i, mi) in ORDER3.iter().enumerate() {
            let hh = b ^ c ^ d;
            let s = R3[i % 4];
            (a, b, c, d) = (
                d,
                a.wrapping_add(hh).wrapping_add(m[*mi]).wrapping_add(0x6ed9_eba1).rotate_left(s),
                b,
                c,
            );
        }
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
    }
    let mut out = [0u8; 16];
    for (i, w) in h.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&w.to_le_bytes());
    }
    out
}

fn hmac_md5(key: &[u8], data: &[u8]) -> [u8; 16] {
    // block size 64; key longer than block → hash it first
    let md5 = |d: &[u8]| ctf_core::hash::md5(d);
    let mut k = [0u8; 64];
    if key.len() > 64 {
        let h = md5(key);
        k[..16].copy_from_slice(&h);
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let mut ipad = [0x36u8; 64];
    let mut opad = [0x5cu8; 64];
    for i in 0..64 {
        ipad[i] ^= k[i];
        opad[i] ^= k[i];
    }
    let inner = md5(&[ipad.as_slice(), data].concat());
    md5(&[opad.as_slice(), inner.as_slice()].concat())
}

/// UTF-16LE encode (no BOM)
pub fn utf16le(s: &str) -> Vec<u8> {
    s.encode_utf16().flat_map(|u| u.to_le_bytes()).collect()
}

/// NT password hash: MD4(UTF-16LE(password))
pub fn nt_hash(password: &str) -> [u8; 16] {
    md4(&utf16le(password))
}

/// NetNTLMv2 response pieces:
/// - ntlmv2_hash = HMAC-MD5(nt_hash, UTF16LE(upper(user) + domain))
/// - response    = HMAC-MD5(ntlmv2_hash, challenge || blob)
pub fn ntlmv2_response(
    user: &str,
    domain: &str,
    password: &str,
    server_challenge: [u8; 8],
    blob: &[u8],
) -> ([u8; 16], [u8; 16]) {
    let nth = nt_hash(password);
    let identity = utf16le(&format!("{}{}", user.to_uppercase(), domain));
    let ntlmv2_hash = hmac_md5(&nth, &identity);
    let mut msg = server_challenge.to_vec();
    msg.extend_from_slice(blob);
    let response = hmac_md5(&ntlmv2_hash, &msg);
    (ntlmv2_hash, response)
}

/// hashcat `-m 5600` (NetNTLMv2) line:
/// `user::domain:challenge:response_hex:blob_hex`
pub fn ntlmv2_hashcat_line(
    user: &str,
    domain: &str,
    password: &str,
    server_challenge: [u8; 8],
    blob: &[u8],
) -> Result<String> {
    if blob.is_empty() {
        return Err(invalid("empty NTLMv2 blob"));
    }
    let (_, response) = ntlmv2_response(user, domain, password, server_challenge, blob);
    let ch_hex: String = server_challenge.iter().map(|b| format!("{:02x}", b)).collect();
    let rsp_hex: String = response.iter().map(|b| format!("{:02x}", b)).collect();
    let blob_hex: String = blob.iter().map(|b| format!("{:02x}", b)).collect();
    Ok(format!("{}::{}:{}:{}:{}", user, domain, ch_hex, rsp_hex, blob_hex))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn md4_rfc1320_vectors() {
        // RFC 1320 test suite (B.1): MD4("") etc.
        let hx = |d: &[u8]| -> String { md4(d).iter().map(|b| format!("{:02x}", b)).collect() };
        assert_eq!(hx(b""), "31d6cfe0d16ae931b73c59d7e0c089c0");
        assert_eq!(hx(b"a"), "bde52cb31de33e46245e05fbdbd6fb24");
        assert_eq!(hx(b"abc"), "a448017aaf21d8525fc10ae87aa6729d");
        // 值由 pycryptodome Crypto.Hash.MD4 独立生成核对
        assert_eq!(
            hx(b"message digest"),
            "d9130a8164549fe818874806e1c7014b"
        );
        assert_eq!(
            hx(b"abcdefghijklmnopqrstuvwxyz"),
            "d79e1c308aa5bbcdeea8ed63df412da9"
        );
    }

    #[test]
    fn nt_hash_known_value() {
        // "password" 的 NT hash（广为人知的值，pycryptodome/官方一致）
        assert_eq!(
            nt_hash("password").iter().map(|b| format!("{:02x}", b)).collect::<String>(),
            "8846f7eaee8fb117ad06bdd830b7586c"
        );
    }

    #[test]
    fn ntlmv2_line_shape_and_roundtrip() {
        let blob: Vec<u8> = (0..40u8).collect(); // plausible client blob
        let line = ntlmv2_hashcat_line(
            "Administrator",
            "CORP",
            "123qwe!@#Q",
            [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08],
            &blob,
        )
        .expect("line");
        let parts: Vec<&str> = line.split(':').collect();
        // 格式 user::domain:challenge:response:blob —— user 后是双冒号
        assert_eq!(parts.len(), 6, "hashcat 5600 line has 6 fields: {}", line);
        assert_eq!(parts[0], "Administrator");
        assert_eq!(parts[1], "");
        assert_eq!(parts[2], "CORP");
        assert_eq!(parts[3], "0102030405060708"); // challenge
        assert_eq!(parts[4].len(), 32); // response HMAC
        assert_eq!(parts[5].len(), 80); // blob hex
        // determinism: same inputs → same line
        let line2 = ntlmv2_hashcat_line(
            "Administrator",
            "CORP",
            "123qwe!@#Q",
            [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08],
            &blob,
        )
        .unwrap();
        assert_eq!(line, line2);
        // different password → different response
        let other = ntlmv2_hashcat_line(
            "Administrator",
            "CORP",
            "wrongpass",
            [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08],
            &blob,
        )
        .unwrap();
        assert_ne!(line, other);
    }
}

#[cfg(test)]
mod md4_bisect_tests {
    use super::*;

    #[test]
    fn md4_lengths_0_to_20() {
        // 参考值由 pycryptodome Crypto.Hash.MD4 生成
        let refs: &[(usize, &[u8], &str)] = &[
            (0, b"", "31d6cfe0d16ae931b73c59d7e0c089c0"),
            (1, b"\x03", "7a71b83fcd0caf6fd77de7573b0d24ab"),
            (2, b"\x03\x0a", "c96ed8d30a5ba8758bf122c7485a42f2"),
            (3, b"\x03\x0a\x11", "380318863357e745939884f2f327f6c0"),
            (4, b"\x03\x0a\x11\x18", "4086d674e3cd6c42f1b314524f035adb"),
            (5, b"\x03\x0a\x11\x18\x1f", "88a373abc832bd0f66ce4ce0becf71e6"),
            (6, b"\x03\x0a\x11\x18\x1f&", "8763d2b2395b8c55be7262dc1bab32dd"),
            (7, b"\x03\x0a\x11\x18\x1f&-", "7e084aa2347cc66cd39c925c36427ef7"),
            (8, b"\x03\x0a\x11\x18\x1f&-4", "ca69300bbc916286c710482356a0aef0"),
            (9, b"\x03\x0a\x11\x18\x1f&-4;", "fd64ccf55293d9f883f27f96f1293084"),
            (10, b"\x03\x0a\x11\x18\x1f&-4;B", "40e776015435a99381e93fb521af0d15"),
            (11, b"\x03\x0a\x11\x18\x1f&-4;BI", "6a89a37577e8acfb40f074260dc16108"),
            (12, b"\x03\x0a\x11\x18\x1f&-4;BIP", "6469ea744bc58e80d8b766a9b4a4c68d"),
            (13, b"\x03\x0a\x11\x18\x1f&-4;BIPW", "a2fdbb9defa0106a4955c13ac69e4e2f"),
            (14, b"\x03\x0a\x11\x18\x1f&-4;BIPW^", "25cdb0c89d5fb77da7d99b2a1a190fb6"),
            (15, b"\x03\x0a\x11\x18\x1f&-4;BIPW^e", "e6037200f2e6102b04513a639e274fd9"),
            (16, b"\x03\x0a\x11\x18\x1f&-4;BIPW^el", "1ccbb995fec958da35ba6a8017207c7f"),
            (17, b"\x03\x0a\x11\x18\x1f&-4;BIPW^els", "08b64c63d7d6e6dc0d44d104651e2287"),
            (18, b"\x03\x0a\x11\x18\x1f&-4;BIPW^elsz", "3548f94aa48b549908125b8926ae649d"),
            (19, b"\x03\x0a\x11\x18\x1f&-4;BIPW^elsz\x81", "9b1b5485859260c7871b36bab46c0a47"),
            (20, b"\x03\x0a\x11\x18\x1f&-4;BIPW^elsz\x81\x88", "b2ae5938dbd476cea8069797b914d135"),
        ];
        for (len, msg, want) in refs {
            let hx: String = md4(msg).iter().map(|b| format!("{:02x}", b)).collect();
            assert_eq!(&hx, want, "md4 len {} mismatch", len);
        }
    }
}
