//! Minimal PEM/DER RSA public key parsing (SPKI "BEGIN PUBLIC KEY" and
//! PKCS#1 "BEGIN RSA PUBLIC KEY"). Enough for CTF key files — no x509
//! validation, no OID checking beyond presence.

use num_bigint::BigUint;
use num_traits::Zero;

use ctf_core::error::{CoreError, Result};

fn invalid(what: &str) -> CoreError {
    CoreError::Invalid(what.into())
}

/// One DER TLV: (tag, value bytes).
fn read_tlv<'a>(der: &'a [u8], pos: &mut usize) -> Result<(u8, &'a [u8])> {
    if *pos >= der.len() {
        return Err(invalid("der truncated (tag)"));
    }
    let tag = der[*pos];
    *pos += 1;
    if *pos >= der.len() {
        return Err(invalid("der truncated (len)"));
    }
    let mut len = der[*pos] as usize;
    *pos += 1;
    if len & 0x80 != 0 {
        let n = len & 0x7f;
        if n == 0 || n > 4 || *pos + n > der.len() {
            return Err(invalid("der bad long-form length"));
        }
        len = 0;
        for _ in 0..n {
            len = (len << 8) | der[*pos] as usize;
            *pos += 1;
        }
    }
    if *pos + len > der.len() {
        return Err(invalid("der truncated (value)"));
    }
    let value = &der[*pos..*pos + len];
    *pos += len;
    Ok((tag, value))
}

/// Parse PKCS#1 RSAPublicKey from a full SEQUENCE TLV: unwrap the outer
/// SEQ, then read the two INTEGER children from its value.
fn parse_pkcs1_value(rsa_seq_tlv: &[u8]) -> Result<(BigUint, BigUint)> {
    let mut outer = 0usize;
    let (t_seq, seq_value) = read_tlv(rsa_seq_tlv, &mut outer)?;
    if t_seq != 0x30 {
        return Err(invalid("expected RSAPublicKey SEQUENCE"));
    }
    let mut pos = 0usize;
    let (tag_n, n_bytes) = read_tlv(seq_value, &mut pos)?;
    if tag_n != 0x02 {
        return Err(invalid("expected INTEGER n"));
    }
    let (tag_e, e_bytes) = read_tlv(seq_value, &mut pos)?;
    if tag_e != 0x02 {
        return Err(invalid("expected INTEGER e"));
    }
    // strip the leading zero sign byte
    let n = BigUint::from_bytes_be(n_bytes.strip_prefix(&[0u8][..]).unwrap_or(n_bytes));
    let e = BigUint::from_bytes_be(e_bytes.strip_prefix(&[0u8][..]).unwrap_or(e_bytes));
    if n.is_zero() || e.is_zero() {
        return Err(invalid("zero modulus or exponent"));
    }
    Ok((n, e))
}

/// Parse a PEM body: returns (n, e) for PUBLIC KEY (SPKI) or RSA PUBLIC KEY
/// (PKCS#1) armors.
pub fn parse_rsa_public_key_pem(text: &str) -> Result<(BigUint, BigUint)> {
    let b64: String = text
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .map(|l| l.trim())
        .collect();
    let der = data_encoding::BASE64.decode(b64.as_bytes())
        .map_err(|e| invalid(&format!("pem base64: {e}")))?;
    if text.contains("RSA PUBLIC KEY") {
        return parse_pkcs1_value(&der);
    }
    // SPKI: SEQUENCE { SEQUENCE { alg... }, BITSTRING { ... } }
    // read_tlv advances past a whole TLV and returns its VALUE slice; nested
    // parsing re-cursors into the value with a local cursor.
    let mut pos = 0usize;
    let (t0, outer_value) = read_tlv(&der, &mut pos)?;
    if t0 != 0x30 {
        return Err(invalid("expected SPKI SEQUENCE"));
    }
    let mut inner = 0usize;
    let (t1, _alg) = read_tlv(outer_value, &mut inner)?;
    if t1 != 0x30 {
        return Err(invalid("expected alg SEQUENCE"));
    }
    let (t2, bitstring) = read_tlv(outer_value, &mut inner)?;
    if t2 != 0x03 {
        return Err(invalid("expected BIT STRING"));
    }
    if bitstring.first() != Some(&0x00) {
        return Err(invalid("bitstring missing leading zero"));
    }
    parse_pkcs1_value(&bitstring[1..])
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_PEM: &str = "-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDLKek9fMM7zfjYDxc4j/DY6GAJ
DvjTXp4ZVGhd8Bb2fC/3C/j8K+0Hs8k35VGL83Dy+Jnko2pKBgflD1HFMtZBRseJ
VCcV66xMb61f9c6JfAhFXp5mF/1ZH6t24MaTK6hJKXARnYWZBPl3SO09EoeV9RtO
wW2mHyfbGtnaoOQGMQIDAQAB
-----END PUBLIC KEY-----";

    #[test]
    fn parses_spki_pem() {
        let (n, e) = parse_rsa_public_key_pem(TEST_PEM).unwrap();
        assert_eq!(e, BigUint::from(65537u32));
        // n mod 1000 == 913 (vector generated with pycryptodome)
        assert_eq!(&n % BigUint::from(1000u32), BigUint::from(913u32));
        assert_eq!(n.bits(), 1024);
    }

    #[test]
    fn rejects_garbage() {
        assert!(parse_rsa_public_key_pem("-----BEGIN PUBLIC KEY-----\n!!!\n-----END PUBLIC KEY-----").is_err());
        assert!(parse_rsa_public_key_pem("").is_err());
    }
}
