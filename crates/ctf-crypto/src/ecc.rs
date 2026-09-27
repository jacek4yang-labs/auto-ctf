//! secp256k1 + Keccak-256 — the minimal Ethereum toolset for blockchain
//! forensics challenges (private key → public key → address derivation).
//!
//! 华为杯 2024 "广为人知的秘密" validated the full path: UTF-8 string bytes
//! used directly as the private key → address. Test vectors include the
//! canonical Keccak/empty-string and secp256k1 G-multiplication cases plus
//! that challenge instance.
//!
//! Provenance: Keccak-f1600 per the Keccak reference specification and
//! secp256k1 per "SEC 2: Recommended Elliptic Curve Domain Parameters" (public
//! standards); independent implementation on num-bigint, no code copied.

use num_bigint::BigInt;
use num_bigint::BigUint;
use num_traits::{One, Zero};
use num_traits::Num;

use ctf_core::error::{CoreError, Result};

fn invalid(what: &str) -> CoreError {
    CoreError::Invalid(what.into())
}

// ---------------------------------------------------------------------------
// Keccak-256 (original Keccak padding 0x01, NOT SHA3's 0x06)
// ---------------------------------------------------------------------------

const RC: [u64; 24] = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808a, 0x8000000080008000,
    0x000000000000808b, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008a, 0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
    0x000000008000808b, 0x800000000000008b, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800a, 0x800000008000000a,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
];

/// Keccak-f[1600] permutation on 25 u64 lanes
fn keccak_f(state: &mut [u64; 25]) {
    for round in RC.iter() {
        // θ
        let mut c = [0u64; 5];
        for x in 0..5 {
            c[x] = state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20];
        }
        for x in 0..5 {
            let d = c[(x + 4) % 5] ^ c[(x + 1) % 5].rotate_left(1);
            for y in 0..5 {
                state[x + 5 * y] ^= d;
            }
        }
        // ρ + π
        let (mut x, mut y) = (1usize, 0usize);
        let mut last = state[x + 5 * y];
        for t in 0..24 {
            let (nx, ny) = (y, (2 * x + 3 * y) % 5);
            let tmp = state[nx + 5 * ny];
            state[nx + 5 * ny] = last.rotate_left(((t + 1) * (t + 2) / 2) % 64);
            last = tmp;
            x = nx;
            y = ny;
        }
        // χ
        for y in 0..5 {
            let row: Vec<u64> = (0..5).map(|x| state[x + 5 * y]).collect();
            for x in 0..5 {
                state[x + 5 * y] = row[x] ^ ((!row[(x + 1) % 5]) & row[(x + 2) % 5]);
            }
        }
        // ι
        state[0] ^= *round;
    }
}

/// Keccak-256 digest (Ethereum flavor — padding byte 0x01)
pub fn keccak256(data: &[u8]) -> [u8; 32] {
    const RATE: usize = 136;
    let mut state = [0u64; 25];
    let mut buf = data.to_vec();
    // pad10*1 with the Keccak domain byte 0x01
    buf.push(0x01);
    while buf.len() % RATE != 0 {
        buf.push(0x00);
    }
    *buf.last_mut().unwrap() |= 0x80;
    for block in buf.chunks(RATE) {
        for (i, lane) in block.chunks(8).enumerate() {
            let mut b = [0u8; 8];
            b.copy_from_slice(lane);
            state[i] ^= u64::from_le_bytes(b);
        }
        keccak_f(&mut state);
    }
    let mut out = [0u8; 32];
    for (i, b) in out.iter_mut().enumerate() {
        *b = (state[i / 8] >> (8 * (i % 8))) as u8;
    }
    out
}

pub fn keccak256_hex(data: &[u8]) -> String {
    keccak256(data).iter().map(|b| format!("{:02x}", b)).collect()
}

// ---------------------------------------------------------------------------
// secp256k1 (affine, double-and-add — fine for CTF-scale single derivations)
// ---------------------------------------------------------------------------

struct Pt(Option<(BigUint, BigUint)>); // None = infinity

const P_HEX: &str = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F";
const GX_HEX: &str = "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798";
const GY_HEX: &str = "483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8";
const N_HEX: &str = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141";

fn mod_p(v: &BigUint, p: &BigUint) -> BigUint {
    v % p
}

fn point_add(a: &Pt, b: &Pt, p: &BigUint) -> Pt {
    let (ax, ay) = match &a.0 {
        Some(v) => v,
        None => return Pt(b.0.clone()),
    };
    let (bx, by) = match &b.0 {
        Some(v) => v,
        None => return Pt(a.0.clone()),
    };
    fn sub_mod(a: &BigUint, b: &BigUint, p: &BigUint) -> BigUint {
        (a % p + p - b % p) % p
    }
    if ax == bx {
        if ay != by || ay.is_zero() {
            // P + (−P) = 无穷远
            return Pt(None);
        }
        // else: 相同点 → 走下方 doubling
    } else {
        // 通用加法: λ = (y2−y1)/(x2−x1)
        let num = sub_mod(by, ay, p);
        let den = sub_mod(bx, ax, p);
        let den_inv = ctf_core::num::mod_inverse(&den, p).unwrap_or_else(|_| BigUint::zero());
        let lambda = mod_p(&(num * den_inv), p);
        let x3 = sub_mod(&sub_mod(&(&lambda * &lambda), ax, p), bx, p);
        let y3 = sub_mod(&(&lambda * sub_mod(ax, &x3, p)), ay, p);
        return Pt(Some((x3, y3)));
    }
    if ax == bx && ay == by {
        // doubling: λ = 3x²·(2y)⁻¹ mod p
        let three = BigUint::from(3u32);
        let two = BigUint::from(2u32);
        let num = mod_p(&(three * ax * ax), p);
        let den = mod_p(&(two * ay), p);
        let den_inv = ctf_core::num::mod_inverse(&den, p).unwrap_or_else(|_| BigUint::zero());
        let lambda = mod_p(&(num * den_inv), p);
        // x3 = λ² − 2x ; y3 = λ(x − x3) − y
        let x3 = sub_mod(&sub_mod(&(&lambda * &lambda), ax, p), ax, p);
        let y3 = sub_mod(&(&lambda * sub_mod(ax, &x3, p)), ay, p);
        return Pt(Some((x3, y3)));
    }
    // general addition: λ = (y2−y1)/(x2−x1)
    let num = sub_mod(by, ay, p);
    let den = sub_mod(bx, ax, p);
    let den_inv = ctf_core::num::mod_inverse(&den, p).unwrap_or_else(|_| BigUint::zero());
    let lambda = mod_p(&(num * den_inv), p);
    let x3 = sub_mod(&sub_mod(&(&lambda * &lambda), ax, p), bx, p);
    let y3 = sub_mod(&(&lambda * sub_mod(ax, &x3, p)), ay, p);
    Pt(Some((x3, y3)))
}

/// k·G on secp256k1 → (x, y) uncompressed coordinates
pub fn secp256k1_pubkey(k: &BigUint) -> Result<(BigUint, BigUint)> {
    if k.is_zero() {
        return Err(invalid("zero private key"));
    }
    let p = <BigUint as Num>::from_str_radix(P_HEX, 16).map_err(|_| invalid("bad P"))?;
    let gx = <BigUint as Num>::from_str_radix(GX_HEX, 16).map_err(|_| invalid("bad Gx"))?;
    let gy = <BigUint as Num>::from_str_radix(GY_HEX, 16).map_err(|_| invalid("bad Gy"))?;
    let order = <BigUint as Num>::from_str_radix(N_HEX, 16).map_err(|_| invalid("bad N"))?;
    let k = k % &order;
    if k.is_zero() {
        return Err(invalid("k ≡ 0 mod n"));
    }
    let mut result = Pt(None); // infinity
    let mut addend = Pt(Some((gx, gy)));
    let kk = k.clone();
    let mut bits: Vec<bool> = Vec::new();
    let mut tmp = kk;
    while tmp > BigUint::zero() {
        bits.push(tmp.bit(0));
        tmp >>= 1;
    }
    for bit in bits {
        if bit {
            result = point_add(&result, &addend, &p);
        }
        addend = point_add(&addend, &addend, &p);
    }
    result.0.ok_or_else(|| invalid("point at infinity"))
}

/// Ethereum address: keccak256(uncompressed pubkey[1..65]) last 20 bytes,
/// lowercase hex with 0x prefix
pub fn eth_address(priv_key_hex_or_bytes: &str) -> Result<String> {
    // accepts raw 32-byte hex OR raw bytes-as-hex of arbitrary length < 32
    let hex: String = priv_key_hex_or_bytes.trim().to_string();
    let hex = hex.strip_prefix("0x").unwrap_or(&hex);
    let k = BigUint::from_str_radix(hex, 16).map_err(|_| invalid("bad private key hex"))?;
    let (x, y) = secp256k1_pubkey(&k)?;
    let mut buf = Vec::with_capacity(64);
    let xb = x.to_bytes_be();
    let yb = y.to_bytes_be();
    for _ in 0..(32 - xb.len()) {
        buf.push(0);
    }
    buf.extend(xb);
    for _ in 0..(32 - yb.len()) {
        buf.push(0);
    }
    buf.extend(yb);
    let h = keccak256(&buf);
    let addr: String = h[12..32].iter().map(|b| format!("{:02x}", b)).collect();
    Ok(format!("0x{}", addr))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keccak_known_vectors() {
        assert_eq!(
            keccak256_hex(b""),
            "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
        );
        assert_eq!(
            keccak256_hex(b"abc"),
            "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45"
        );
    }

    #[test]
    fn secp256k1_g_multiplication() {
        // 1·G = G
        let (x, y) = secp256k1_pubkey(&BigUint::one()).unwrap();
        assert_eq!(x.to_str_radix(16).to_uppercase(), GX_HEX);
        assert_eq!(y.to_str_radix(16).to_uppercase(), GY_HEX);
        // 2·G (well-known coordinates)
        let (x2, _) = secp256k1_pubkey(&BigUint::from(2u32)).unwrap();
        assert_eq!(
            x2.to_str_radix(16).to_uppercase(),
            "C6047F9441ED7D6D3045406E95C07CD85C778E4B8CEF3CA7ABAC09B95C709EE5"
        );
    }

    #[test]
    fn eth_address_huawei_challenge() {
        // 华为杯 2024 "广为人知的秘密": UTF-8 bytes of the challenge sentence
        // used directly as the private key → address 0x34c5a8Cb…E186
        let key_text = "秘密吗?藏在Goerli网络里.";
        let key_hex: String = key_text.as_bytes().iter().map(|b| format!("{:02x}", b)).collect();
        let addr = eth_address(&key_hex).expect("address");
        assert_eq!(addr, "0x34c5a8cbe765454a43f515cfe94928d26c2fe186");
    }
}

#[cfg(test)]
mod ecc_debug_tests {
    use super::*;
    use num_traits::Num;

    #[test]
    fn probe_double_g() {
        let p = <BigUint as Num>::from_str_radix(P_HEX, 16).unwrap();
        let gx = <BigUint as Num>::from_str_radix(GX_HEX, 16).unwrap();
        let gy = <BigUint as Num>::from_str_radix(GY_HEX, 16).unwrap();
        let a = Pt(Some((gx.clone(), gy.clone())));
        let b = Pt(Some((gx.clone(), gy.clone())));
        let r = point_add(&a, &b, &p);
        match r.0 {
            Some((x, y)) => eprintln!("[ecc] 2G = ({:#x}, {:#x})", x, y),
            None => eprintln!("[ecc] 2G = infinity"),
        }
        // 再打印公式中间值
        let three = BigUint::from(3u32);
        let two = BigUint::from(2u32);
        let num = mod_p(&(three * &gx * &gx), &p);
        let den = mod_p(&(two * &gy), &p);
        let dinv = ctf_core::num::mod_inverse(&den, &p).unwrap();
        let lambda = mod_p(&(num * &dinv), &p);
        eprintln!("[ecc] den={:#x} dinv={:#x} lambda={:#x}", den, dinv, lambda);
    }
}
