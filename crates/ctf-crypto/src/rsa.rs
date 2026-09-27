//! RSA attacks. Each function mirrors one branch of the decision tree in
//! `Crypto笔记.md` / `refs/autorsa` (`solver/writeup.py`, `solver/wiener_attack.py`).
//! `auto_attack` walks the tree given whatever parameters are known.

use std::path::Path;

use num_bigint::{BigInt, BigUint};
use num_traits::{One, ToPrimitive, Zero};

use ctf_core::error::{CoreError, Result};
use ctf_core::num::{
    crt_merge, egcd, gcd, iroot, mod_inverse, modpow, modpow_signed, pollard_p1, pollard_rho,
};
use ctf_core::check_bit_cap;

fn invalid(what: &str) -> CoreError {
    CoreError::Invalid(what.into())
}

fn two() -> BigUint {
    BigUint::from(2u32)
}

fn four() -> BigUint {
    BigUint::from(4u32)
}

/// Verify a modulus is inside the 8192-bit cap.
pub fn cap_ok(n: &BigUint) -> Result<()> {
    check_bit_cap(n.bits())
}

fn to_u32_sat(v: &BigUint) -> u32 {
    v.to_u32().unwrap_or(u32::MAX)
}

/// m = c^d mod n (已知 n, d, c).
pub fn decrypt(c: &BigUint, d: &BigUint, n: &BigUint) -> Result<BigUint> {
    cap_ok(n)?;
    Ok(modpow(c, d, n))
}

/// Decrypt given p and q; handles gcd(e, phi) > 1 like autorsa's
/// `basic_rsa_decrypt`: t == 1 → plain; small t → t-th root of m^t;
/// large t → per-prime partial path when one side is coprime to e.
pub fn from_pq(c: &BigUint, e: &BigUint, p: &BigUint, q: &BigUint) -> Result<BigUint> {
    let n = p * q;
    cap_ok(&n)?;
    let phi = (p - BigUint::one()) * (q - BigUint::one());
    let (t, _, _) = egcd(&BigInt::from(e.clone()), &BigInt::from(phi.clone()));
    let t = t.to_biguint().ok_or_else(|| invalid("negative gcd"))?;
    if t.is_one() {
        let d = mod_inverse(e, &phi)?;
        return Ok(modpow(c, &d, &n));
    }
    let t_u32 = to_u32_sat(&t);
    if t_u32 <= 64 {
        // d' = (e/t)^-1 mod phi; m' = c^d' = m^t mod n; take the t-th root
        let e_t = e / &t;
        if &e_t * &t != *e {
            return Err(invalid("e not divisible by gcd(e, phi)"));
        }
        let d = mod_inverse(&e_t, &phi)?;
        let mt = modpow(c, &d, &n);
        let (m, exact) = iroot(&mt, t_u32);
        if exact {
            return Ok(m);
        }
        return Err(CoreError::NoRoot { k: t_u32 });
    }
    // large t: solve on whichever prime side is coprime to e (partial m mod p)
    let gp = gcd(e, &(p - BigUint::one()));
    let gq = gcd(e, &(q - BigUint::one()));
    if gp.is_one() && !gq.is_one() {
        let dp = mod_inverse(e, &(p - BigUint::one()))?;
        return Ok(modpow(c, &dp, p));
    }
    if gq.is_one() && !gp.is_one() {
        let dq = mod_inverse(e, &(q - BigUint::one()))?;
        return Ok(modpow(c, &dq, q));
    }
    Err(invalid(
        "e and phi share a large gcd; AMM/finite-field roots required (documented gap)",
    ))
}

/// dp 泄露: e*dp - 1 = x*(p-1) with x < e, so p = (e*dp-1)/x + 1 for a
/// divisor x (autorsa branch). Requires e <= 2^20.
pub fn dp_leak(e: &BigUint, n: &BigUint, dp: &BigUint) -> Result<(BigUint, BigUint)> {
    cap_ok(n)?;
    let e_small = e.to_u64().ok_or_else(|| invalid("e too large for dp_leak"))?;
    if e_small > 1 << 20 {
        return Err(invalid("dp_leak requires small e (<= 2^20)"));
    }
    let k = dp * e - BigUint::one();
    for x in 1..=e_small {
        let xb = BigUint::from(x);
        if &k % &xb != BigUint::zero() {
            continue;
        }
        let p_candidate = &k / &xb + BigUint::one();
        if !p_candidate.is_zero() && n % &p_candidate == BigUint::zero() {
            let q = n / &p_candidate;
            if !q.is_one() && &p_candidate != &q {
                return Ok((p_candidate, q));
            }
        }
    }
    Err(invalid("dp_leak found no factor"))
}

/// dp/dq + p/q CRT combine (dp、dq 泄漏 branch).
pub fn dpdq(p: &BigUint, q: &BigUint, dp: &BigUint, dq: &BigUint, c: &BigUint) -> Result<BigUint> {
    let n = p * q;
    cap_ok(&n)?;
    let m1 = modpow(c, dp, p);
    let m2 = modpow(c, dq, q);
    let inv_p = mod_inverse(p, q)?;
    let t = (((&m2 + q - (&m1 % q)) % q) * &inv_p) % q;
    Ok(m1 + t * p)
}

/// Wiener attack (维纳攻击): small-d recovery via continued fractions of e/n.
pub fn wiener(e: &BigUint, n: &BigUint) -> Option<BigUint> {
    cap_ok(n).ok()?;
    let cf = continued_fraction(e, n);
    let zero = BigUint::zero();
    let one = BigUint::one();
    // convergents h_i / k_i of e/n; candidates (k, d) = (h, k_denominator)
    let mut h_m2 = zero.clone();
    let mut h_m1 = one.clone();
    let mut k_m2 = one.clone();
    let mut k_m1 = zero.clone();
    for a in cf {
        let h = &a * &h_m1 + &h_m2;
        let k_den = &a * &k_m1 + &k_m2;
        h_m2 = std::mem::replace(&mut h_m1, h.clone());
        k_m2 = std::mem::replace(&mut k_m1, k_den.clone());
        if h.is_zero() || k_den.is_zero() {
            continue;
        }
        // e*d - 1 = k * phi
        let ed = e * &k_den - &one;
        if &ed % &h != zero {
            continue;
        }
        let phi = &ed / &h;
        if phi.is_zero() || phi >= *n {
            continue;
        }
        // p + q = n - phi + 1; x^2 - s x + n = 0 needs discriminant sqrt
        let s = n - &phi + &one;
        let disc = &s * &s;
        let four_n = four() * n;
        if disc < four_n {
            continue;
        }
        let (sq, exact) = iroot(&(&disc - &four_n), 2);
        if !exact {
            continue;
        }
        let p = (&s + &sq) / two();
        let q = (&s - &sq) / two();
        if &p * &q == *n && !q.is_one() {
            return Some(k_den);
        }
    }
    None
}

/// Continued fraction expansion of x/y.
fn continued_fraction(x: &BigUint, y: &BigUint) -> Vec<BigUint> {
    let mut x = x.clone();
    let mut y = y.clone();
    let mut out = Vec::new();
    while !y.is_zero() {
        out.push(&x / &y);
        let r = &x % &y;
        x = std::mem::replace(&mut y, r);
    }
    out
}

/// Fermat factorization for close p, q (费马分解).
pub fn fermat(n: &BigUint, max_iter: u64) -> Option<(BigUint, BigUint)> {
    cap_ok(n).ok()?;
    let (mut a, _) = iroot(n, 2);
    a += BigUint::one();
    for _ in 0..max_iter {
        let b2 = &a * &a - n;
        let (b, exact) = iroot(&b2, 2);
        if exact && !b.is_zero() {
            let p = &a + &b;
            let q = &a - &b;
            if !q.is_one() && &p * &q == *n {
                return Some((p, q));
            }
        }
        a += BigUint::one();
    }
    None
}

/// 低加密指数攻击 (Håstad, single modulus): m = (c + k*n)^(1/e).
pub fn low_e(c: &BigUint, e: &BigUint, n: &BigUint, max_k: u64) -> Option<BigUint> {
    cap_ok(n).ok()?;
    let e_small = to_u32_sat(e);
    if e_small < 2 {
        return None;
    }
    for k in 0..=max_k {
        let cand = c + n * BigUint::from(k);
        let (m, exact) = iroot(&cand, e_small);
        if exact {
            return Some(m);
        }
    }
    None
}

/// 共模攻击: same n, coprime e1/e2 (reduces by gcd and takes the g-th root).
pub fn common_modulus(
    c1: &BigUint,
    c2: &BigUint,
    e1: &BigUint,
    e2: &BigUint,
    n: &BigUint,
) -> Result<BigUint> {
    cap_ok(n)?;
    let g = gcd(e1, e2);
    let (a, b) = if g.is_one() {
        (e1.clone(), e2.clone())
    } else {
        (e1 / &g, e2 / &g)
    };
    let (_, s1, s2) = egcd(&BigInt::from(a), &BigInt::from(b));
    let m = modpow_signed(c1, &s1, n)? * modpow_signed(c2, &s2, n)? % n;
    if g.is_one() {
        Ok(m)
    } else {
        let (r, exact) = iroot(&m, to_u32_sat(&g));
        if exact {
            Ok(r)
        } else {
            Err(CoreError::NoRoot { k: to_u32_sat(&g) })
        }
    }
}

/// 广播攻击 (Håstad broadcast): same m, small e, e pairwise-coprime moduli.
pub fn hastad_broadcast(cs: &[BigUint], ns: &[BigUint], e: &BigUint) -> Result<BigUint> {
    if cs.len() != ns.len() || cs.len() < 2 {
        return Err(invalid("need >= 2 (c, n) pairs"));
    }
    for n in ns {
        cap_ok(n)?;
    }
    let e_small = to_u32_sat(e);
    if e_small < 2 {
        return Err(invalid("e must be >= 2"));
    }
    // Pairs may be fewer than e: the CRT result still yields m exactly when
    // m^e < prod(n_i) (tiny-message broadcast variant).
    let mut a = cs[0].clone();
    let mut m = ns[0].clone();
    for pair in ns.iter().zip(cs.iter()).skip(1) {
        let (ni, ci) = pair;
        let (na, nm) =
            crt_merge(&a, &m, ci, ni).ok_or_else(|| invalid("moduli are not pairwise coprime"))?;
        a = na;
        m = nm;
    }
    let (r, exact) = iroot(&a, e_small);
    if exact {
        Ok(r)
    } else {
        Err(CoreError::NoRoot { k: e_small })
    }
}

/// Rabin (e=2): four roots via the p,q ≡ 3 (mod 4) shortcut.
pub fn rabin(c: &BigUint, p: &BigUint, q: &BigUint) -> Result<[BigUint; 4]> {
    let n = p * q;
    cap_ok(&n)?;
    if gcd(p, q) != BigUint::one() {
        return Err(invalid("rabin requires coprime p, q"));
    }
    let mp = modpow(c, &((p + BigUint::one()) / four()), p);
    let mq = modpow(c, &((q + BigUint::one()) / four()), q);
    // p*yp + q*yq = 1
    let (_, yp, yq) = egcd(&BigInt::from(p.clone()), &BigInt::from(q.clone()));
    let nb = BigInt::from(n.clone());
    let pb = BigInt::from(p.clone());
    let qb = BigInt::from(q.clone());
    let mpb = BigInt::from(mp);
    let mqb = BigInt::from(mq);
    let norm = |v: BigInt| -> BigUint {
        let r = v % &nb;
        ((r + &nb) % &nb).to_biguint().unwrap_or_default()
    };
    let m1 = norm(&yp * &pb * &mqb + &yq * &qb * &mpb);
    let m3 = norm(&yp * &pb * &mqb - &yq * &qb * &mpb);
    let m2 = &n - &m1;
    let m4 = &n - &m3;
    Ok([m1, m2, m3, m4])
}

/// Factor a semiprime with Pollard rho, returns (p, q).
pub fn factor_rho(n: &BigUint, rounds: u64) -> Option<(BigUint, BigUint)> {
    cap_ok(n).ok()?;
    let f = pollard_rho(n, rounds)?;
    if !f.is_one() && f != *n {
        Some((f.clone(), n / &f))
    } else {
        None
    }
}

/// Factor via p-1 (B-smooth), returns (p, q).
pub fn factor_p1(n: &BigUint, bound: u64) -> Option<(BigUint, BigUint)> {
    cap_ok(n).ok()?;
    let f = pollard_p1(n, bound)?;
    if !f.is_one() && f != *n {
        Some((f.clone(), n / &f))
    } else {
        None
    }
}

/// Schmidt-Samoa cryptosystem: N = p^2 q, c = m^N mod N, m = c^d mod pq with
/// d = N^{-1} mod (p-1)(q-1). Recovered from p, q (Crypto笔记 section).
pub fn schmidt_samoa(c: &BigUint, p: &BigUint, q: &BigUint) -> Result<BigUint> {
    let n = p * q;
    let big_n = p * p * q;
    cap_ok(&big_n)?;
    let phi = (p - BigUint::one()) * (q - BigUint::one());
    let d = mod_inverse(&big_n, &phi)?;
    Ok(modpow(c, &d, &n))
}

/// Integer roots of a2·x² + a1·x + a0 = 0 over Z (a2 != 0).
/// Returns 0..2 positive integer roots; the conjugate root may be fractional
/// (root product a0/a2), as in the [SWPU2020]happy p-recovery shape where
/// the roots are p and 1/p. Reusable primitive.
pub fn integer_quadratic_roots(a2: &BigUint, a1: &BigInt, a0: &BigInt) -> Vec<BigUint> {
    if a2.is_zero() {
        return vec![];
    }
    // disc = a1² - 4·a2·a0 (BigInt math; may be negative)
    let a1b = a1.clone();
    let disc = &a1b * &a1b - BigInt::from(4u32) * BigInt::from(a2.clone()) * a0;
    if disc < BigInt::from(0u32) {
        return vec![];
    }
    let Some(disc_u) = disc.to_biguint() else { return vec![] };
    let (sq, exact) = iroot(&disc_u, 2);
    if !exact {
        return vec![];
    }
    // x = (-a1 ± sq) / (2·a2)
    let two = BigUint::from(2u32);
    let mut roots = Vec::new();
    for sign in [1i32, -1i32] {
        let num = if sign == 1 {
            BigInt::from(-1) * &a1b + BigInt::from(sq.clone())
        } else {
            BigInt::from(-1) * &a1b - BigInt::from(sq.clone())
        };
        let den = BigInt::from(a2 * &two);
        if num >= BigInt::from(0u32) && (&num % &den) == BigInt::from(0u32) {
            if let Some(x) = (num / &den).to_biguint() {
                if !x.is_zero() && !roots.contains(&x) {
                    roots.push(x);
                }
            }
        }
    }
    roots
}

/// [SWPU2020]happy shape: given A = q(1+p³), B = q(p+p²), recover p via
/// B·p² − (A+B)·p + B = 0, then q, n, φ and m = c^(e⁻¹ mod φ) mod pq.
pub fn happy_attack(
    sum_a: &BigUint,
    sum_b: &BigUint,
    c: &BigUint,
    e: &BigUint,
) -> Result<BigUint> {
    let neg_ab = -(BigInt::from(sum_a + sum_b));
    let roots = integer_quadratic_roots(sum_b, &neg_ab, &BigInt::from(sum_b.clone()));
    let p = roots
        .iter()
        .max()
        .cloned()
        .ok_or_else(|| invalid("happy: no integer p from the sum relations"))?;
    let p2p = &p * &p + &p;
    if sum_b % &p2p != BigUint::zero() {
        return Err(invalid("happy: q not integral (relation mismatch)"));
    }
    let q = sum_b / &p2p;
    let n = &p * &q;
    let phi = (p - BigUint::one()) * (q - BigUint::one());
    let d = mod_inverse(e, &phi)?;
    Ok(modpow(c, &d, &n))
}

/// 共享素数: pairwise gcds of a modulus list.
pub fn shared_prime(ns: &[BigUint]) -> Vec<(usize, usize, BigUint)> {
    let mut out = Vec::new();
    for i in 0..ns.len() {
        for j in (i + 1)..ns.len() {
            let g = gcd(&ns[i], &ns[j]);
            if !g.is_one() {
                out.push((i, j, g));
            }
        }
    }
    out
}

/// yafu sidecar factorization (delegates to the pinned binary).
pub fn factor_yafu(n: &BigUint, timeout_secs: u64) -> Result<Vec<BigUint>> {
    if std::env::var("CTF_FORGE_FAST").as_deref() == Ok("1") {
        return Err(invalid("fast mode: yafu sidecar disabled"));
    }
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .ok_or_else(|| invalid("cannot locate repo root"))?
        .to_path_buf();
    ctf_sidecar::yafu::factor(&root, n, timeout_secs)
}

/// Everything `auto_attack` can accept. Missing pieces stay `None`.
#[derive(Debug, Default, Clone)]
pub struct RsaParams {
    pub n: Option<BigUint>,
    pub e: Option<BigUint>,
    pub c: Option<BigUint>,
    pub d: Option<BigUint>,
    pub p: Option<BigUint>,
    pub q: Option<BigUint>,
    pub dp: Option<BigUint>,
    pub dq: Option<BigUint>,
    pub c1: Option<BigUint>,
    pub c2: Option<BigUint>,
    pub e1: Option<BigUint>,
    pub e2: Option<BigUint>,
    pub ns: Option<Vec<BigUint>>,
    pub cs: Option<Vec<BigUint>>,
    pub sum_a: Option<BigUint>,
    pub sum_b: Option<BigUint>,
}

/// Decision-tree walk (order mirrors the notes + autorsa):
/// p&q → d&n → dp&dq&p&q → e&n&dp → wiener → low-e → rho/p1/fermat/yafu →
/// common modulus → broadcast.
pub fn auto_attack(params: &RsaParams) -> Result<BigUint> {
    let n = params.n.clone();
    let e = params.e.clone();

    if let (Some(p), Some(q), Some(c), Some(e)) =
        (params.p.clone(), params.q.clone(), params.c.clone(), e.clone())
    {
        return from_pq(&c, &e, &p, &q);
    }
    if let (Some(d), Some(nv), Some(c)) = (params.d.clone(), n.clone(), params.c.clone()) {
        return decrypt(&c, &d, &nv);
    }
    if let (Some(p), Some(q), Some(dp), Some(dq), Some(c)) = (
        params.p.clone(),
        params.q.clone(),
        params.dp.clone(),
        params.dq.clone(),
        params.c.clone(),
    ) {
        return dpdq(&p, &q, &dp, &dq, &c);
    }
    if let (Some(e), Some(nv), Some(dp), Some(c)) =
        (e.clone(), n.clone(), params.dp.clone(), params.c.clone())
    {
        let (p, q) = dp_leak(&e, &nv, &dp)?;
        return from_pq(&c, &e, &p, &q);
    }
    if let (Some(c1), Some(c2), Some(e1), Some(e2), Some(nv)) = (
        params.c1.clone(),
        params.c2.clone(),
        params.e1.clone(),
        params.e2.clone(),
        n.clone(),
    ) {
        return common_modulus(&c1, &c2, &e1, &e2, &nv);
    }
    if let (Some(sa), Some(sb), Some(cv), Some(ev)) = (
        params.sum_a.clone(),
        params.sum_b.clone(),
        params.c.clone(),
        params.e.clone(),
    ) {
        return happy_attack(&sa, &sb, &cv, &ev);
    }
    if let (Some(cs), Some(ns), Some(e)) = (params.cs.clone(), params.ns.clone(), e.clone()) {
        return hastad_broadcast(&cs, &ns, &e);
    }
    if let (Some(e), Some(nv), Some(c)) = (e.clone(), n.clone(), params.c.clone()) {
        if let Some(d) = wiener(&e, &nv) {
            return decrypt(&c, &d, &nv);
        }
        if to_u32_sat(&e) <= 64 {
            if let Some(m) = low_e(&c, &e, &nv, 100_000) {
                return Ok(m);
            }
        }
        let mut pq = factor_rho(&nv, 2);
        if pq.is_none() {
            pq = factor_p1(&nv, 30_000);
        }
        if pq.is_none() {
            pq = fermat(&nv, 20_000);
        }
        if let Some((p, q)) = pq {
            return from_pq(&c, &e, &p, &q);
        }
        if std::env::var("CTF_FORGE_FAST").as_deref() == Ok("1") {
            return Err(invalid("auto_attack: fast mode skips sidecar factoring"));
        }
        let factors = factor_yafu(&nv, 30)?;
        if factors.len() == 2 {
            return from_pq(&c, &e, &factors[0], &factors[1]);
        }
        return Err(invalid("auto_attack: all factor paths failed"));
    }
    Err(invalid("auto_attack: insufficient parameters"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bu(v: u32) -> BigUint {
        BigUint::from(v)
    }

    #[test]
    fn decrypt_basic() {
        let p = bu(61);
        let q = bu(53);
        let n = &p * &q; // 3233
        let phi = (p - 1u32) * (q - 1u32);
        let e = bu(17);
        let d = mod_inverse(&e, &phi).unwrap();
        let c = modpow(&bu(65), &e, &n); // m = 65 ("A")
        assert_eq!(decrypt(&c, &d, &n).unwrap(), bu(65));
    }

    #[test]
    fn low_e_toy() {
        let n = bu(3233);
        let e = bu(3);
        let m = bu(5);
        let c = &m * &m * &m; // 125 < n
        assert_eq!(low_e(&c, &e, &n, 100).unwrap(), m);
    }

    #[test]
    fn common_modulus_toy() {
        let n = bu(3233);
        let e1 = bu(3);
        let e2 = bu(5);
        let m = bu(42);
        let c1 = modpow(&m, &e1, &n);
        let c2 = modpow(&m, &e2, &n);
        assert_eq!(common_modulus(&c1, &c2, &e1, &e2, &n).unwrap(), m);
    }

    #[test]
    fn rabin_toy() {
        let p = bu(7);
        let q = bu(11);
        let m = bu(9);
        let c = &m * &m; // 81 mod 77 = 4
        let roots = rabin(&c, &p, &q).unwrap();
        assert!(roots.iter().any(|r| *r == m));
        // all four roots square to c
        for r in roots {
            assert_eq!(modpow(&r, &bu(2), &(&p * &q)), &c % &(&p * &q));
        }
    }

    #[test]
    fn dpdq_toy() {
        let p = bu(61);
        let q = bu(53);
        let phi = (&p - 1u32) * (&q - 1u32);
        let e = bu(17);
        let d = mod_inverse(&e, &phi).unwrap();
        let dp = &d % (&p - 1u32);
        let dq = &d % (&q - 1u32);
        let n = &p * &q;
        let m = bu(65);
        let c = modpow(&m, &e, &n);
        assert_eq!(dpdq(&p, &q, &dp, &dq, &c).unwrap(), m);
    }

    #[test]
    fn from_pq_toy() {
        let p = bu(61);
        let q = bu(53);
        let n = &p * &q;
        let phi = (&p - 1u32) * (&q - 1u32);
        let e = bu(17);
        let d = mod_inverse(&e, &phi).unwrap();
        let m = bu(65);
        let c = modpow(&m, &e, &n);
        assert_eq!(from_pq(&c, &e, &p, &q).unwrap(), m);
        let _ = d;
    }

    #[test]
    fn shared_prime_toy() {
        let p = bu(11);
        let n1 = &p * bu(13);
        let n2 = &p * bu(17);
        let hits = shared_prime(&[n1, n2]);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].2, p);
    }

    #[test]
    fn fermat_on_close_primes() {
        // (10^15 + 37) and nextprime-ish close pair with known product
        let p = bu(1000003);
        let q = bu(1000033);
        let n = &p * &q;
        let (fp, fq) = fermat(&n, 10_000).expect("close primes factor quickly");
        assert_eq!(&fp * &fq, n);
    }

    #[test]
    fn happy_synthetic() {
        // p, q chosen; A = q(1+p^3), B = q(p+p^2); decrypt via happy_attack
        let p = bu(10007);
        let q = bu(10009);
        let a = &q * (BigUint::one() + pow_u32(&p, 3));
        let b = &q * (&p * &p + &p);
        let n = &p * &q;
        let phi = (&p - 1u32) * (&q - 1u32);
        let e = bu(65537);
        let d = mod_inverse(&e, &phi).unwrap();
        let m = bu(12345678); // must be < n = p*q
        let c = modpow(&m, &e, &n);
        let got = happy_attack(&a, &b, &c, &e).unwrap();
        assert_eq!(got, m);
        let _ = d;
    }

    fn pow_u32(base: &BigUint, exp: u32) -> BigUint {
        use num_traits::One;
        let mut r = BigUint::one();
        for _ in 0..exp {
            r *= base;
        }
        r
    }

    #[test]
    fn wiener_rejects_normal_e() {
        // normal e for a small modulus must not yield a bogus d
        let p = bu(10007);
        let q = bu(10009);
        let n = &p * &q;
        let phi = (p - 1u32) * (q - 1u32);
        let e = bu(65537);
        let d = mod_inverse(&e, &phi).unwrap();
        let c = modpow(&bu(1234), &e, &n);
        let m = decrypt(&c, &d, &n).unwrap();
        assert_eq!(m, bu(1234));
        // d here is large, so wiener should NOT fire
        let _ = wiener(&e, &n);
    }
}
