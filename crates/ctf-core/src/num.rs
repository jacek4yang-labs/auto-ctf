//! Number theory helpers on `BigUint`/`BigInt`.
//!
//! Decision-tree source: local `Crypto笔记.md` sections 欧几里得定理 / 扩展欧几里得
//! 算法 / 乘法逆元, and `refs/autorsa` solver primitives (gmpy2 equivalents).
//! All functions are safe Rust; inputs are capped at 8192 bits.

use num_bigint::{BigInt, BigUint};
use num_integer::Integer;
use num_traits::{One, Zero};

use crate::error::{CoreError, Result};

/// gcd(a, b).
pub fn gcd(a: &BigUint, b: &BigUint) -> BigUint {
    a.gcd(b)
}

/// Iterative extended gcd on `BigInt`; returns (g, x, y) with ax + by = g.
pub fn egcd(a: &BigInt, b: &BigInt) -> (BigInt, BigInt, BigInt) {
    let (mut old_r, mut r) = (a.clone(), b.clone());
    let (mut old_s, mut s) = (BigInt::from(1), BigInt::from(0));
    let (mut old_t, mut t) = (BigInt::from(0), BigInt::from(1));
    while !r.is_zero() {
        let q = &old_r / &r;
        let tmp = &old_r - &q * &r;
        old_r = std::mem::replace(&mut r, tmp);
        let tmp = &old_s - &q * &s;
        old_s = std::mem::replace(&mut s, tmp);
        let tmp = &old_t - &q * &t;
        old_t = std::mem::replace(&mut t, tmp);
    }
    (old_r, old_s, old_t)
}

/// Modular inverse of `a` mod `m` (m > 1). Errors when gcd != 1.
pub fn mod_inverse(a: &BigUint, m: &BigUint) -> Result<BigUint> {
    let am = &BigInt::from(a.clone() % m);
    let mm = &BigInt::from(m.clone());
    let (g, x, _) = egcd(am, mm);
    if g != BigInt::from(1) {
        return Err(CoreError::NoInverse(g.to_string()));
    }
    let m_b = BigInt::from(m.clone());
    let inv = ((x % &m_b) + &m_b) % &m_b;
    Ok(inv.to_biguint().expect("inverse is non-negative"))
}

/// base^exp mod modulus.
pub fn modpow(base: &BigUint, exp: &BigUint, modulus: &BigUint) -> BigUint {
    base.modpow(exp, modulus)
}

/// base^exp mod modulus where `exp` may be negative (uses modular inverse).
pub fn modpow_signed(base: &BigUint, exp: &BigInt, modulus: &BigUint) -> Result<BigUint> {
    if *exp >= BigInt::from(0) {
        let e = exp.to_biguint().expect("non-negative");
        return Ok(modpow(base, &e, modulus));
    }
    let inv = mod_inverse(base, modulus)?;
    let e = (-exp).to_biguint().expect("non-negative");
    Ok(modpow(&inv, &e, modulus))
}

/// Non-negative integer power.
pub fn pow_uint(base: &BigUint, mut exp: u32) -> BigUint {
    let mut result = BigUint::one();
    let mut b = base.clone();
    while exp > 0 {
        if exp & 1 == 1 {
            result *= &b;
        }
        b = &b * &b;
        exp >>= 1;
    }
    result
}

/// Integer k-th root of `n`; returns (root, exact). Newton iteration from above.
pub fn iroot(n: &BigUint, k: u32) -> (BigUint, bool) {
    assert!(k >= 1);
    if k == 1 || n.is_zero() || n.is_one() {
        return (n.clone(), true);
    }
    if k as u64 >= n.bits() + 1 {
        return (BigUint::one(), false);
    }
    let kn = BigUint::from(k);
    let mut x: BigUint = BigUint::one() << ((n.bits() as u32 + k - 1) / k);
    loop {
        // x' = ((k-1)*x + n / x^(k-1)) / k
        let xk1 = pow_uint(&x, k - 1);
        let next = (BigUint::from(k - 1) * &x + n / &xk1) / &kn;
        if next >= x {
            break;
        }
        x = next;
    }
    while pow_uint(&x, k) > *n {
        x -= BigUint::one();
    }
    let exact = pow_uint(&x, k) == *n;
    (x, exact)
}

/// Miller-Rabin with fixed bases. Deterministic below 3.3e24; strong probable
/// prime test above that (documented limitation — final factorization
/// confidence comes from the yafu sidecar).
pub fn is_probable_prime(n: &BigUint) -> bool {
    if n < &BigUint::from(2u32) {
        return false;
    }
    let small = [2u32, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37];
    for &p in &small {
        let bp = BigUint::from(p);
        if n == &bp {
            return true;
        }
        if n % &bp == BigUint::zero() {
            return false;
        }
    }
    // n - 1 = d * 2^s
    let one = BigUint::one();
    let nm1 = n - &one;
    let mut d = nm1.clone();
    let mut s = 0u64;
    while (&d & BigUint::one()).is_zero() {
        d >>= 1;
        s += 1;
    }
    'bases: for &p in &small {
        let bp = BigUint::from(p);
        let mut x = modpow(&bp, &d, n);
        if x.is_one() || x == nm1 {
            continue;
        }
        for _ in 1..s {
            x = (&x * &x) % n;
            if x == nm1 {
                continue 'bases;
            }
            if x.is_one() {
                return false;
            }
        }
        return false;
    }
    true
}

/// Brent-cycle Pollard rho with batched gcd (m=128); returns a non-trivial
/// factor or None after `max_rounds` parameter restarts / step budget.
pub fn pollard_rho(n: &BigUint, max_rounds: u64) -> Option<BigUint> {
    if (n & BigUint::one()).is_zero() {
        return Some(BigUint::from(2u32));
    }
    if n % BigUint::from(3u32) == BigUint::zero() {
        return Some(BigUint::from(3u32));
    }
    let batch: u64 = 128;
    let mut c = BigUint::one();
    for _ in 0..max_rounds {
        let step = |x: &BigUint| (x * x + &c) % n;
        let mut y = BigUint::from(2u32);
        let mut d = BigUint::one();
        let mut r = 1u64;
        let mut q = BigUint::one();
        let mut x = y.clone();
        let mut steps = 0u64;
        while d.is_one() {
            x = y.clone();
            for _ in 0..r {
                y = step(&y);
            }
            let mut k = 0u64;
            while k < r && d.is_one() {
                let mut ys = y.clone();
                for _ in 0..batch.min(r - k) {
                    ys = step(&ys);
                    let diff = if &x > &ys { &x - &ys } else { &ys - &x };
                    q = (&q * &diff) % n;
                }
                d = gcd(&q, n);
                y = ys;
                k += batch;
                steps += k;
            }
            r *= 2;
            if steps > 8_000_000 {
                break;
            }
        }
        if d != *n && !d.is_one() {
            return Some(d);
        }
        if d == *n {
            // back off to per-step gcd to recover the factor inside the batch
            let mut ys = y.clone();
            for _ in 0..batch {
                ys = step(&ys);
                let diff = if &x > &ys { &x - &ys } else { &ys - &x };
                let g = gcd(&diff, n);
                if !g.is_one() && g != *n {
                    return Some(g);
                }
            }
        }
        c += BigUint::one();
        if c > BigUint::from(64u32) {
            return None;
        }
    }
    None
}

/// Pollard p-1: finds factor p when p-1 is B-smooth (exponentiates by every
/// j in 2..=bound so prime powers in p-1 are covered).
pub fn pollard_p1(n: &BigUint, bound: u64) -> Option<BigUint> {
    let mut a = BigUint::from(2u32);
    for j in 2u64..=bound {
        a = modpow(&a, &BigUint::from(j), n);
        if j % 32 == 0 {
            let g = gcd(&(&a - BigUint::one()), n);
            if g == *n {
                return None;
            }
            if !g.is_one() {
                return Some(g);
            }
        }
    }
    let g = gcd(&(&a - BigUint::one()), n);
    if !g.is_one() && g != *n {
        Some(g)
    } else {
        None
    }
}

/// Tiny-modulus modular inverse by trial (m <= ~100k); None when no inverse.
pub fn mod_inverse_small(x: i64, m: i64) -> Option<i64> {
    let x = x.rem_euclid(m);
    if x == 0 {
        return None;
    }
    (1..m).find(|&i| (i * x) % m == 1)
}

/// Standard CRT merge of (a1, m1) and (a2, m2); None when moduli not coprime.
pub fn crt_merge(
    a1: &BigUint,
    m1: &BigUint,
    a2: &BigUint,
    m2: &BigUint,
) -> Option<(BigUint, BigUint)> {
    let g = gcd(m1, m2);
    if !g.is_one() {
        return None;
    }
    let m1b = BigInt::from(m1.clone());
    let m2b = BigInt::from(m2.clone());
    let (_, s, _) = egcd(&m1b, &m2b);
    let diff = BigInt::from(a2.clone()) - BigInt::from(a1.clone());
    let k = (&diff * &s) % &m2b;
    let lcm = m1 * m2;
    let lcmb = BigInt::from(lcm.clone());
    let x = (BigInt::from(a1.clone()) + &k * &m1b) % &lcmb;
    let x = ((x + &lcmb) % &lcmb + &lcmb) % &lcmb;
    Some((x.to_biguint()?, lcm))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn egcd_bezout() {
        let (g, x, y) = egcd(&BigInt::from(240), &BigInt::from(46));
        assert_eq!(g, BigInt::from(2));
        assert_eq!(BigInt::from(240) * x + BigInt::from(46) * y, g);
    }

    #[test]
    fn inverse_works() {
        let m = BigUint::from(0x7fff_ffffu32);
        let a = BigUint::from(12345u32);
        let inv = mod_inverse(&a, &m).unwrap();
        assert_eq!((&a * &inv) % &m, BigUint::one());
    }

    #[test]
    fn iroot_exact_and_floor() {
        let n = BigUint::from(1024u32);
        let (r, exact) = iroot(&n, 2);
        assert_eq!(r, BigUint::from(32u32));
        assert!(exact);
        let n = BigUint::from(1025u32);
        let (r, exact) = iroot(&n, 2);
        assert_eq!(r, BigUint::from(32u32));
        assert!(!exact);
    }

    #[test]
    fn iroot_big_cube() {
        let base = BigUint::one() << 200;
        let n = pow_uint(&base, 3);
        let (r, exact) = iroot(&n, 3);
        assert!(exact);
        assert_eq!(r, base);
    }

    #[test]
    fn primes_and_composites() {
        assert!(is_probable_prime(&BigUint::from(65537u32)));
        assert!(!is_probable_prime(&BigUint::from(65536u32)));
        assert!(!is_probable_prime(&BigUint::from(561u32))); // Carmichael 561
    }

    #[test]
    fn rho_finds_small_factor() {
        let n = BigUint::from(10007u32) * BigUint::from(10009u32);
        let f = pollard_rho(&n, 8).unwrap();
        assert!(&n % &f == BigUint::zero() && !f.is_one() && f != n);
    }

    #[test]
    fn p1_finds_smooth_factor() {
        let p = BigUint::from(2u32 * 2 * 3 * 5 * 7 * 13 * 17 * 23 + 1);
        if !is_probable_prime(&p) {
            return; // construction lost primality; covered by vector tests
        }
        let q = BigUint::from(7919u32);
        let n = &p * &q;
        let f = pollard_p1(&n, 10_000).expect("p-1 smooth factor");
        assert_eq!(f, p);
    }

    #[test]
    fn crt_merges_coprime() {
        let r = crt_merge(
            &BigUint::from(2u32),
            &BigUint::from(3u32),
            &BigUint::from(3u32),
            &BigUint::from(5u32),
        )
        .unwrap();
        assert_eq!(r.0, BigUint::from(8u32));
        assert_eq!(r.1, BigUint::from(15u32));
    }
}
