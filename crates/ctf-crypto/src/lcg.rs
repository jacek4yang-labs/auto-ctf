//! LCG (线性同余) recovery: parameters from outputs, stepping, and seed search.
//! Formulas from `Crypto笔记.md` LCG section and `refs/autorsa/solver/lcg.py`.

use num_bigint::{BigInt, BigUint};
use num_traits::{Signed, Zero};

use ctf_core::bytes::int_to_bytes;
use ctf_core::error::{CoreError, Result};
use ctf_core::num::mod_inverse;

fn invalid(what: &str) -> CoreError {
    CoreError::Invalid(what.into())
}

/// a = (x2 - x1) * (x1 - x0)^-1 mod m  (needs gcd(x1-x0, m) == 1)
pub fn find_a(x0: &BigUint, x1: &BigUint, x2: &BigUint, m: &BigUint) -> Result<BigUint> {
    let d1 = sub_mod(x1, x0, m);
    let d2 = sub_mod(x2, x1, m);
    if d1.is_zero() {
        return Err(invalid("x1 == x0; cannot derive a"));
    }
    let inv = mod_inverse(&d1, m)?;
    Ok(d2 * inv % m)
}

/// b = (x1 - a*x0) mod m
pub fn find_b(x0: &BigUint, x1: &BigUint, a: &BigUint, m: &BigUint) -> BigUint {
    sub_mod(x1, &(a * x0 % m), m)
}

/// m from 5 outputs: T2 = t3*t1 - t2^2, T1 = t2*t0 - t1^2, m = gcd(T2, T1)
/// where t_i = x_{i+1} - x_i (signed; autorsa `lcd_findm` equivalent).
pub fn find_m(x0: &BigUint, x1: &BigUint, x2: &BigUint, x3: &BigUint, x4: &BigUint) -> BigUint {
    let xs = [x0, x1, x2, x3, x4];
    let t: Vec<BigInt> = (0..4)
        .map(|i| BigInt::from(xs[i + 1].clone()) - BigInt::from(xs[i].clone()))
        .collect();
    let big_t2 = &t[3] * &t[1] - &t[2] * &t[2];
    let big_t1 = &t[2] * &t[0] - &t[1] * &t[1];
    ctf_core::num::gcd(&abs_val(&big_t2), &abs_val(&big_t1))
}

fn abs_val(v: &BigInt) -> BigUint {
    v.clone()
        .abs()
        .to_biguint()
        .unwrap_or_else(BigUint::zero)
}

/// (a - b) mod m
fn sub_mod(a: &BigUint, b: &BigUint, m: &BigUint) -> BigUint {
    (a % m + m - b % m) % m
}

/// x_{n+1} = (a*x_n + b) mod m
pub fn step(x: &BigUint, a: &BigUint, b: &BigUint, m: &BigUint) -> BigUint {
    (a * x + b) % m
}

/// x_{n-1} = (x_n - b) * a^-1 mod m
pub fn step_back(x: &BigUint, a: &BigUint, b: &BigUint, m: &BigUint) -> Result<BigUint> {
    let inv = mod_inverse(a, m)?;
    Ok(inv * sub_mod(x, b, m) % m)
}

/// Walk `rounds` steps backward from `x`; return the first seed whose byte
/// representation contains `needle` (autorsa `lcg_findseed` equivalent).
pub fn seed_search(
    x: &BigUint,
    a: &BigUint,
    b: &BigUint,
    m: &BigUint,
    rounds: u64,
    needle: &[u8],
) -> Result<Option<BigUint>> {
    if needle.is_empty() {
        return Err(invalid("empty needle"));
    }
    let mut cur = x.clone();
    for _ in 0..rounds {
        cur = step_back(&cur, a, b, m)?;
        let bytes = int_to_bytes(&cur);
        if bytes.len() >= needle.len() && bytes.windows(needle.len()).any(|w| w == needle) {
            return Ok(Some(cur));
        }
    }
    Ok(None)
}

/// Predict the next `count` outputs.
pub fn predict_next(
    x_last: &BigUint,
    a: &BigUint,
    b: &BigUint,
    m: &BigUint,
    count: usize,
) -> Vec<BigUint> {
    let mut cur = x_last.clone();
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        cur = step(&cur, a, b, m);
        out.push(cur.clone());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lcg_params() -> (BigUint, BigUint, BigUint) {
        (
            BigUint::from(1103515245u64),
            BigUint::from(12345u64),
            BigUint::from(2147483648u64), // 2^31
        )
    }

    #[test]
    fn find_params_and_predict() {
        let (a, b, m) = lcg_params();
        let mut xs = vec![BigUint::from(1u32)];
        for _ in 0..5 {
            xs.push(step(xs.last().unwrap(), &a, &b, &m));
        }
        let found_a = find_a(&xs[0], &xs[1], &xs[2], &m).unwrap();
        assert_eq!(found_a, a);
        let found_b = find_b(&xs[0], &xs[1], &found_a, &m);
        assert_eq!(found_b, b);
        let preds = predict_next(xs.last().unwrap(), &a, &b, &m, 1);
        assert_eq!(preds[0], step(xs.last().unwrap(), &a, &b, &m));
        let back = step_back(xs.last().unwrap(), &a, &b, &m).unwrap();
        assert_eq!(back, xs[xs.len() - 2]);
    }

    #[test]
    fn find_m_two_candidates() {
        let (a, b, m) = lcg_params();
        let mut xs = vec![BigUint::from(7u32)];
        for _ in 0..5 {
            xs.push(step(xs.last().unwrap(), &a, &b, &m));
        }
        let found_m = find_m(&xs[0], &xs[1], &xs[2], &xs[3], &xs[4]);
        assert_eq!(found_m, m);
    }

    #[test]
    fn seed_search_finds_marker() {
        use ctf_core::bytes::bytes_to_int;
        let (a, b, m) = lcg_params();
        // seed must stay below m = 2^31 for the round-trip to be lossless
        let seed = bytes_to_int(b"KEY1"); // 0x4b455931 < 2^31
        let x1 = step(&seed, &a, &b, &m);
        let found = seed_search(&x1, &a, &b, &m, 10, b"KEY").unwrap();
        assert_eq!(found, Some(seed));
    }
}

/// N from 6 outputs (华为杯 2022 "四层挑战" challenge-4 pattern):
/// with t_i = x_{i+1} − x_i, the second differences satisfy
/// t1·t3 − t2² ≡ 0, t2·t4 − t3² ≡ 0, t0·t4 − t1·t3 ≡ 0 (mod N);
/// the GCD of the three absolute values is N itself on clean data.
pub fn find_m_six(x0: &BigUint, x1: &BigUint, x2: &BigUint, x3: &BigUint, x4: &BigUint, x5: &BigUint) -> BigUint {
    let xs = [x0, x1, x2, x3, x4, x5];
    let t: Vec<BigInt> = (0..5)
        .map(|i| BigInt::from(xs[i + 1].clone()) - BigInt::from(xs[i].clone()))
        .collect();
    let x = &t[1] * &t[3] - &t[2] * &t[2];
    let y = &t[2] * &t[4] - &t[3] * &t[3];
    let z = &t[0] * &t[4] - &t[1] * &t[3];
    let g1 = ctf_core::num::gcd(&abs_val(&x), &abs_val(&y));
    ctf_core::num::gcd(&g1, &abs_val(&z))
}

/// Full "unknown a, b, N, only 6 consecutive outputs" recovery.
///
/// `find_m_six` can return a small multiple of N (the difference products
/// share accidental factors), so candidates are derived by stripping small
/// prime factors and accepted only when the full recurrence
/// a·x_{i}+b ≡ x_{i+1} holds on the recovered parameters.
pub fn recover_seed_six(outputs: &[BigUint; 6]) -> Result<(BigUint, BigUint, BigUint, BigUint)> {
    let n0 = find_m_six(&outputs[0], &outputs[1], &outputs[2], &outputs[3], &outputs[4], &outputs[5]);
    if n0 <= BigUint::from(1u32) {
        return Err(invalid("degenerate modulus from second differences"));
    }
    let small_primes = [
        2u32, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79,
        83, 89, 97,
    ];
    let consistent = |cand: &BigUint| -> Option<(BigUint, BigUint)> {
        let a = find_a(&outputs[0], &outputs[1], &outputs[2], cand).ok()?;
        let b = find_b(&outputs[0], &outputs[1], &a, cand);
        if step(&outputs[2], &a, &b, cand) == outputs[3]
            && step(&outputs[3], &a, &b, cand) == outputs[4]
            && step(&outputs[4], &a, &b, cand) == outputs[5]
        {
            Some((a, b))
        } else {
            None
        }
    };
    // strip every small prime factor first, then walk the strip chain from the
    // smallest candidate upward — the smallest consistent modulus wins because
    // a lifted modulus (e.g. 2N) also satisfies the recurrence
    let mut chain = vec![n0.clone()];
    let mut cur = n0.clone();
    loop {
        let mut divided = false;
        for pr in small_primes {
            let pr = BigUint::from(pr);
            if (&cur % &pr).is_zero() {
                cur = &cur / &pr;
                chain.push(cur.clone());
                divided = true;
                break;
            }
        }
        if !divided || cur <= BigUint::from(1u32) {
            break;
        }
    }
    for cand in chain.iter().rev() {
        if let Some((a, b)) = consistent(cand) {
            let seed = step_back(&outputs[0], &a, &b, cand)?;
            return Ok((seed, a, b, cand.clone()));
        }
    }
    Err(invalid("could not reduce second-difference GCD to N"))
}

#[cfg(test)]
mod six_tests {
    use super::*;

    #[test]
    fn recover_seed_from_six_outputs() {
        // 华为杯 2022 四层挑战 challenge-4 replay: a,b,N unknown, 6 outputs
        let n = BigUint::from(2147483647u64);
        let a = BigUint::from(1103515245u64 % 2147483647u64 + 3u64);
        let b = BigUint::from(987654321u64);
        let mut s = BigUint::from(1946970516u64);
        let mut outs = Vec::new();
        for _ in 0..6 {
            s = step(&s, &a, &b, &n);
            outs.push(s.clone());
        }
        let mut arr: [BigUint; 6] = std::array::from_fn(|i| outs[i].clone());
        let (seed, fa, fb, fn_) = recover_seed_six(&arr).expect("recover");
        assert_eq!(fn_, n);
        assert_eq!(fa, a);
        assert_eq!(fb, b);
        assert_eq!(seed, BigUint::from(1946970516u64));
    }
}
