//! Lattice reduction + Coppersmith `small_roots` — pure safe Rust, exact arithmetic.
//!
//! Policy (docs/DEPS.md): the backend is replaceable — pure Rust now, fplll FFI
//! later — and SageMath is never required. LLL runs over Q with trimmed
//! big-rationals (no rounding drift); the Coppersmith builder follows the
//! standard Howgrave-Graham construction (g_{i,j} = x^j·f^i·N^max(0, βm−i),
//! plus x^i·f^m tail rows) and isolates the root with a rational polynomial
//! GCD across the shortest vectors, then verifies gcd(f(x0), n).
//!
//! Provenance: algorithm from the public Coppersmith/Howgrave-Graham literature
//! (Coppersmith 1997; Howgrave-Graham 1997; Cohen Alg. 16.10 for LLL);
//! independent implementation, no code copied. First exercised against the
//! 华为杯 2024 qualifier set (known-LSB padding, orthogonal-lattice class).

use num_bigint::{BigInt, BigUint};
use num_integer::Integer as _;
use num_traits::{One, Signed, ToPrimitive, Zero};

use ctf_core::error::{CoreError, Result};

fn invalid(what: &str) -> CoreError {
    CoreError::Invalid(what.into())
}
use ctf_core::num::{gcd as uint_gcd, mod_inverse};

/// Core bit cap (ctf-core::BIT_CAP) applies to the modulus.
const BIT_CAP: u64 = 8192;

// ---------------------------------------------------------------------------
// exact rational
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct Rat {
    num: BigInt,
    den: BigInt, // always > 0, gcd(num, den) = 1
}

impl Rat {
    fn new(num: BigInt, den: BigInt) -> Self {
        assert!(!den.is_zero(), "Rat::new zero denominator");
        let (num, den) = if den.is_negative() { (-num, -den) } else { (num, den) };
        let g = num.abs().gcd(&den);
        if g.is_zero() {
            Self { num: BigInt::zero(), den: BigInt::one() }
        } else {
            Self { num: num / &g, den: den / &g }
        }
    }
    fn zero() -> Self {
        Self { num: BigInt::zero(), den: BigInt::one() }
    }
    fn one() -> Self {
        Self { num: BigInt::one(), den: BigInt::one() }
    }
    fn from_int(v: &BigInt) -> Self {
        Self { num: v.clone(), den: BigInt::one() }
    }
    fn is_zero(&self) -> bool {
        self.num.is_zero()
    }
    fn abs_gt_half(&self) -> bool {
        self.den < &self.num.abs() * 2u32
    }
    fn round(&self) -> BigInt {
        // floor((2n + d) / (2d))
        let n2 = &self.num * 2u32;
        let d2 = &self.den * 2u32;
        (&n2 + &self.den).div_floor(&d2)
    }
}

impl std::ops::Add for Rat {
    type Output = Rat;
    fn add(self, o: Rat) -> Rat {
        Rat::new(self.num * &o.den + o.num * &self.den, self.den * o.den)
    }
}
impl std::ops::Sub for Rat {
    type Output = Rat;
    fn sub(self, o: Rat) -> Rat {
        Rat::new(self.num * &o.den - o.num * &self.den, self.den * o.den)
    }
}
impl std::ops::Mul for Rat {
    type Output = Rat;
    fn mul(self, o: Rat) -> Rat {
        Rat::new(self.num * o.num, self.den * o.den)
    }
}
impl std::ops::Div for Rat {
    type Output = Rat;
    fn div(self, o: Rat) -> Rat {
        Rat::new(self.num * o.den, self.den * o.num)
    }
}
impl PartialEq for Rat {
    fn eq(&self, o: &Rat) -> bool {
        &self.num * &o.den == &o.num * &self.den
    }
}
impl PartialOrd for Rat {
    fn partial_cmp(&self, o: &Rat) -> Option<std::cmp::Ordering> {
        Some((&self.num * &o.den).cmp(&(&o.num * &self.den)))
    }
}

// ---------------------------------------------------------------------------
// LLL (Cohen Alg. 16.10 shape, exact rational Gram-Schmidt)
// ---------------------------------------------------------------------------

/// Integer matrix in row-major form.
#[derive(Debug, Clone)]
pub struct IntegerMatrix {
    pub rows: usize,
    pub cols: usize,
    pub data: Vec<BigInt>,
}

impl IntegerMatrix {
    pub fn zeros(rows: usize, cols: usize) -> Self {
        Self { rows, cols, data: vec![BigInt::from(0); rows * cols] }
    }
    pub fn from_rows(rows: Vec<Vec<BigInt>>, cols: usize) -> Self {
        let r = rows.len();
        let mut data = Vec::with_capacity(r * cols);
        for mut row in rows {
            row.resize(cols, BigInt::zero());
            data.append(&mut row);
        }
        Self { rows: r, cols, data }
    }
    pub fn get(&self, r: usize, c: usize) -> &BigInt {
        &self.data[r * self.cols + c]
    }
    pub fn set(&mut self, r: usize, c: usize, v: BigInt) {
        self.data[r * self.cols + c] = v;
    }
    pub fn row(&self, r: usize) -> Vec<BigInt> {
        self.data[r * self.cols..(r + 1) * self.cols].to_vec()
    }
}

/// Replaceable reduction backend.
pub trait LatticeReducer {
    fn lll(&self, basis: &IntegerMatrix) -> std::result::Result<IntegerMatrix, String>;
}

/// LLL with δ = 3/4, exact rational Gram-Schmidt recomputed after each swap.
#[derive(Debug, Clone, Copy)]
pub struct Lll;

type GsState = (Vec<Vec<Rat>>, Vec<Vec<Rat>>, Vec<Rat>);

fn gs(b: &[Vec<BigInt>], cols: usize) -> std::result::Result<GsState, String> {
    let n = b.len();
    let mut bstar = vec![vec![Rat::zero(); cols]; n];
    let mut mu = vec![vec![Rat::zero(); n]; n];
    let mut bnorm = vec![Rat::zero(); n];
    for i in 0..n {
        let mut v: Vec<Rat> = b[i].iter().map(Rat::from_int).collect();
        for j in 0..i {
            let mut dot = Rat::zero();
            for c in 0..cols {
                let t = Rat::from_int(&b[i][c]) * bstar[j][c].clone();
                dot = dot + t;
            }
            let mij = dot / bnorm[j].clone();
            for c in 0..cols {
                let t = mij.clone() * bstar[j][c].clone();
                v[c] = v[c].clone() - t;
            }
            mu[i][j] = mij;
        }
        let mut norm = Rat::zero();
        for c in 0..cols {
            let t = v[c].clone() * v[c].clone();
            norm = norm + t;
        }
        if norm.is_zero() {
            return Err("linearly dependent basis vector".into());
        }
        bstar[i] = v;
        bnorm[i] = norm;
    }
    Ok((bstar, mu, bnorm))
}

impl LatticeReducer for Lll {
    fn lll(&self, basis: &IntegerMatrix) -> std::result::Result<IntegerMatrix, String> {
        let n = basis.rows;
        let cols = basis.cols;
        if n == 0 || cols == 0 {
            return Ok(basis.clone());
        }
        let mut b: Vec<Vec<BigInt>> = (0..n).map(|r| basis.row(r)).collect();
        let (mut bstar, mut mu, mut bnorm) = gs(&b, cols)?;

        let mut k = 1usize;
        let mut guard = 0usize;
        let cap = 4000 * n + 1000;
        let dbg = std::env::var("CTF_LLL_DEBUG").is_ok();
        while k < n {
            guard += 1;
            if guard > cap {
                return Err("LLL iteration cap exceeded".into());
            }
            if dbg && guard % 5000 == 0 {
                eprintln!("[lll] iter={} k={} n={}", guard, k, n);
            }
            // size-reduce b_k against b_{k-1..0}; b*_k and B[k] are invariant
            for j in (0..k).rev() {
                let mukj = mu[k][j].clone();
                if mukj.abs_gt_half() {
                    let q = mukj.round();
                    for c in 0..cols {
                        b[k][c] = b[k][c].clone() - &q * &b[j][c];
                    }
                    for i in 0..j {
                        let t = Rat::from_int(&q) * mu[j][i].clone();
                        mu[k][i] = mu[k][i].clone() - t;
                    }
                    mu[k][j] = mu[k][j].clone() - Rat::from_int(&q);
                }
            }
            // Lovász: B[k] + μ_{k,k-1}²·B[k-1] < δ·B[k-1]  →  swap
            let muo = mu[k][k - 1].clone();
            let mu2 = muo.clone() * muo.clone();
            let lhs = bnorm[k].clone() + mu2 * bnorm[k - 1].clone();
            let rhs = Rat::new(BigInt::from(3u32), BigInt::from(4u32)) * bnorm[k - 1].clone();
            if lhs < rhs {
                // local exact G-S update for the swapped pair (rows k-1, k):
                //   b*_{k-1}' = b*_k + μ·b*_{k-1}
                //   B' = B_k + μ²·B_{k-1};  μ'_{k,k-1} = μ·B_{k-1}/B'
                //   b*_k' = (B_{k-1}/B')·b*_{k-1} − μ·b*_{k-1}'
                //   B_k' = B_{k-1}·B_k/B'
                //   μ_{i,k-1}' = (μ_{i,k}B_k + μμ_{i,k-1}B_{k-1})/B'      (i > k)
                //   μ_{i,k}'   = μ_{i,k-1} − μμ_{i,k} − μ²μ_{i,k-1}B_{k-1}/B_k
                let b1 = bnorm[k - 1].clone();
                let b2 = bnorm[k].clone();
                let bprime = lhs; // B2 + μ²·B1 (already computed)
                let new_bstar_k1: Vec<Rat> = (0..cols)
                    .map(|c| bstar[k][c].clone() + muo.clone() * bstar[k - 1][c].clone())
                    .collect();
                let mu_new = muo.clone() * b1.clone() / bprime.clone();
                // b*_k' = b*_{k-1} − μ'·b*_{k-1}'   (μ' = μB_A/B'); norm² = B_A·B_C/B'
                let new_bstar_k: Vec<Rat> = (0..cols)
                    .map(|c| {
                        bstar[k - 1][c].clone() - mu_new.clone() * new_bstar_k1[c].clone()
                    })
                    .collect();
                bnorm[k - 1] = bprime.clone();
                bnorm[k] = b1.clone() * b2.clone() / bprime.clone();
                bstar[k - 1] = new_bstar_k1;
                bstar[k] = new_bstar_k;
                mu[k][k - 1] = mu_new.clone();
                for i in 0..k - 1 {
                    let tmp = mu[k - 1][i].clone();
                    mu[k - 1][i] = mu[k][i].clone();
                    mu[k][i] = tmp;
                }
                for i in (k + 1)..n {
                    let a = mu[i][k - 1].clone();
                    let bb = mu[i][k].clone();
                    mu[i][k - 1] = (bb.clone() * b2.clone()
                        + muo.clone() * a.clone() * b1.clone())
                        / bprime.clone();
                    mu[i][k] = a.clone() * bprime.clone() / b2.clone()
                        - muo.clone() * bb
                        - muo.clone() * muo.clone() * a * b1.clone() / b2.clone();
                }
                b.swap(k - 1, k);
                k = (k - 1).max(1);
            } else {
                k += 1;
            }
        }
        Ok(IntegerMatrix::from_rows(b, cols))
    }
}

// ---------------------------------------------------------------------------
// Z[x] helpers
// ---------------------------------------------------------------------------

fn poly_trim(mut p: Vec<BigInt>) -> Vec<BigInt> {
    while p.len() > 1 && p.last().map(|c| c.is_zero()).unwrap_or(true) {
        p.pop();
    }
    p
}

/// exact integer polynomial multiply — coefficients are NOT reduced mod n:
/// for beta < 1 the Howgrave-Graham congruence lives mod p^ceil(βm) (> p), and
/// multiples of n are only ≡ 0 mod p, so any mod-n reduction in the power
/// basis would silently invalidate the tail rows (f^m) of the lattice.
fn poly_mul_u(a: &[BigUint], b: &[BigUint]) -> Vec<BigUint> {
    let mut out = vec![BigUint::zero(); a.len() + b.len() - 1];
    for (i, ai) in a.iter().enumerate() {
        if ai.is_zero() {
            continue;
        }
        for (j, bj) in b.iter().enumerate() {
            out[i + j] = out[i + j].clone() + ai * bj;
        }
    }
    while out.len() > 1 && out.last() == Some(&BigUint::zero()) {
        out.pop();
    }
    out
}

fn poly_eval_bigint(p: &[BigInt], x: &BigInt) -> BigInt {
    let mut acc = BigInt::zero();
    for c in p.iter().rev() {
        acc = acc * x + c;
    }
    acc
}

fn rat_monic(mut p: Vec<Rat>) -> Vec<Rat> {
    while p.len() > 1 && p.last().map(|c| c.is_zero()).unwrap_or(true) {
        p.pop();
    }
    let lead = match p.last() {
        Some(c) if !c.is_zero() => c.clone(),
        _ => return Vec::new(), // zero polynomial
    };
    if lead.num == BigInt::one() && lead.den == BigInt::one() {
        return p;
    }
    p.iter_mut().for_each(|c| *c = c.clone() / lead.clone());
    p
}

/// remainder a mod b (b monic), exact rational arithmetic
fn rat_poly_rem(a: &[Rat], b: &[Rat]) -> Vec<Rat> {
    let mut r = a.to_vec();
    let bl = b.len();
    while r.len() >= bl {
        while r.len() > 1 && r.last().map(|c| c.is_zero()).unwrap_or(true) {
            r.pop();
        }
        if r.len() < bl {
            break;
        }
        let lead = r.last().cloned().unwrap_or(Rat::zero());
        if lead.is_zero() {
            r.pop();
            continue;
        }
        let shift = r.len() - bl;
        for (idx, bc) in b.iter().enumerate() {
            let t = lead.clone() * bc.clone();
            r[shift + idx] = r[shift + idx].clone() - t;
        }
        r.pop(); // leading term cancelled exactly
    }
    while r.len() > 1 && r.last().map(|c| c.is_zero()).unwrap_or(true) {
        r.pop();
    }
    r
}

/// Euclidean GCD over Q[x]; returns the gcd monic (possibly the zero poly).
fn rat_poly_gcd(a: &[Rat], b: &[Rat]) -> Vec<Rat> {
    let mut a = rat_monic(a.to_vec());
    let mut b = rat_monic(b.to_vec());
    if a.is_empty() {
        return b;
    }
    if b.is_empty() {
        return a;
    }
    loop {
        let r = rat_poly_rem(&a, &b);
        if r.iter().all(|c| c.is_zero()) {
            return b;
        }
        a = b;
        b = rat_monic(r);
        if b.is_empty() {
            return a;
        }
        if b.len() == 1 {
            return vec![Rat::one()]; // nonzero constant
        }
    }
}

// ---------------------------------------------------------------------------
// Coppersmith small_roots — candidate extraction
// ---------------------------------------------------------------------------

type C64 = (f64, f64);

fn cadd(a: C64, b: C64) -> C64 {
    (a.0 + b.0, a.1 + b.1)
}
fn csub(a: C64, b: C64) -> C64 {
    (a.0 - b.0, a.1 - b.1)
}
fn cmul(a: C64, b: C64) -> C64 {
    (a.0 * b.0 - a.1 * b.1, a.0 * b.1 + a.1 * b.0)
}
fn cdiv(a: C64, b: C64) -> C64 {
    let d = b.0 * b.0 + b.1 * b.1;
    ((a.0 * b.0 + a.1 * b.1) / d, (a.1 * b.0 - a.0 * b.1) / d)
}

/// Durand–Kerner root finding on a complex-coefficient polynomial (low→high).
fn durand_kerner(a: &[C64], iters: usize) -> Vec<C64> {
    let deg = a.len() - 1;
    if deg == 0 {
        return Vec::new();
    }
    // monic-ize
    let lead = a[deg];
    let lead_n2 = lead.0 * lead.0 + lead.1 * lead.1;
    let poly: Vec<C64> = a
        .iter()
        .map(|z| ((z.0 * lead.0 + z.1 * lead.1) / lead_n2, (z.1 * lead.0 - z.0 * lead.1) / lead_n2))
        .collect();
    let eval = |z: C64| -> C64 {
        let mut acc = (0.0, 0.0);
        for c in poly.iter().rev() {
            acc = cadd(cmul(acc, z), *c);
        }
        acc
    };
    // standard initialization: powers of the complex number 0.4+0.9i
    let mut cur = (0.4f64, 0.9f64);
    let mut roots: Vec<C64> = Vec::with_capacity(deg);
    for _ in 0..deg {
        roots.push(cur);
        cur = cmul(cur, (0.4, 0.9));
    }
    for _ in 0..iters {
        let mut movement = 0.0f64;
        for i in 0..deg {
            let p = eval(roots[i]);
            let mut denom = (1.0, 0.0);
            for j in 0..deg {
                if j != i {
                    denom = cmul(denom, csub(roots[i], roots[j]));
                }
            }
            if denom.0.abs() + denom.1.abs() < 1e-300 {
                continue;
            }
            let delta = cdiv(p, denom);
            movement += delta.0.abs() + delta.1.abs();
            roots[i] = csub(roots[i], delta);
        }
        if movement < 1e-13 {
            break;
        }
    }
    roots
}

/// Integer Newton iteration (truncated division) from an approximate root:
/// converges quadratically to the exact integer root of the integer
/// polynomial. Returns every visited point (the true root is among them).
#[allow(dead_code)]
fn integer_newton_visited(poly: &[BigInt], start: BigInt, max_iter: usize) -> Vec<BigInt> {
    let mut der: Vec<BigInt> = Vec::new();
    for (i, c) in poly.iter().enumerate().skip(1) {
        der.push(c * BigInt::from(i as u64));
    }
    if der.is_empty() {
        return Vec::new();
    }
    let mut x = start.clone();
    let mut visited = vec![x.clone()];
    for _ in 0..max_iter {
        let pv = poly_eval_bigint(poly, &x);
        if pv.is_zero() {
            return visited; // x itself is the exact root
        }
        let dv = poly_eval_bigint(&der, &x);
        if dv.is_zero() {
            break;
        }
        let q = pv / dv; // truncated division
        if q.is_zero() {
            break;
        }
        x = x - q;
        if visited.iter().any(|v| v == &x) {
            break; // cycle; visited points still get verified
        }
        visited.push(x.clone());
    }
    visited
}

/// Exact integer roots of the integer polynomial h in [0, 2^x_bits):
/// coarse sign-change scan over a grid, then exact BigInt bisection inside
/// each bracket. h(x0) = 0 is guaranteed by Howgrave–Graham for the short
/// vectors, so this isolates the root with no floating-point involved.
/// Recursively collect exact integer roots of poly in [lo, hi] with a sign
/// change (or an exact zero at an endpoint), verifying each against
/// gcd(f(x), n). Returns true once a verified root is found.
// ---------------------------------------------------------------------------
// Sturm sequence — exact real-root isolation (no floating point)
// ---------------------------------------------------------------------------

/// polynomial division over Q: returns (quotient, remainder)
fn rat_poly_divmod(a: &[Rat], b: &[Rat]) -> (Vec<Rat>, Vec<Rat>) {
    let mut q = vec![Rat::zero(); a.len().max(b.len())];
    let mut r: Vec<Rat> = a.to_vec();
    let bl = b.iter().rposition(|c| !c.is_zero()).map(|x| x + 1).unwrap_or(0);
    if bl == 0 {
        return (q, r);
    }
    let b_lead = b[bl - 1].clone();
    while r.iter().rposition(|c| !c.is_zero()).map(|x| x + 1).unwrap_or(0) >= bl {
        let rl = r.iter().rposition(|c| !c.is_zero()).unwrap();
        let shift = rl + 1 - bl;
        let factor = r[rl].clone() / b_lead.clone();
        q[shift] = factor.clone();
        for (idx, bc) in b.iter().enumerate() {
            r[shift + idx] = r[shift + idx].clone() - factor.clone() * bc.clone();
        }
    }
    while r.len() > 1 && r.last().map(|c| c.is_zero()).unwrap_or(true) {
        r.pop();
    }
    (q, r)
}

fn rat_poly_derivative(a: &[Rat]) -> Vec<Rat> {
    let mut out = Vec::new();
    for (i, c) in a.iter().enumerate().skip(1) {
        out.push(c.clone() * Rat::from_int(&BigInt::from(i as u64)));
    }
    if out.is_empty() {
        out.push(Rat::zero());
    }
    out
}

/// Sturm chain of the squarefree part of p
fn sturm_chain(p_rat: &[Rat]) -> Vec<Vec<Rat>> {
    let p = rat_monic(p_rat.to_vec());
    if p.len() <= 1 {
        return Vec::new();
    }
    let der = rat_poly_derivative(&p);
    let g = rat_poly_gcd(&p, &der);
    // squarefree part: p / gcd(p, p')
    let (sf, _) = rat_poly_divmod(&p, &g);
    let sf = rat_monic(sf);
    if sf.len() <= 1 {
        return Vec::new();
    }
    let mut chain = vec![sf.clone()];
    let mut cur = rat_poly_derivative(&sf);
    // p_{k+1} = −rem(p_{k−1}, p_k): negate the remainder but NEVER monic-ize
    // (dividing by a negative leading coefficient flips signs and corrupts the
    // variation count) and keep the final constant (its sign is counted).
    loop {
        chain.push(cur.clone());
        let prev = chain[chain.len() - 2].clone();
        let (_, r) = rat_poly_divmod(&prev, &cur);
        let mut rn: Vec<Rat> = r.into_iter().map(|c| c.clone() * Rat::new(BigInt::from(-1), BigInt::one())).collect();
        while rn.len() > 1 && rn.last().map(|c| c.is_zero()).unwrap_or(true) {
            rn.pop();
        }
        if rn.is_empty() || (rn.len() == 1 && rn[0].is_zero()) {
            break;
        }
        if rn.len() == 1 {
            chain.push(rn);
            break;
        }
        cur = rn;
    }
    chain
}

/// sign changes of the Sturm chain evaluated at x
fn sturm_variations(chain: &[Vec<Rat>], x: &BigInt) -> usize {
    let mut signs: Vec<i8> = Vec::new();
    let xr = Rat::from_int(x);
    for c in chain {
        let mut acc = Rat::zero();
        for cc in c.iter().rev() {
            acc = acc * xr.clone() + cc.clone();
        }
        if acc.is_zero() {
            continue;
        }
        signs.push(if acc.num.is_negative() { -1 } else { 1 });
    }
    let mut v = 0;
    for w in signs.windows(2) {
        if w[0] != w[1] {
            v += 1;
        }
    }
    v
}

fn sturm_collect_roots(
    chain: &[Vec<Rat>],
    f: &[BigInt],
    n: &BigUint,
    lo: BigInt,
    hi: BigInt,
    depth: u32,
    out: &mut Vec<BigUint>,
) -> bool {
    if depth == 0 {
        return false;
    }
    let verify = |x: &BigInt, out: &mut Vec<BigUint>| -> bool {
        let gcommon = uint_gcd(&to_mod(&poly_eval_bigint(f, x), n), n);
        if gcommon > BigUint::one() {
            if let Some(v) = x.to_biguint() {
                out.push(v);
                return true;
            }
        }
        false
    };
    let (vlo, vhi) = (sturm_variations(chain, &lo), sturm_variations(chain, &hi));
    if vlo <= vhi {
        return false; // no roots in (lo, hi]
    }
    // exact root at the low endpoint?
    let sf_int: Vec<BigInt> = chain[0].iter().map(|c| c.num.clone() / c.den.clone()).collect();
    if to_mod(&poly_eval_bigint(&sf_int, &lo), &BigUint::from(1u32)) == BigUint::zero() {
        // placeholder — zero detection done via direct eval below
    }
    let pl = poly_eval_bigint(&sf_int, &lo);
    if pl.is_zero() && lo >= BigInt::zero() && verify(&lo, out) {
        return true;
    }
    if &hi - &lo == BigInt::one() {
        // a single root in a width-1 interval must be the integer endpoint hi
        return verify(&hi, out);
    }
    let mid = (&lo + &hi) / 2u32;
    if sturm_collect_roots(chain, f, n, lo.clone(), mid.clone(), depth - 1, out) {
        return true;
    }
    sturm_collect_roots(chain, f, n, mid, hi, depth - 1, out)
}

/// Exact integer roots of the gcd polynomial in [0, 2^x_bits) via Sturm
/// isolation. Returns verified candidates (gcd(f(x0), n) > 1).
fn gcd_root_candidates(h_int: &[BigInt], f: &[BigInt], n: &BigUint, x_bits: u32) -> Vec<BigUint> {
    let mut out: Vec<BigUint> = Vec::new();
    let h_rat: Vec<Rat> = h_int.iter().map(Rat::from_int).collect();
    let chain = sturm_chain(&h_rat);
    if chain.is_empty() {
        return out;
    }
    let x_hi = BigInt::from(2u32).pow(x_bits);
    sturm_collect_roots(&chain, f, n, BigInt::zero(), x_hi, x_bits + 2, &mut out);
    out
}

fn rat_poly_to_integer(g: &[Rat]) -> Option<Vec<BigInt>> {
    let mut lcm = BigInt::one();
    for c in g {
        lcm = &lcm * &c.den / lcm.gcd(&c.den);
    }
    Some(g.iter().map(|c| &c.num * (&lcm / &c.den)).collect())
}

// ---------------------------------------------------------------------------
// Coppersmith small_roots
// ---------------------------------------------------------------------------


#[derive(Debug, Clone)]
pub struct SmallRoot {
    pub x0: BigUint,
    /// gcd(f(x0), n); None when the root holds mod n outright
    pub factor: Option<BigUint>,
}

fn to_mod(c: &BigInt, n: &BigUint) -> BigUint {
    let m = c.mod_floor(&BigInt::from(n.clone()));
    m.to_biguint().unwrap_or_else(BigUint::zero)
}

/// Coppersmith `small_roots`: find integers x, 0 ≤ x < 2^x_bits, with
/// f(x) ≡ 0 (mod b) for some divisor b | n, b ≥ n^(beta_num/beta_den).
/// f is given low→high over the integers; the working polynomial is reduced
/// monic mod n. Lattice dimension = m·deg(f) + t (keep ≤ ~24 in-process).
pub fn small_roots(
    f: &[BigInt],
    n: &BigUint,
    beta: (u64, u64),
    x_bits: u32,
    m: usize,
    t: usize,
) -> Result<Vec<SmallRoot>> {
    if n.bits() > BIT_CAP {
        return Err(CoreError::TooLarge { bits: n.bits(), cap: BIT_CAP });
    }
    if beta.0 == 0 || beta.1 == 0 {
        return Err(CoreError::Invalid("beta must be a positive rational".into()));
    }
    let f = poly_trim(f.to_vec());
    if f.len() < 2 {
        return Err(CoreError::Invalid("f must be non-constant".into()));
    }
    if f.last().map(|c| c.is_zero()).unwrap_or(true) {
        return Err(CoreError::Invalid("leading coefficient is zero".into()));
    }
    if m == 0 || m * (f.len() - 1) + t < 2 {
        return Err(CoreError::Invalid("degenerate lattice parameters".into()));
    }
    if *n < BigUint::from(3u32) {
        return Err(CoreError::Invalid("modulus too small".into()));
    }

    // monic-ize mod n (BigUint domain)
    let lead_mod = to_mod(f.last().unwrap(), n);
    if uint_gcd(&lead_mod, n) != BigUint::one() {
        return Err(CoreError::Invalid("leading coefficient not invertible mod n".into()));
    }
    let inv = mod_inverse(&lead_mod, n)?;
    let fm: Vec<BigUint> = f.iter().map(|c| to_mod(c, n) * &inv % n).collect();
    let fm = &fm[..];
    let d = fm.len() - 1;
    let dim = m * d + t;

    // Howgrave-Graham polynomial set: x^j·f^i·N^max(0, ceil(βm)−i), then x^i·f^m
    let k_base = (beta.0 * m as u64 + beta.1 - 1) / beta.1;
    let mut fpow: Vec<Vec<BigUint>> = Vec::with_capacity(m + 1);
    fpow.push(vec![BigUint::one()]);
    for _ in 0..m {
        let prev = fpow.last().unwrap().clone();
        fpow.push(poly_mul_u(&prev, fm));
    }
    let mut polys: Vec<Vec<BigUint>> = Vec::with_capacity(dim);
    for i in 0..m {
        // N^(ceil(βm)−i) stays an INTEGER factor — never reduced mod n
        // (reducing it would zero the row: N ≡ 0 mod n).
        let npow = if k_base > i as u64 {
            let e = (k_base - i as u64) as u32;
            BigUint::from(n.clone()).pow(e)
        } else {
            BigUint::one()
        };
        for j in 0..d {
            let mut p = vec![BigUint::zero(); j];
            p.extend(fpow[i].iter().map(|c| c * &npow));
            polys.push(p);
        }
    }
    for i in 0..t {
        let mut p = vec![BigUint::zero(); i];
        p.extend(fpow[m].iter().map(|c| c.clone()));
        polys.push(p);
    }

    // scale column c by X^c (entries stay plain integers)
    let xbig = BigUint::from(2u32).pow(x_bits);
    let mut basis = IntegerMatrix::zeros(dim, dim);
    for (r, p) in polys.iter().enumerate() {
        for (c, coeff) in p.iter().enumerate() {
            if c >= dim {
                break;
            }
            basis.set(r, c, BigInt::from(coeff * xbig.pow(c as u32)));
        }
    }

    let red = Lll.lll(&basis).map_err(CoreError::Invalid)?;
    let dbg = std::env::var("CTF_LLL_DEBUG").is_ok();
    if dbg {
        for r in 0..red.rows.min(4) {
            let row = red.row(r);
            let norm_bits: u64 = row
                .iter()
                .map(|c| {
                    let v = c.abs();
                    v.bits() as u64
                })
                .max()
                .unwrap_or(0);
            eprintln!("[sr] row {} max-entry ~2^{}", r, norm_bits);
        }
        eprintln!("[sr] det_est log2 = {}", 0u64); // placeholder
    }

    // unscale the shortest rows back into Q[x] polynomials
    let mut hp: Vec<Vec<Rat>> = Vec::new();
    for r in 0..red.rows.min(4) {
        let row = red.row(r);
        if row.iter().all(|c| c.is_zero()) {
            continue;
        }
        let mut h: Vec<Rat> = Vec::with_capacity(dim);
        let mut ok = true;
        for (c, v) in row.iter().enumerate() {
            let sc = BigInt::from(xbig.pow(c as u32));
            let (q, rem) = v.div_rem(&sc);
            if !rem.is_zero() {
                ok = false;
                break;
            }
            h.push(Rat::from_int(&q));
        }
        if ok && !h.is_empty() {
            if dbg && r == 0 {
                for (c, cc) in h.iter().enumerate() {
                    let sign = if cc.num.is_negative() { "-" } else { "+" };
                    eprintln!("[sr] h0[{}] = {}~2^{}", c, sign, cc.num.abs().bits());
                }
            }
            hp.push(h);
        }
    }
    if hp.len() < 2 {
        return Err(CoreError::Invalid("LLL produced too few usable short vectors".into()));
    }

    // isolate common factors via pairwise rational GCDs, then extract and
    // verify candidate roots against gcd(f(x0), n)
    let dbg = std::env::var("CTF_LLL_DEBUG").is_ok();
    // pairwise gcds, processed smallest-degree first: fewer shared factors →
    // better-separated roots → far better Durand–Kerner accuracy
    let mut pairs: Vec<Vec<Rat>> = Vec::new();
    for i in 0..hp.len() {
        for j in (i + 1)..hp.len() {
            pairs.push(rat_poly_gcd(&hp[i], &hp[j]));
        }
    }
    pairs.sort_by_key(|g| g.iter().rposition(|c| !c.is_zero()).unwrap_or(0));
    // chained full gcd over every short vector: everything in the reduced
    // basis vanishes at x0, so the overall common factor is (x − x0) itself
    // (generically linear) — this is the deterministic isolation path
    let mut chain_g = hp[0].clone();
    for h in hp.iter().skip(1) {
        chain_g = rat_poly_gcd(&chain_g, h);
        let last = chain_g.iter().rposition(|c| !c.is_zero()).unwrap_or(0);
        if last == 0 {
            break; // collapsed to a constant
        }
        pairs.push(chain_g.clone());
    }
    let mut cand: Vec<BigUint> = Vec::new();
    'pairs: for g in &pairs {
        if dbg {
            let deg = g.iter().rposition(|c| !c.is_zero()).map(|x| x + 1).unwrap_or(0);
            eprintln!("[sr] gcd deg={} (ascending)", deg);
        }
        let g_int = match rat_poly_to_integer(g) {
            Some(v) => v,
            None => continue,
        };
        for c in gcd_root_candidates(&g_int, &f, n, x_bits) {
            if dbg {
                eprintln!("[sr] candidate {} (bits {})", c, c.bits());
            }
            if !cand.contains(&c) {
                cand.push(c);
            }
            if cand.len() >= 8 {
                break 'pairs;
            }
        }
    }
    let mut roots: Vec<SmallRoot> = Vec::new();
    for x0b in cand {
        if x0b.bits() > x_bits as u64 + 1 {
            continue;
        }
        let x0 = BigInt::from(x0b.clone());
        let fv = poly_eval_bigint(&f, &x0);
        let fv_mod = to_mod(&fv, n);
        let gcommon = uint_gcd(&fv_mod, n);
        if dbg {
            eprintln!("[sr] verify x0={}: gcd(f(x0),n) = {} (bits {})", x0b, gcommon, gcommon.bits());
        }
        if gcommon == BigUint::one() {
            continue;
        }
        let factor = if gcommon == *n { None } else { Some(gcommon) };
        roots.push(SmallRoot { x0: x0b, factor });
        if roots.len() >= 4 {
            break;
        }
    }
    Ok(roots)
}

// apbq/orthogonal-lattice attack: the validated reference implementation is
// the Python+flint solver from the 2024-qualifier analysis (see
// docs/DEPS.md reference table and .tmp/work/y2024q/coppersmith.py).
// Rust port pending a paper-verified kernel-embedding formulation — the
// naive 6-dim embedding returns mixed kernel vectors with gcd 1.
#[cfg(test)]
mod tests {
    use super::*;
    use ctf_core::num::{is_probable_prime, modpow};

    fn bigint(v: i64) -> BigInt {
        BigInt::from(v)
    }

    fn next_prime(mut v: BigUint) -> BigUint {
        loop {
            if is_probable_prime(&v) {
                return v;
            }
            v += 1u32;
        }
    }

    #[test]
    fn matrix_roundtrip() {
        let mut m = IntegerMatrix::zeros(2, 2);
        m.set(1, 1, BigInt::from(7));
        assert_eq!(*m.get(1, 1), BigInt::from(7));
        assert_eq!(m.data.len(), 4);
    }

    #[test]
    fn lll_known_example() {
        // classic 2D example (Cohen); det = −1279 → Hermite bound for n=2:
        // ||b1||² ≤ (4/3)^(1/2)·|det| ≈ 1.155·1279 ≈ 1477
        let basis = IntegerMatrix::from_rows(
            vec![vec![bigint(201), bigint(37)], vec![bigint(1648), bigint(297)]],
            2,
        );
        let red = Lll.lll(&basis).expect("lll");
        let r0 = red.row(0);
        let norm2: i64 = r0.iter().map(|c| {
            let v = c.to_i64().unwrap();
            v * v
        }).sum();
        assert!(norm2 <= 1480, "first reduced vector too long: {:?}", r0);
        // membership: reduced rows stay in the original lattice
        for r in 0..2 {
            let row = red.row(r);
            let det = bigint(201) * bigint(297) - bigint(37) * bigint(1648);
            let a = (&row[0] * bigint(297) - &row[1] * bigint(1648)) / &det;
            let bb = (&row[1] * bigint(201) - &row[0] * bigint(37)) / &det;
            assert_eq!(&a * bigint(201) + &bb * bigint(1648), row[0]);
            assert_eq!(&a * bigint(37) + &bb * bigint(297), row[1]);
        }
    }

    #[test]
    fn lll_hermite_bound_on_random_lattice() {
        // xorshift64 deterministic pseudo-random full-rank basis
        let mut state: u64 = 0x243F6A8885A308D3;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        let n = 6usize;
        let mut rows = Vec::new();
        for i in 0..n {
            let mut row = vec![bigint(0); n];
            for c in 0..n {
                row[c] = bigint((next() % 4096) as i64);
            }
            row[i] = bigint((next() % 8192) as i64 + 8192);
            rows.push(row);
        }
        let basis = IntegerMatrix::from_rows(rows.clone(), n);
        let red = Lll.lll(&basis).expect("lll");
        let rows_out: Vec<Vec<BigInt>> = (0..red.rows).map(|r| red.row(r)).collect();

        let log2_rat = |r: &Rat| -> f64 {
            (r.num.to_f64().unwrap() / r.den.to_f64().unwrap()).log2()
        };
        // 1) Gram determinant is invariant under unimodular row ops
        let (_, _, bnorm_in) = gs(&rows, n).unwrap();
        let (_, mu_out, bnorm_out) = gs(&rows_out, n).unwrap();
        let log_det_in: f64 = bnorm_in.iter().map(log2_rat).sum();
        let log_det_out: f64 = bnorm_out.iter().map(log2_rat).sum();
        assert!(
            (log_det_in - log_det_out).abs() < 1e-6,
            "Gram determinant changed: {} vs {}",
            log_det_in,
            log_det_out
        );
        // 2) output is LLL-reduced: |μ| ≤ 1/2 and Lovász (δ=3/4) everywhere
        for i in 0..n {
            for j in 0..i {
                let m = mu_out[i][j].num.to_f64().unwrap() / mu_out[i][j].den.to_f64().unwrap();
                assert!(m.abs() <= 0.5000001, "μ[{}][{}] = {} not size-reduced", i, j, m);
            }
        }
        for k in 1..n {
            let mk = mu_out[k][k - 1].num.to_f64().unwrap()
                / mu_out[k][k - 1].den.to_f64().unwrap();
            let lhs = log2_rat(&bnorm_out[k]) + 2.0 * mk.abs().log2() + log2_rat(&bnorm_out[k - 1]);
            let rhs = 2.0f64.log2() * (0.75f64).log2() * -1.0 + log2_rat(&bnorm_out[k - 1]);
            // lhs_log ≥ log2(0.75) + log2 B_{k-1}  ⟺  B_k + μ²B_{k-1} ≥ 0.75·B_{k-1}
            let lhs_val = log2_rat(&bnorm_out[k])
                + (mk * mk).log2()
                + log2_rat(&bnorm_out[k - 1]);
            let rhs_val = (0.75f64).log2() + log2_rat(&bnorm_out[k - 1]);
            let _ = (lhs, rhs);
            assert!(
                lhs_val >= rhs_val - 1e-9,
                "Lovász violated at k={}: {} < {}",
                k,
                lhs_val,
                rhs_val
            );
        }
        // 3) Hermite bound on the first vector: ||b1||² ≤ (4/3)^((n-1)/2)·det^(2/n)
        let b1 = log2_rat(&bnorm_out[0]) / 2.0; // log2 ||b1||
        let hermite = (n as f64 - 1.0) / 2.0 * (4.0f64 / 3.0).log2() / 2.0 + log_det_out / (n as f64);
        assert!(
            b1 <= hermite + 1e-9,
            "Hermite bound violated: log2||b1||={} > {}",
            b1,
            hermite
        );
    }

    #[test]
    fn coppersmith_low_e_with_padding_beta_one() {
        // c = (pad + x·2^k)^3 mod n → f(x) = (pad + x·2^k)^3 − c, root x0 mod n
        let p = next_prime(BigUint::from(2u32).pow(127) + 12345u32);
        let q = next_prime(BigUint::from(2u32).pow(127) + 98765u32);
        let n = &p * &q;
        let pad: u64 = 0x0102_0304_0506_0708;
        let k = 48u32;
        let x0 = BigUint::from(0x0000_beef_cafe_f00du64); // < 2^48
        let base = BigUint::from(pad) * BigUint::from(2u32).pow(k);
        let m_plain = base.clone() + &x0;
        let c = modpow(&m_plain, &BigUint::from(3u32), &n);

        // m_plain = A + x0 with A = pad·2^48 → f(x) = (A + x)^3 − c,
        // root x0 mod n (the unknown low bits)
        let a_big = BigInt::from(base.clone());
        let ci = BigInt::from(c);
        let f = vec![
            a_big.pow(3) - ci,
            bigint(3) * a_big.pow(2),
            bigint(3) * a_big.clone(),
            BigInt::one(),
        ];
        let roots = small_roots(&f, &n, (1, 1), 48, 2, 1).expect("small_roots");
        assert!(
            roots.iter().any(|r| r.x0 == x0 && r.factor.is_none()),
            "expected exact root {:?}, got {:?}",
            x0,
            roots
        );
    }

    #[test]
    fn coppersmith_known_high_bits_factor_beta_half() {
        // p = hi + x0, x0 < 2^36 → f(x) = x − hi ≡ 0 (mod p), beta = 1/2
        let p = next_prime(BigUint::from(2u32).pow(160) * 3u32 + 7u32);
        let q = next_prime(BigUint::from(2u32).pow(160) * 5u32 + 11u32);
        let n = &p * &q;
        let x0 = BigUint::from(0x0A1B_2C3D_4Eu64);
        // p = hi + x0  →  f(x) = x + hi has root x0 mod p (f(x0) = p)
        let hi = &p - &x0;
        let f = vec![BigInt::from(hi.clone()), BigInt::one()];
        let roots = small_roots(&f, &n, (1, 2), 36, 4, 4).expect("small_roots");
        assert!(
            !roots.is_empty(),
            "no root recovered for known-high-bits factoring"
        );
        let hit = roots
            .iter()
            .find(|r| r.x0 == x0 || r.factor.as_ref() == Some(&p))
            .expect("expected x0 or factor p among candidates");
        if let Some(fac) = &hit.factor {
            assert_eq!(fac % &p, BigUint::zero(), "factor must be a multiple of p");
        }
    }
}

#[cfg(test)]
mod debug_tests {
    use super::*;

    /// reference LLL: full rational G-S recompute after every swap (slow but simple)
    fn lll_reference(basis: &IntegerMatrix) -> IntegerMatrix {
        let n = basis.rows;
        let cols = basis.cols;
        let mut b: Vec<Vec<BigInt>> = (0..n).map(|r| basis.row(r)).collect();
        let mut k = 1usize;
        let mut guard = 0usize;
        while k < n {
            guard += 1;
            if guard > 20000 {
                panic!("reference cap");
            }
            // full size reduction using fresh gs each time
            let (_, mu, _) = gs(&b, cols).unwrap();
            let mut changed = false;
            for j in 0..k {
                let mukj = mu[k][j].clone();
                if mukj.abs_gt_half() {
                    let q = mukj.round();
                    for c in 0..cols {
                        b[k][c] = b[k][c].clone() - &q * &b[j][c];
                    }
                    changed = true;
                }
            }
            if changed {
                continue;
            }
            let (_, mu, bnorm) = gs(&b, cols).unwrap();
            let mu2 = mu[k][k - 1].clone() * mu[k][k - 1].clone();
            let lhs = bnorm[k].clone() + mu2 * bnorm[k - 1].clone();
            let rhs = Rat::new(BigInt::from(3u32), BigInt::from(4u32)) * bnorm[k - 1].clone();
            if lhs < rhs {
                b.swap(k - 1, k);
                k = (k - 1).max(1);
            } else {
                k += 1;
            }
        }
        IntegerMatrix::from_rows(b, cols)
    }

    #[test]
    fn local_matches_reference_on_small_lattices() {
        let mut state: u64 = 0xACBDCFBE01234567;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        for trial in 0..8 {
            let n = 3 + (trial % 3); // 3..5
            let cols = n;
            let mut rows = Vec::new();
            for i in 0..n {
                let mut row = vec![BigInt::zero(); cols];
                for c in 0..cols {
                    row[c] = BigInt::from((next() % 64) as i64);
                }
                row[i] = BigInt::from((next() % 512) as i64 + 64);
                rows.push(row);
            }
            let basis = IntegerMatrix::from_rows(rows, cols);
            let fast = Lll.lll(&basis).expect("fast");
            let slow = lll_reference(&basis);
            // compare sorted row norms (reduced bases can differ by sign/order)
            let mut fnorms: Vec<i64> = (0..fast.rows)
                .map(|r| fast.row(r).iter().map(|c| c.to_i64().unwrap().pow(2)).sum())
                .collect();
            let mut snorms: Vec<i64> = (0..slow.rows)
                .map(|r| slow.row(r).iter().map(|c| c.to_i64().unwrap().pow(2)).sum())
                .collect();
            fnorms.sort();
            snorms.sort();
            assert_eq!(fnorms, snorms, "trial {} mismatch\nfast={:?}\nslow={:?}", trial, fnorms, snorms);
        }
    }
}

#[cfg(test)]
mod gcd_debug_tests {
    use super::*;

    fn ri(v: i64) -> Rat {
        Rat::from_int(&BigInt::from(v))
    }

    #[test]
    fn poly_gcd_finds_linear_factor() {
        // h1 = (x-5)(x+3) = x² - 2x - 15 ; h2 = (x-5)(x+2) = x² - 3x - 10
        let h1 = vec![ri(-15), ri(-2), ri(1)];
        let h2 = vec![ri(-10), ri(-3), ri(1)];
        let g = rat_poly_gcd(&h1, &h2);
        assert_eq!(g.len(), 2, "gcd should be linear, got {:?}", g);
        // monic: g = x - 5 → root = −g[0]/g[1] = 5
        let ratio = Rat::zero() - g[0].clone() / g[1].clone();
        assert_eq!(ratio.num, BigInt::from(5));
        assert_eq!(ratio.den, BigInt::one());
    }

    fn poly_mul_bigint(a: &[BigInt], b: &[BigInt]) -> Vec<BigInt> {
        let mut out = vec![BigInt::zero(); a.len() + b.len() - 1];
        for (i, ai) in a.iter().enumerate() {
            for (j, bj) in b.iter().enumerate() {
                out[i + j] = out[i + j].clone() + ai * bj;
            }
        }
        out
    }

    #[test]
    fn poly_gcd_big_coeffs_multi_step() {
        // (x − R)(x² + 77x − 3) 与 (x − R)(x³ − 5x + 9)，R 为大整数：
        // 多步欧几里得归约后 gcd 仍应为线性因子 (x − R)
        let r = BigInt::from(123456789012345678901234567890i128);
        let h1 = poly_mul_bigint(
            &vec![-r.clone(), BigInt::one()],
            &vec![BigInt::from(-3), BigInt::from(77), BigInt::one()],
        );
        let h2 = poly_mul_bigint(
            &vec![-r.clone(), BigInt::one()],
            &vec![BigInt::from(9), BigInt::from(-5), BigInt::one(), BigInt::one()],
        );
        let g = rat_poly_gcd(
            &h1.iter().map(Rat::from_int).collect::<Vec<_>>(),
            &h2.iter().map(Rat::from_int).collect::<Vec<_>>(),
        );
        assert_eq!(g.len(), 2, "gcd should be linear, got len {}", g.len());
        let ratio = Rat::zero() - g[0].clone() / g[1].clone();
        assert_eq!(ratio.num, r);
        assert_eq!(ratio.den, BigInt::one());
    }

    #[test]
    fn poly_gcd_coprime() {
        let h1 = vec![ri(-15), ri(-2), ri(1)];
        let h2 = vec![ri(-6), ri(1)]; // x - 6
        let g = rat_poly_gcd(&h1, &h2);
        assert_eq!(g.len(), 1, "coprime gcd should be constant");
    }

    #[test]
    fn poly_rem_smoke() {
        // (x² - 2x - 15) mod (x - 5) = 0
        let a = vec![ri(-15), ri(-2), ri(1)];
        let b = vec![ri(-5), ri(1)];
        let r = rat_poly_rem(&rat_monic(a.clone()), &rat_monic(b.clone()));
        assert!(r.iter().all(|c| c.is_zero()), "remainder should be zero, got {:?}", r);
    }
}

#[cfg(test)]
mod coppersmith_debug_tests {
    use super::*;
    use ctf_core::num::is_probable_prime;

    #[test]
    fn manual_lattice_diagnosis() {
        let p = {
            let mut v = BigUint::from(2u32).pow(160) * 3u32 + 7u32;
            while !is_probable_prime(&v) { v += 1u32; }
            v
        };
        let q = {
            let mut v = BigUint::from(2u32).pow(160) * 5u32 + 11u32;
            while !is_probable_prime(&v) { v += 1u32; }
            v
        };
        let n = &p * &q;
        let x0 = BigUint::from(0x0A1B_2C3D_4Eu64);
        let hi = &p - &x0;

        // f = x − hi (monic, deg 1), β = 1/2, m=4, t=4 → dim 8
        let fm = vec![to_mod(&BigInt::from(hi.clone()), &n), BigUint::one()];
        let m = 4usize; let t = 4usize; let d = 1usize;
        let k_base = 2u64;
        let dim = m * d + t;
        let mut fpow: Vec<Vec<BigUint>> = vec![vec![BigUint::one()]];
        for _ in 0..m {
            let prev = fpow.last().unwrap().clone();
            let mut nxt = vec![BigUint::zero(); prev.len() + 1];
            for (i, c) in prev.iter().enumerate() {
                nxt[i] = nxt[i].clone() + c * &fm[0];
                nxt[i + 1] = nxt[i + 1].clone() + c;
            }
            fpow.push(nxt);
        }
        let mut polys: Vec<Vec<BigUint>> = Vec::new();
        for i in 0..m {
            let npow = if k_base > i as u64 { BigUint::from(n.clone()).pow((k_base - i as u64) as u32) } else { BigUint::one() };
            polys.push(fpow[i].iter().map(|c| c * &npow).collect());
        }
        for i in 0..t {
            let mut v = vec![BigUint::zero(); i];
            v.extend(fpow[m].iter().cloned());
            polys.push(v);
        }
        // evaluate every g at x0 → must be ≡ 0 mod p²
        let xb = BigInt::from(x0.clone());
        let p2 = &p * &p;
        for (i, poly) in polys.iter().enumerate() {
            // poly stored low→high as BigUint (may wrap negative mod n)
            let mut acc = BigInt::zero();
            // coefficients are exact non-negative integers now (no mod-n wrap);
            // fm[0] = n − hi is the monic-ized residue of −hi, ≡ −hi (mod n),
            // so the integer polynomial still evaluates ≡ 0 mod p at x0.
            for coeff in poly.iter().rev() {
                acc = acc * xb.clone() + BigInt::from(coeff.clone());
            }
            let m2 = acc.mod_floor(&BigInt::from(p2.clone()));
            assert!(m2.is_zero(), "g_{}(x0) not ≡ 0 mod p²", i);
        }
        // build + LLL + evaluate h(x0)
        let xbig = BigUint::from(2u32).pow(36);
        let mut basis = IntegerMatrix::zeros(dim, dim);
        for (r, poly) in polys.iter().enumerate() {
            for (c, coeff) in poly.iter().enumerate() {
                basis.set(r, c, BigInt::from(coeff * xbig.pow(c as u32)));
            }
        }
        let red = Lll.lll(&basis).expect("lll");
        for r in 0..red.rows.min(4) {
            let row = red.row(r);
            let mut h: Vec<BigInt> = Vec::new();
            let mut ok = true;
            for (c, v) in row.iter().enumerate() {
                let sc = BigInt::from(xbig.pow(c as u32));
                let (qq, rr) = v.div_rem(&sc);
                if !rr.is_zero() { ok = false; break; }
                h.push(qq);
            }
            if !ok { continue; }
            let mut acc = BigInt::zero();
            for c in h.iter().rev() {
                acc = acc * &xb + c;
            }
            eprintln!("[diag] h_{}(x0) = {} (bits {})", r, acc, acc.abs().bits());
            if r < 2 {
                assert!(acc.is_zero(), "h_{}(x0) must be 0 over Z, got {}", r, acc);
            }
        }
    }
}

#[cfg(test)]
mod gcd_scale_tests {
    use super::*;

    #[test]
    fn poly_gcd_at_coppersmith_scale() {
        // deg-6 polys with ~2^470-bit coefficients sharing (x − x0),
        // mirroring the low_e Coppersmith vector scale
        let x0 = BigInt::from(209937112166413i64); // < 2^48
        // h(x) = (x − x0)·q(x) with q having ~2^420-bit coefficients
        let q1 = vec![
            -BigInt::from(2u32).pow(420) - BigInt::from(12345u32),
            BigInt::from(2u32).pow(418) + BigInt::from(777u32),
            -BigInt::from(2u32).pow(300),
            BigInt::from(2u32).pow(250) + BigInt::from(99u32),
            -BigInt::from(2u32).pow(150),
            BigInt::from(2u32).pow(90),
            BigInt::one(),
        ];
        let q2 = vec![
            BigInt::from(2u32).pow(430) - BigInt::from(555u32),
            -BigInt::from(2u32).pow(411),
            BigInt::from(2u32).pow(310) + BigInt::from(31u32),
            -BigInt::from(2u32).pow(240),
            BigInt::from(2u32).pow(140) + BigInt::from(7u32),
            BigInt::one(),
            BigInt::zero(),
        ];
        let mul = |a: &[BigInt], b: &[BigInt]| -> Vec<BigInt> {
            let mut out = vec![BigInt::zero(); a.len() + b.len() - 1];
            for (i, ai) in a.iter().enumerate() {
                for (j, bj) in b.iter().enumerate() {
                    out[i + j] = out[i + j].clone() + ai * bj;
                }
            }
            out
        };
        let lin = vec![-x0.clone(), BigInt::one()];
        let h1 = mul(&q1, &lin);
        let h2 = mul(&q2, &lin);
        let g = rat_poly_gcd(
            &h1.iter().map(Rat::from_int).collect::<Vec<_>>(),
            &h2.iter().map(Rat::from_int).collect::<Vec<_>>(),
        );
        assert_eq!(g.len(), 2, "gcd should be the linear factor (x − x0), got len {}", g.len());
        let ratio = Rat::zero() - g[0].clone() / g[1].clone();
        assert_eq!(ratio.num, x0);
    }
}

#[cfg(test)]
mod low_e_debug_tests {
    use super::*;
    use ctf_core::num::{is_probable_prime, modpow};

    fn bigint(v: i64) -> BigInt {
        BigInt::from(v)
    }

    #[test]
    fn low_e_manual_diagnosis() {
        let p = {
            let mut v = BigUint::from(2u32).pow(255) + 111u32;
            while !is_probable_prime(&v) { v += 1u32; }
            v
        };
        let q = {
            let mut v = BigUint::from(2u32).pow(255) + 333u32;
            while !is_probable_prime(&v) { v += 1u32; }
            v
        };
        let n = &p * &q;
        let pad: u64 = 0x0102_0304_0506_0708;
        let k = 48u32;
        let x0 = BigUint::from(209937112166413u64); // < 2^48
        let base = BigUint::from(pad) * BigUint::from(2u32).pow(k);
        let m_plain = base.clone() + &x0;
        let c = modpow(&m_plain, &BigUint::from(3u32), &n);

        let a_big = BigInt::from(base.clone()); // A = pad·2^48
        let ci = BigInt::from(c.clone());
        // (A + x)^3 − c ; root x0 (the unknown low bits of m_plain)
        let f = vec![
            a_big.pow(3) - ci,
            bigint(3) * a_big.pow(2),
            bigint(3) * a_big.clone(),
            BigInt::one(),
        ];
        // f(x0) must be ≡ 0 mod n
        let fv = poly_eval_bigint(&f, &BigInt::from(x0.clone()));
        assert!(to_mod(&fv, &n).is_zero(), "f(x0) not ≡ 0 mod n");

        // replicate small_roots construction
        let nb = BigUint::from(n.clone());
        let lead_mod = to_mod(f.last().unwrap(), &nb);
        let inv = mod_inverse(&lead_mod, &nb).unwrap();
        let fm: Vec<BigUint> = f.iter().map(|cc| to_mod(cc, &nb) * &inv % &nb).collect();
        let (m, t) = (2usize, 1usize);
        let d = 3usize;
        let k_base = (1u64 * m as u64 + 0) ; // ceil(βm) = m for β=1
        let dim = m * d + t;
        let mul_u = |a: &[BigUint], b: &[BigUint]| -> Vec<BigUint> {
            let mut out = vec![BigUint::zero(); a.len() + b.len() - 1];
            for (i, ai) in a.iter().enumerate() {
                for (j, bj) in b.iter().enumerate() {
                    out[i + j] = out[i + j].clone() + ai * bj;
                }
            }
            out
        };
        let mut fpow: Vec<Vec<BigUint>> = vec![vec![BigUint::one()]];
        for _ in 0..m {
            let prev = fpow.last().unwrap().clone();
            fpow.push(mul_u(&prev, &fm));
        }
        let mut polys: Vec<Vec<BigUint>> = Vec::new();
        for i in 0..m {
            let npow = if k_base > i as u64 { BigUint::from(n.clone()).pow((k_base - i as u64) as u32) } else { BigUint::one() };
            for j in 0..d {
                let mut v = vec![BigUint::zero(); j];
                v.extend(fpow[i].iter().map(|cc| cc * &npow));
                polys.push(v);
            }
        }
        for i in 0..t {
            let mut v = vec![BigUint::zero(); i];
            v.extend(fpow[m].iter().cloned());
            polys.push(v);
        }
        // each g(x0) must be ≡ 0 mod N^m = N²
        let xb = BigInt::from(x0.clone());
        let nm = BigUint::from(n.clone()).pow(2u32);
        for (i, poly) in polys.iter().enumerate() {
            let mut acc = BigInt::zero();
            for cc in poly.iter().rev() {
                acc = acc * &xb + BigInt::from(cc.clone());
            }
            let r = acc.mod_floor(&BigInt::from(nm.clone()));
            assert!(r.is_zero(), "g_{}(x0) not ≡ 0 mod N²", i);
        }
        eprintln!("[diag] all {} rows ≡ 0 mod N² ✓", polys.len());
        // LLL + evaluate h(x0)
        let xbig = BigUint::from(2u32).pow(48);
        let mut basis = IntegerMatrix::zeros(dim, dim);
        for (r, poly) in polys.iter().enumerate() {
            for (cc, coeff) in poly.iter().enumerate() {
                basis.set(r, cc, BigInt::from(coeff * xbig.pow(cc as u32)));
            }
        }
        let red = Lll.lll(&basis).expect("lll");
        for r in 0..red.rows.min(3) {
            let row = red.row(r);
            let mut acc = BigInt::zero();
            let mut ok = true;
            for (cc, v) in row.iter().enumerate() {
                let sc = BigInt::from(xbig.pow(cc as u32));
                let (qq, rr) = v.div_rem(&sc);
                if !rr.is_zero() { ok = false; break; }
                acc = acc * &xb + qq;
            }
            eprintln!("[diag] h_{}: ok={} |h(x0)| bits = {}", r, ok, if ok { acc.abs().bits() } else { 0 });
        }
    }
}



#[cfg(test)]
mod scan_tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn sign_scan_finds_integer_root() {
        // h = (x − 43405557070)·(x² + 3x + 7) — the linear factor's root is
        // inside [0, 2^36); the quadratic has no real roots
        let x0: i64 = 43405557070;
        let h = vec![
            BigInt::from(-x0 * 7),
            BigInt::from(7 - 3 * x0),
            BigInt::from(3 - x0),
            BigInt::one(),
        ];
        // verification target: f = x − x0, n = x0·65537 → gcd(f(x0), n) = x0
        let n = BigUint::from_str("2845840838424382477907210").unwrap(); // x0·65537
        let fv = vec![BigInt::from(-x0), BigInt::one()];
        let roots = gcd_root_candidates(&h, &fv, &n, 36);
        eprintln!("scan roots = {:?}", roots);
        assert!(roots.iter().any(|r| r == &BigUint::from(x0 as u64)), "root not found: {:?}", roots);
    }
}

#[cfg(test)]
mod sturm_debug_tests {
    use super::*;

    #[test]
    fn sturm_chain_smoke() {
        // p = x² − 2x − 15 = (x−5)(x+3); squarefree; chain = [p, 2x−2, 16]
        let p = vec![Rat::from_int(&BigInt::from(-15)), Rat::from_int(&BigInt::from(-2)), Rat::one()];
        let chain = sturm_chain(&p);
        eprintln!("chain len = {}", chain.len());
        for (i, c) in chain.iter().enumerate() {
            eprintln!("  p{} = {:?}", i, c.iter().map(|r| (r.num.to_i64().unwrap(), r.den.to_i64().unwrap())).collect::<Vec<_>>());
        }
        let v0 = sturm_variations(&chain, &BigInt::from(0));
        let v10 = sturm_variations(&chain, &BigInt::from(10));
        eprintln!("V(0) = {}, V(10) = {}", v0, v10);
        assert_eq!(v0 - v10, 1, "exactly one root in (0, 10]");
        // through gcd_root_candidates: f = x − 5, n = 5·65537
        let n = BigUint::from(5u32) * BigUint::from(65537u32);
        let f = vec![BigInt::from(-5), BigInt::one()];
        let h_int: Vec<BigInt> = p.iter().map(|c| c.num.clone() / c.den.clone()).collect();
        let roots = gcd_root_candidates(&h_int, &f, &n, 10);
        assert!(roots.iter().any(|r| r == &BigUint::from(5u32)), "root 5 not found: {:?}", roots);
    }
}

#[cfg(test)]
mod apbq_tests {
    use super::*;
    use ctf_core::num::is_probable_prime;

    fn gen_prime(bits: u32, offset: u64) -> BigUint {
        let mut v = BigUint::from(2u32).pow(bits)
            | (BigUint::from(1u32) << (bits - 1))
            | BigUint::from(1u32);
        v += BigUint::from(offset) * BigUint::from(2u32).pow(8);
        loop {
            if is_probable_prime(&v) {
                return v.clone();
            }
            v += BigUint::from(2u32); // stay odd, accumulate
        }
    }

}
