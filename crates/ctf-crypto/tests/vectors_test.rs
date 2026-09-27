//! End-to-end attack tests against `tests/vectors.json` — synthetic RSA/LCG
//! instances generated locally (Python + pycryptodome) so every branch of the
//! decision tree is exercised without platform data.

use num_bigint::BigUint;
use num_traits::Num;
use serde::Deserialize;

use ctf_crypto::rsa::{
    auto_attack, common_modulus, decrypt, dpdq, dp_leak, factor_p1, factor_rho, fermat, from_pq,
    hastad_broadcast, low_e, rabin, shared_prime, wiener, RsaParams,
};

fn bu(s: &str) -> BigUint {
    BigUint::from_str_radix(s, 10).expect("decimal vector")
}

#[derive(Deserialize)]
struct Vectors {
    from_pq: FromPq,
    wiener: Wiener,
    low_e: LowE,
    common_modulus: CommonModulus,
    hastad: Hastad,
    fermat: Fermat,
    rabin: Rabin,
    dpdq: Dpdq,
    dp_leak: DpLeak,
    pollard_p1: PollardP1,
    pollard_rho: PollardRho,
    shared_prime: SharedPrime,
    lcg: Lcg,
}

#[derive(Deserialize)]
struct FromPq {
    p: String, q: String, n: String, e: u32, c: String, m: String,
}
#[derive(Deserialize)]
struct Wiener {
    n: String, e: String, c: String, d: String, m: String,
}
#[derive(Deserialize)]
struct LowE {
    n: String, e: u32, c: String, m: String,
}
#[derive(Deserialize)]
struct CommonModulus {
    n: String, e1: u32, e2: u32, c1: String, c2: String, m: String,
}
#[derive(Deserialize)]
struct Hastad {
    ns: Vec<String>, cs: Vec<String>, e: u32, m: String,
}
#[derive(Deserialize)]
struct Fermat {
    n: String, e: u32, c: String, m: String,
}
#[derive(Deserialize)]
struct Rabin {
    p: String, q: String, n: String, c: String, m: String,
}
#[derive(Deserialize)]
struct Dpdq {
    p: String, q: String, dp: String, dq: String, c: String, m: String,
}
#[derive(Deserialize)]
struct DpLeak {
    n: String, e: u32, dp: String, c: String, m: String,
}
#[derive(Deserialize)]
struct PollardP1 {
    n: String, e: u32, c: String, m: String,
}
#[derive(Deserialize)]
struct PollardRho {
    n: String, p: String, q: String,
}
#[derive(Deserialize)]
struct SharedPrime {
    n1: String, n2: String, p: String,
}
#[derive(Deserialize)]
struct Lcg {
    a: u64, b: u64, m: u64, xs: Vec<u64>,
}

#[test]
fn vectors() {
    let raw = include_str!("vectors.json");
    let v: Vectors = serde_json::from_str(raw).expect("vectors parse");

    // from_pq
    let v2 = &v.from_pq;
    let m = from_pq(&bu(&v2.c), &bu(&v2.e.to_string()), &bu(&v2.p), &bu(&v2.q)).unwrap();
    assert_eq!(m, bu(&v2.m));

    // wiener
    let v2 = &v.wiener;
    let d = wiener(&bu(&v2.e), &bu(&v2.n)).expect("wiener recovers d");
    assert_eq!(d, bu(&v2.d));
    assert_eq!(decrypt(&bu(&v2.c), &d, &bu(&v2.n)).unwrap(), bu(&v2.m));

    // low_e
    let v2 = &v.low_e;
    assert_eq!(
        low_e(&bu(&v2.c), &bu(&v2.e.to_string()), &bu(&v2.n), 100_000).unwrap(),
        bu(&v2.m)
    );

    // common modulus
    let v2 = &v.common_modulus;
    assert_eq!(
        common_modulus(
            &bu(&v2.c1), &bu(&v2.c2),
            &bu(&v2.e1.to_string()), &bu(&v2.e2.to_string()),
            &bu(&v2.n),
        )
        .unwrap(),
        bu(&v2.m)
    );

    // hastad broadcast
    let v2 = &v.hastad;
    let cs: Vec<BigUint> = v2.cs.iter().map(|s| bu(s)).collect();
    let ns: Vec<BigUint> = v2.ns.iter().map(|s| bu(s)).collect();
    assert_eq!(
        hastad_broadcast(&cs, &ns, &bu(&v2.e.to_string())).unwrap(),
        bu(&v2.m)
    );

    // fermat
    let v2 = &v.fermat;
    let (p, q) = fermat(&bu(&v2.n), 100_000).expect("fermat factors close primes");
    assert_eq!(
        from_pq(&bu(&v2.c), &bu(&v2.e.to_string()), &p, &q).unwrap(),
        bu(&v2.m)
    );

    // rabin
    let v2 = &v.rabin;
    let roots = rabin(&bu(&v2.c), &bu(&v2.p), &bu(&v2.q)).unwrap();
    assert!(roots.iter().any(|r| *r == bu(&v2.m)));

    // dpdq
    let v2 = &v.dpdq;
    assert_eq!(
        dpdq(&bu(&v2.p), &bu(&v2.q), &bu(&v2.dp), &bu(&v2.dq), &bu(&v2.c)).unwrap(),
        bu(&v2.m)
    );

    // dp_leak
    let v2 = &v.dp_leak;
    let e = bu(&v2.e.to_string());
    let (p, q) = dp_leak(&e, &bu(&v2.n), &bu(&v2.dp)).expect("dp_leak factors n");
    assert_eq!(from_pq(&bu(&v2.c), &e, &p, &q).unwrap(), bu(&v2.m));

    // pollard p-1
    let v2 = &v.pollard_p1;
    let (p, q) = factor_p1(&bu(&v2.n), 100_000).expect("p-1 smooth factor");
    assert_eq!(
        from_pq(&bu(&v2.c), &bu(&v2.e.to_string()), &p, &q).unwrap(),
        bu(&v2.m)
    );

    // pollard rho
    let v2 = &v.pollard_rho;
    let (p, q) = factor_rho(&bu(&v2.n), 16).expect("rho factors 128-bit semiprime");
    assert_eq!(&p * &q, bu(&v2.n));

    // shared prime
    let v2 = &v.shared_prime;
    let hits = shared_prime(&[bu(&v2.n1), bu(&v2.n2)]);
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].2, bu(&v2.p));

    // auto_attack decision tree on a few shapes
    let auto_pq = RsaParams {
        p: Some(bu(&v.from_pq.p)),
        q: Some(bu(&v.from_pq.q)),
        c: Some(bu(&v.from_pq.c)),
        e: Some(bu(&v.from_pq.e.to_string())),
        ..Default::default()
    };
    assert_eq!(auto_attack(&auto_pq).unwrap(), bu(&v.from_pq.m));

    let auto_wiener = RsaParams {
        n: Some(bu(&v.wiener.n)),
        e: Some(bu(&v.wiener.e)),
        c: Some(bu(&v.wiener.c)),
        ..Default::default()
    };
    assert_eq!(auto_attack(&auto_wiener).unwrap(), bu(&v.wiener.m));

    let auto_low = RsaParams {
        n: Some(bu(&v.low_e.n)),
        e: Some(bu(&v.low_e.e.to_string())),
        c: Some(bu(&v.low_e.c)),
        ..Default::default()
    };
    assert_eq!(auto_attack(&auto_low).unwrap(), bu(&v.low_e.m));

    let auto_cm = RsaParams {
        n: Some(bu(&v.common_modulus.n)),
        c1: Some(bu(&v.common_modulus.c1)),
        c2: Some(bu(&v.common_modulus.c2)),
        e1: Some(bu(&v.common_modulus.e1.to_string())),
        e2: Some(bu(&v.common_modulus.e2.to_string())),
        ..Default::default()
    };
    assert_eq!(auto_attack(&auto_cm).unwrap(), bu(&v.common_modulus.m));

    let auto_dp = RsaParams {
        n: Some(bu(&v.dp_leak.n)),
        e: Some(bu(&v.dp_leak.e.to_string())),
        dp: Some(bu(&v.dp_leak.dp)),
        c: Some(bu(&v.dp_leak.c)),
        ..Default::default()
    };
    assert_eq!(auto_attack(&auto_dp).unwrap(), bu(&v.dp_leak.m));

    // LCG round trip through u64-backed BigUints
    let l = &v.lcg;
    let m = BigUint::from(l.m);
    let a = BigUint::from(l.a);
    let b = BigUint::from(l.b);
    let xs: Vec<BigUint> = l.xs.iter().map(|x| BigUint::from(*x)).collect();
    let fa = ctf_crypto::lcg::find_a(&xs[0], &xs[1], &xs[2], &m).unwrap();
    assert_eq!(fa, a);
    assert_eq!(ctf_crypto::lcg::find_b(&xs[0], &xs[1], &fa, &m), b);
    assert_eq!(
        ctf_crypto::lcg::predict_next(&xs[5], &a, &b, &m, 1)[0],
        ctf_crypto::lcg::step(&xs[5], &a, &b, &m)
    );
}
