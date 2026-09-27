//! Small dense matrices over Z/N with the operations the Hill cipher and
//! later lattice work need: determinant (mod N), adjugate inverse mod N.
//! Sizes 2x2 and 3x3 are exact and unit-tested; larger sizes are on demand
//! (full Gaussian elimination lands with the lattice track).

/// Row-major square matrix over Z/N.
#[derive(Debug, Clone)]
pub struct Matrix {
    pub size: usize,
    pub data: Vec<i64>,
    pub modulus: i64,
}

impl Matrix {
    pub fn new(size: usize, modulus: i64, data: &[i64]) -> Option<Self> {
        if size == 0 || data.len() != size * size || modulus <= 1 {
            return None;
        }
        Some(Self {
            size,
            modulus,
            data: data.iter().map(|v| v.rem_euclid(modulus)).collect(),
        })
    }

    pub fn get(&self, r: usize, c: usize) -> i64 {
        self.data[r * self.size + c]
    }

    /// determinant mod modulus via cofactor expansion (sizes 2..=4).
    pub fn det(&self) -> i64 {
        let n = self.size;
        let m = self.modulus;
        let det: i64 = match n {
            2 => self.get(0, 0) * self.get(1, 1) - self.get(0, 1) * self.get(1, 0),
            3 => {
                (self.get(0, 0) * (self.get(1, 1) * self.get(2, 2) - self.get(1, 2) * self.get(2, 1)))
                    - (self.get(0, 1) * (self.get(1, 0) * self.get(2, 2) - self.get(1, 2) * self.get(2, 0)))
                    + (self.get(0, 2) * (self.get(1, 0) * self.get(2, 1) - self.get(1, 1) * self.get(2, 0)))
            }
            4 => {
                // Laplace over the first row
                let mut acc = 0i64;
                for c in 0..4 {
                    let mut minor = Vec::with_capacity(9);
                    for r in 1..4 {
                        for cc in 0..4 {
                            if cc != c {
                                minor.push(self.get(r, cc));
                            }
                        }
                    }
                    let sub = Matrix::new(3, m, &minor).unwrap();
                    let sign = if c % 2 == 0 { 1 } else { -1 };
                    acc += sign * self.get(0, c) * sub.det();
                }
                acc
            }
            _ => 0,
        };
        det.rem_euclid(m)
    }

    /// modular multiplicative inverse of x mod m (m small, trial-based).
    fn inv_mod(x: i64, m: i64) -> Option<i64> {
        let x = x.rem_euclid(m);
        (1..m).find(|&i| (i * x) % m == 1)
    }

    /// Adjugate inverse mod N. Returns None when det has no inverse.
    pub fn inverse(&self) -> Option<Matrix> {
        let n = self.size;
        let m = self.modulus;
        let det = self.det();
        let det_inv = Self::inv_mod(det, m)?;
        let mut out = vec![0i64; n * n];
        match n {
            2 => {
                out[0] = self.get(1, 1);
                out[1] = -self.get(0, 1);
                out[2] = -self.get(1, 0);
                out[3] = self.get(0, 0);
            }
            3 => {
                for r in 0..3 {
                    for c in 0..3 {
                        // minor over the other rows/cols in ASCENDING order
                        // (cyclic order would flip the 2x2 det sign)
                        let others_r: Vec<usize> = (0..3).filter(|&x| x != r).collect();
                        let others_c: Vec<usize> = (0..3).filter(|&x| x != c).collect();
                        let minor = self.get(others_r[0], others_c[0])
                            * self.get(others_r[1], others_c[1])
                            - self.get(others_r[0], others_c[1])
                                * self.get(others_r[1], others_c[0]);
                        let sign = if (r + c) % 2 == 0 { 1 } else { -1 };
                        // adjugate = transpose of cofactor matrix: out[c][r]
                        out[c * n + r] = sign * minor;
                    }
                }
            }
            _ => return None,
        }
        Some(Matrix {
            size: n,
            modulus: m,
            data: out.into_iter().map(|v| (v * det_inv).rem_euclid(m)).collect(),
        })
    }

    /// Multiply this matrix by a column vector of length `size` mod N.
    pub fn mul_vec(&self, v: &[i64]) -> Option<Vec<i64>> {
        if v.len() != self.size {
            return None;
        }
        Some((0..self.size)
            .map(|r| {
                let acc: i64 = (0..self.size).map(|c| self.get(r, c) * v[c]).sum();
                acc.rem_euclid(self.modulus)
            })
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn det_mod26() {
        let m = Matrix::new(2, 26, &[3, 3, 2, 5]).unwrap();
        assert_eq!(m.det(), 9); // det = 3*5 - 3*2 = 9
    }

    #[test]
    fn inverse_roundtrip_mod26() {
        let m = Matrix::new(2, 26, &[3, 3, 2, 5]).unwrap();
        let inv = m.inverse().expect("det 9 invertible mod 26");
        // m * inv == identity
        for i in 0..2 {
            let v = [if i == 0 { 1 } else { 0 }, if i == 1 { 1 } else { 0 }];
            let prod = m.mul_vec(&{
                // inv as column application: use inv.mul_vec on unit vector
                let iv = inv.mul_vec(&v).unwrap();
                iv
            });
            // apply m then inv (or inv then m) — unit check: inv·m·e_i == e_i
            let unit = inv.mul_vec(&m.mul_vec(&v).unwrap()).unwrap();
            let _ = prod;
            assert_eq!(unit, v);
        }
    }

    #[test]
    fn inverse_3x3_mod26() {
        let m = Matrix::new(3, 26, &[6, 24, 1, 13, 16, 10, 20, 17, 15]).unwrap();
        // classic Hill example: det = 441 mod 26 = 29? known invertible
        let inv = m.inverse().expect("classic hill key invertible mod 26");
        let v = [1, 2, 3];
        let unit = inv.mul_vec(&m.mul_vec(&v).unwrap()).unwrap();
        assert_eq!(unit, v);
    }

    #[test]
    fn non_invertible_detected() {
        let m = Matrix::new(2, 26, &[2, 4, 6, 8]).unwrap(); // det = -8 = 18 mod 26, gcd(18,26)=2
        assert!(m.inverse().is_none());
    }
}
