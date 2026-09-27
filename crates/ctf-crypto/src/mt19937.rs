//! MT19937 (梅森旋转算法): reference-aligned generator, temper/untemper, and
//! state recovery + prediction from 624 consecutive outputs (randcrack
//! equivalent for the 32-bit output stream). Cross-checked against CPython's
//! `random.getrandbits(32)` seeding (`init_by_array`).

const N: usize = 624;
const M: usize = 397;
const MATRIX_A: u32 = 0x9908_b0df;
const UPPER_MASK: u32 = 0x8000_0000;
const LOWER_MASK: u32 = 0x7fff_ffff;

/// Reference MT19937 generator (init_genrand / init_by_array seeding).
#[derive(Clone)]
pub struct Mt19937 {
    mt: [u32; N],
    index: usize,
}

impl Mt19937 {
    /// Classic single-word seeding (init_genrand).
    pub fn new(seed: u32) -> Self {
        let mut mt = [0u32; N];
        mt[0] = seed;
        for i in 1..N {
            mt[i] = 1812433253u32
                .wrapping_mul(mt[i - 1] ^ (mt[i - 1] >> 30))
                .wrapping_add(i as u32);
        }
        Self { mt, index: N }
    }

    /// CPython `random.seed(int)` compatible seeding (init_by_array on the
    /// 32-bit words of the absolute value).
    pub fn from_seed_words(key: &[u32]) -> Self {
        let mut mt = [0u32; N];
        mt[0] = 19650218;
        for i in 1..N {
            mt[i] = 1812433253u32
                .wrapping_mul(mt[i - 1] ^ (mt[i - 1] >> 30))
                .wrapping_add(i as u32);
        }
        let key = if key.is_empty() { &[0u32] } else { key };
        let mut i = 1usize;
        let mut j = 0usize;
        let rounds = N.max(key.len());
        for _ in 0..rounds {
            mt[i] = (mt[i] ^ (mt[i - 1] ^ (mt[i - 1] >> 30)).wrapping_mul(1664525))
                .wrapping_add(key[j])
                .wrapping_add(j as u32);
            i += 1;
            j += 1;
            if i >= N {
                mt[0] = mt[N - 1];
                i = 1;
            }
            if j >= key.len() {
                j = 0;
            }
        }
        for _ in 0..(N - 1) {
            mt[i] = (mt[i] ^ (mt[i - 1] ^ (mt[i - 1] >> 30)).wrapping_mul(1566083941))
                .wrapping_sub(i as u32);
            i += 1;
            if i >= N {
                mt[0] = mt[N - 1];
                i = 1;
            }
        }
        mt[0] = 0x8000_0000;
        Self { mt, index: N }
    }

    fn twist(&mut self) {
        let mut new_state = [0u32; N];
        for i in 0..N {
            let nxt = if i + 1 < N { self.mt[i + 1] } else { new_state[0] };
            let y = (self.mt[i] & UPPER_MASK) | (nxt & LOWER_MASK);
            let mid = if i + M < N {
                self.mt[i + M]
            } else {
                new_state[i + M - N]
            };
            let mut v = mid ^ (y >> 1);
            if y & 1 == 1 {
                v ^= MATRIX_A;
            }
            new_state[i] = v;
        }
        self.mt = new_state;
        self.index = 0;
    }

    /// Next raw 32-bit output (genrand_int32 + temper).
    pub fn next_u32(&mut self) -> u32 {
        if self.index >= N {
            self.twist();
        }
        let y = self.mt[self.index];
        self.index += 1;
        temper(y)
    }

    /// Regenerate from a known (untampered) state; index set to N so the next
    /// call twists, exactly like a state that just produced its 624th output.
    pub fn from_state(state: [u32; N]) -> Self {
        Self { mt: state, index: N }
    }
}

/// MT19937 output tempering transform.
pub fn temper(y: u32) -> u32 {
    let mut y = y;
    y ^= y >> 11;
    y ^= (y << 7) & 0x9d2c_5680;
    y ^= (y << 15) & 0xefc6_0000;
    y ^= y >> 18;
    y
}

/// Inverse of [`temper`] — recovers the raw state word from an output.
pub fn untemper(y: u32) -> u32 {
    let mut y = y;
    // invert y ^= y >> 18
    y ^= y >> 18;
    // invert y ^= (y << 15) & 0xefc60000
    y ^= (y << 15) & 0xefc6_0000;
    // invert y ^= (y << 7) & 0x9d2c5680
    y = unshift_left(y, 7, 0x9d2c_5680);
    // invert y ^= y >> 11
    y = unshift_right(y, 11);
    y
}

fn unshift_right(y: u32, shift: u32) -> u32 {
    let mut x = y;
    for _ in 0..32 / shift + 1 {
        x = y ^ (x >> shift);
    }
    x
}

fn unshift_left(y: u32, shift: u32, mask: u32) -> u32 {
    let mut x = y;
    for _ in 0..32 / shift + 1 {
        x = y ^ ((x << shift) & mask);
    }
    x
}

/// Recover the internal state from 624 consecutive outputs and predict the
/// next values.
pub struct MtPredictor {
    inner: Mt19937,
}

impl MtPredictor {
    /// Build from exactly 624 consecutive 32-bit outputs.
    pub fn new(outputs: &[u32]) -> Option<Self> {
        if outputs.len() < N {
            return None;
        }
        let mut state = [0u32; N];
        for (i, &o) in outputs.iter().take(N).enumerate() {
            state[i] = untemper(o);
        }
        Some(Self {
            inner: Mt19937::from_state(state),
        })
    }

    /// Predict the next output after the consumed window.
    pub fn next_u32(&mut self) -> u32 {
        self.inner.next_u32()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Vectors produced by CPython `random.seed(1234); random.getrandbits(32)`.
    const PY_FIRST3: [u32; 3] = [4150886329, 3342196574, 1892932127];
    const PY_NEXT3: [u32; 3] = [3715477445, 938706668, 2293463937];

    #[test]
    fn matches_canonical_seed5489() {
        // Matsumoto's reference vector for init_genrand(5489)
        let mut mt = Mt19937::new(5489);
        assert_eq!(mt.next_u32(), 3499211612);
        assert_eq!(mt.next_u32(), 581869302);
        assert_eq!(mt.next_u32(), 3890346734);
    }

    #[test]
    fn matches_python_sequence() {
        let mut mt = Mt19937::from_seed_words(&[1234]);
        let mut outs = Vec::with_capacity(627);
        for _ in 0..627 {
            outs.push(mt.next_u32());
        }
        assert_eq!(&outs[0..3], &PY_FIRST3);
        assert_eq!(&outs[624..627], &PY_NEXT3);
    }

    #[test]
    fn temper_roundtrip() {
        for v in [0u32, 1, 0xdead_beef, 0x8000_0000, u32::MAX, 123456789] {
            assert_eq!(untemper(temper(v)), v);
        }
    }

    #[test]
    fn predicts_after_624_outputs() {
        let mut mt = Mt19937::from_seed_words(&[1234]);
        let mut window = Vec::with_capacity(N);
        for _ in 0..N {
            window.push(mt.next_u32());
        }
        let upcoming = [mt.next_u32(), mt.next_u32(), mt.next_u32()];
        let mut predictor = MtPredictor::new(&window).unwrap();
        assert_eq!(predictor.next_u32(), upcoming[0]);
        assert_eq!(predictor.next_u32(), upcoming[1]);
        assert_eq!(predictor.next_u32(), upcoming[2]);
    }
}
