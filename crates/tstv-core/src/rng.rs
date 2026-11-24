//! Deterministic pseudo-randomness.
//!
//! The simulator must replay identically on every machine, so we never touch
//! `getrandom`.  [`SplitMix64`] is used only to expand a 64-bit seed into key
//! material and large test populations; it is *not* used as a stream cipher.

/// SplitMix64, from Steele, Lea & Flood (2014).  Passes BigCrush; period 2^64.
///
/// Used here purely as a deterministic byte expander for seeds and test fixtures.
/// Never use it to protect real key material — the whole point of this stack is
/// that key derivation goes through [`crate::prf`].
#[derive(Clone)]
pub struct SplitMix64 {
    state: u64,
}

impl SplitMix64 {
    pub const fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    pub fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    pub fn next_u32(&mut self) -> u32 {
        (self.next_u64() >> 32) as u32
    }

    /// Uniform in `0..bound`.  Uses Lemire's multiply-shift with rejection so the
    /// result is unbiased, which keeps stochastic simulations reproducible.
    pub fn below(&mut self, bound: u32) -> u32 {
        debug_assert!(bound > 0);
        let mut x = self.next_u32();
        let mut m = (x as u64) * (bound as u64);
        let mut low = m as u32;
        if low < bound {
            let threshold = bound.wrapping_neg() % bound;
            while low < threshold {
                x = self.next_u32();
                m = (x as u64) * (bound as u64);
                low = m as u32;
            }
        }
        (m >> 32) as u32
    }

    /// Fill a buffer with expanded bytes.
    pub fn fill(&mut self, out: &mut [u8]) {
        let mut chunks = out.chunks_exact_mut(8);
        for c in &mut chunks {
            c.copy_from_slice(&self.next_u64().to_le_bytes());
        }
        let rem = chunks.into_remainder();
        if !rem.is_empty() {
            let bytes = self.next_u64().to_le_bytes();
            rem.copy_from_slice(&bytes[..rem.len()]);
        }
    }

    pub fn bytes<const N: usize>(&mut self) -> [u8; N] {
        let mut b = [0u8; N];
        self.fill(&mut b);
        b
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_for_seed() {
        let a: Vec<u64> = (0..8).map(|_| SplitMix64::new(7).next_u64()).collect();
        assert!(a.iter().all(|&v| v == a[0]));

        let mut x = SplitMix64::new(7);
        let mut y = SplitMix64::new(7);
        for _ in 0..1000 {
            assert_eq!(x.next_u64(), y.next_u64());
        }
    }

    #[test]
    fn below_is_in_range_and_roughly_uniform() {
        let mut rng = SplitMix64::new(0xDEAD_BEEF);
        let mut buckets = [0u32; 10];
        for _ in 0..100_000 {
            let v = rng.below(10);
            assert!(v < 10);
            buckets[v as usize] += 1;
        }
        for &b in &buckets {
            assert!((9_000..11_000).contains(&b), "bucket skew: {b}");
        }
    }

    #[test]
    fn fill_matches_struct_for_partial_chunks() {
        let mut a = SplitMix64::new(1);
        let mut out = [0u8; 13];
        a.fill(&mut out);
        let mut b = SplitMix64::new(1);
        let full: [u8; 8] = b.next_u64().to_le_bytes();
        let tail = b.next_u64().to_le_bytes();
        assert_eq!(&out[..8], &full);
        assert_eq!(&out[8..], &tail[..5]);
    }
}
