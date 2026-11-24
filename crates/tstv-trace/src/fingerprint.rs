//! q-ary collusion-resistant fingerprinting, engineering grade.
//!
//! ## What this is — and what it is not
//!
//! When several issued cards feed one pirate relay, per-card tracing by
//! elimination is not enough: the relay can mix contributions.  A fingerprint
//! code assigns each card a *codeword*; the set of colluders produces an
//! observed word; the decoder names a guilty card.
//!
//! This is **not** Tardos's asymptotically optimal scheme with a proven
//! bound.  It is a practical q-ary code:
//!
//! * each user's symbol in each column is drawn uniformly from `0..q`,
//! * colluders combine by majority-vote per column (the classic "majority
//!   attack" — the strongest simple collusion strategy), with ties broken
//!   adversarially,
//! * decoding scores each user by how often its symbol matches the observed
//!   word and accuses the top scorer(s).
//!
//! On the parameters this system uses (q=8, m≈4·c·log N, c ≤ 5) the empirical
//! false-accusation rate is ≈0 and at least one true colluder is named in the
//! overwhelming majority of trials — verified in the tests below.  For large
//! coalitions a proper Tardos or bias-based code should replace this; the API
//! is written so that is a drop-in.
//!
//! ## Where the codeword lives
//!
//! A codeword symbol is realized as *which of `q` sub-key-epochs* a card is
//! placed into for one **tracing round** (a round = one full-column probe).  The
//! card obeys the symbol via its EMM; the relay's observable liveness across the
//! round reveals the mixed symbol.  Values still never differ; only key epochs do.

use tstv_core::rng::SplitMix64;

/// A q-ary fingerprint codebook.
#[derive(Clone, Debug)]
pub struct FingerprintCode {
    pub q: u8,
    pub columns: usize,
    /// `codewords[user][column]` in `0..q`.
    pub codewords: Vec<Vec<u8>>,
    seed: u64,
}

/// Decoder verdict.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TraceResult {
    /// Users accused, best-first by score.
    pub accused: Vec<usize>,
    /// Score margin between the top accused and the best non-accused.
    pub margin: i32,
}

impl FingerprintCode {
    /// Build `users` codewords of `columns` q-ary symbols, deterministically
    /// from `seed`.
    pub fn generate(users: usize, columns: usize, q: u8, seed: u64) -> Self {
        assert!(q >= 2, "q must be >= 2");
        let mut rng = SplitMix64::new(seed);
        let mut codewords = Vec::with_capacity(users);
        for _ in 0..users {
            let mut w = Vec::with_capacity(columns);
            for _ in 0..columns {
                w.push(rng.below(q as u32) as u8);
            }
            codewords.push(w);
        }
        Self {
            q,
            columns,
            codewords,
            seed,
        }
    }

    /// Code length recommended for `users` and coalition bound `c`
    /// (`m ≈ 4·c·⌈log2 N⌉`, the usual practical rule of thumb).
    pub fn recommended_columns(users: usize, c: usize) -> usize {
        let logn = (usize::BITS - users.max(1).leading_zeros()) as usize;
        4 * c * logn.max(1)
    }

    pub fn users(&self) -> usize {
        self.codewords.len()
    }

    /// Colluder strategy: per-column majority; ties resolved to `tie_symbol`
    /// (an adversary picks the tie-break to hurt tracing most).
    ///
    /// Returns the observable word.
    pub fn majority_collude(&self, colluders: &[usize], tie_symbol: u8) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.columns);
        let mut counts = vec![0u32; self.q as usize];
        for col in 0..self.columns {
            counts.iter_mut().for_each(|c| *c = 0);
            for &u in colluders {
                counts[self.codewords[u][col] as usize] += 1;
            }
            let max = *counts.iter().max().unwrap();
            let winners: Vec<u8> = (0..self.q).filter(|&s| counts[s as usize] == max).collect();
            let sym = if winners.len() == 1 {
                winners[0]
            } else if winners.contains(&tie_symbol) {
                tie_symbol
            } else {
                winners[0]
            };
            out.push(sym);
        }
        out
    }

    /// Score every user against the observed word: `score(u)` = number of
    /// columns where `codeword[u][col] == observed[col]`.
    pub fn scores(&self, observed: &[u8]) -> Vec<i32> {
        assert_eq!(observed.len(), self.columns);
        self.codewords
            .iter()
            .map(|w| w.iter().zip(observed).filter(|(a, b)| a == b).count() as i32)
            .collect()
    }

    /// Decode: accuse every user whose score is within `tolerance` of the top
    /// score (tolerance 0 = just the argmax).  Returns accused best-first.
    pub fn decode(&self, observed: &[u8], tolerance: i32) -> TraceResult {
        let scores = self.scores(observed);
        let top = *scores.iter().max().unwrap_or(&0);
        let mut ranked: Vec<usize> = (0..scores.len()).collect();
        ranked.sort_by(|&a, &b| scores[b].cmp(&scores[a]).then(a.cmp(&b)));
        let accused: Vec<usize> = ranked
            .iter()
            .copied()
            .take_while(|&u| scores[u] >= top - tolerance)
            .collect();
        let best_non_accused = ranked
            .iter()
            .copied()
            .find(|u| !accused.contains(u))
            .map(|u| scores[u])
            .unwrap_or(i32::MIN);
        TraceResult {
            margin: top - best_non_accused,
            accused,
        }
    }

    pub fn codeword(&self, user: usize) -> &[u8] {
        &self.codewords[user]
    }

    pub fn seed(&self) -> u64 {
        self.seed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// For each coalition size, run many random coalitions and measure
    /// (a) at least one true colluder accused, (b) no innocent accused.
    #[test]
    fn majority_coalitions_are_named_without_false_accusations() {
        let users = 2000usize;
        let mut rng = SplitMix64::new(0xF1F0_9E12);
        for c in 1..=5usize {
            let cols = FingerprintCode::recommended_columns(users, c);
            let code = FingerprintCode::generate(users, cols, 8, 0xABCD_0000 + c as u64);
            let mut caught = 0;
            let mut false_acc = 0;
            let trials = if c <= 3 { 200 } else { 80 };
            for _ in 0..trials {
                // Pick a random coalition of distinct users.
                let mut members = Vec::new();
                while members.len() < c {
                    let u = rng.below(users as u32) as usize;
                    if !members.contains(&u) {
                        members.push(u);
                    }
                }
                // Adversarial tie-break varies per trial.
                let tie = rng.below(8) as u8;
                let observed = code.majority_collude(&members, tie);
                let res = code.decode(&observed, 0);
                if res.accused.iter().any(|u| members.contains(u)) {
                    caught += 1;
                }
                if res.accused.iter().any(|u| !members.contains(u)) {
                    false_acc += 1;
                }
            }
            // Requirement: name a true colluder in the large majority, and
            // essentially never accuse an innocent.
            assert!(
                caught as f64 / trials as f64 >= 0.95,
                "c={c}: caught only {caught}/{trials}"
            );
            assert_eq!(false_acc, 0, "c={c}: {false_acc} false accusations");
        }
    }

    #[test]
    fn single_colluder_is_always_identified() {
        let code = FingerprintCode::generate(500, 40, 8, 7);
        for u in [0usize, 1, 250, 499] {
            let observed = code.majority_collude(&[u], 0);
            let res = code.decode(&observed, 0);
            assert_eq!(res.accused, vec![u]);
            // Margin is (top score) - (best innocent score), not the full score:
            // the colluder matches every column, an innocent matches ~columns/q.
            assert!(
                res.margin > (code.columns as i32) / 2,
                "weak margin {} for single colluder",
                res.margin
            );
        }
    }

    #[test]
    fn two_colluders_decoded_when_they_differ_enough() {
        // Random independent codewords differ in ~7/8 of columns; majority of
        // two ties often, but the decoder still surfaces both at tolerance 0+
        // frequently.  Check the weaker guarantee: a true colluder is accused.
        let code = FingerprintCode::generate(1000, 64, 8, 99);
        let observed = code.majority_collude(&[3, 700], 2);
        let res = code.decode(&observed, 0);
        assert!(res.accused.iter().any(|&u| u == 3 || u == 700));
    }

    #[test]
    fn scoring_is_sane() {
        let code = FingerprintCode::generate(10, 20, 4, 1);
        let w = code.codeword(4).to_vec();
        let res = code.decode(&w, 0);
        assert_eq!(res.accused, vec![4]);
        assert!(res.margin > 0);
    }
}
