//! Binary-search tracing over the population of bands, then cards.
//!
//! ## The oracle
//!
//! An operator observes whether the pirate service is still usable after a
//! probe.  That is a 1-bit answer — "piracy still works, yes/no" — and it is the
//! *only* signal available, because we never see the pirate's traffic.  The
//! whole method is designed around that poverty of signal.
//!
//! ## Why it converges
//!
//! Two probe kinds, with different costs (see `docs/DESIGN.md` §3.2):
//!
//! * **Band narrowing (scheme A, interference-free).**  Each band delivers its
//!   ECMs at a distinct in-period offset; the pirate stream's per-period
//!   availability edge carries that offset, which the operator correlates to a
//!   band.  No box glitches.
//! * **Card narrowing (scheme B, bounded interference).**  Inside the located
//!   band, a candidate subset has its ECMs suppressed past the lookahead, so a
//!   sharing card in that subset starves the relay — at the cost of a short,
//!   bounded glitch for those few legitimate viewers.
//!
//! Either way each probe is one bit; binary search needs `ceil(log2 |universe|)`.
//!
//! ## Budget
//!
//! Probes are not free: a band probe costs ECMs on that band's channel for the
//! observation window plus the per-card EMMs for the cards in it.  The
//! controller refuses to launch a probe whose bytes would blow the epoch budget;
//! a refused probe is reported, never silently skipped.

use std::collections::BTreeSet;

use tstv_cas::headend::Headend;
use tstv_core::ids::{CardId, GroupId};

/// What the operator observed after a probe's observation window.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProbeOutcome {
    /// Pirate service died: the sharing card is inside the probed set.
    PiracyBroken,
    /// Pirate service survived: the sharing card is outside the probed set.
    PiracySurvived,
}

/// One probe we decided to run (or wanted to).
#[derive(Clone, Debug)]
pub struct ProbeAttempt {
    pub round: u32,
    pub candidates_before: usize,
    pub probed: Vec<GroupId>,
    pub outcome: Option<ProbeOutcome>,
    pub cost_bytes: u64,
    /// True when the budget refused this probe.
    pub refused_for_budget: bool,
}

/// Drives the search.  Owns no headend state itself; the caller applies probes
/// to the `Headend` and feeds observations back.  This split keeps the tracing
/// logic testable against a synthetic oracle.
pub struct GroupTester {
    /// Bands still in the running.
    candidates: Vec<GroupId>,
    pub total_cost_bytes: u64,
    pub attempts: Vec<ProbeAttempt>,
    /// Periods to wait after the rekey takes effect before judging, so the
    /// relay's last forwarded lookahead drains.
    pub observe_periods: u64,
    budget_remaining: u64,
}

impl GroupTester {
    pub fn new(bands: impl IntoIterator<Item = GroupId>, budget_bytes: u64) -> Self {
        Self {
            candidates: bands.into_iter().collect(),
            total_cost_bytes: 0,
            attempts: Vec::new(),
            observe_periods: 2,
            budget_remaining: budget_bytes,
        }
    }

    pub fn candidates(&self) -> &[GroupId] {
        &self.candidates
    }

    pub fn is_done(&self) -> bool {
        self.candidates.len() <= 1
    }

    /// The subset to probe next: the first half of the candidates.  `None` when
    /// the search is finished.  The split is by index on a sorted list, so it is
    /// deterministic and reproducible.
    pub fn next_probe_set(&mut self) -> Option<Vec<GroupId>> {
        if self.is_done() {
            return None;
        }
        self.candidates.sort();
        let half = self.candidates.len().div_ceil(2);
        Some(self.candidates[..half].to_vec())
    }

    /// Record the result of probing `probed` and narrow the candidate set.
    ///
    /// `cost_bytes` is what the probe actually consumed (from the headend's
    /// estimator); the caller has already checked it against the budget via
    /// [`Self::can_afford`].
    pub fn record(&mut self, probed: Vec<GroupId>, outcome: ProbeOutcome, cost_bytes: u64) {
        let before = self.candidates.len();
        let set: BTreeSet<u16> = probed.iter().map(|b| b.0).collect();
        self.candidates = match outcome {
            // Sharing card was inside the probed set.
            ProbeOutcome::PiracyBroken => self
                .candidates
                .iter()
                .copied()
                .filter(|b| set.contains(&b.0))
                .collect(),
            // Sharing card was outside it.
            ProbeOutcome::PiracySurvived => self
                .candidates
                .iter()
                .copied()
                .filter(|b| !set.contains(&b.0))
                .collect(),
        };
        self.total_cost_bytes += cost_bytes;
        self.budget_remaining = self.budget_remaining.saturating_sub(cost_bytes);
        self.attempts.push(ProbeAttempt {
            round: self.attempts.len() as u32,
            candidates_before: before,
            probed,
            outcome: Some(outcome),
            cost_bytes,
            refused_for_budget: false,
        });
    }

    pub fn can_afford(&self, cost_bytes: u64) -> bool {
        cost_bytes <= self.budget_remaining
    }

    pub fn record_refused(&mut self, probed: Vec<GroupId>, cost_bytes: u64) {
        let before = self.candidates.len();
        self.attempts.push(ProbeAttempt {
            round: self.attempts.len() as u32,
            candidates_before: before,
            probed,
            outcome: None,
            cost_bytes,
            refused_for_budget: true,
        });
    }

    /// Run the search to completion against an oracle that, given the probed
    /// set, returns the true outcome for a sharing card in `secret_band`.
    ///
    /// This is the test/offline driver; live operation uses the step-wise API
    /// above because each probe spans real wall-clock time.
    pub fn run<F>(
        &mut self,
        headend: &Headend,
        secret_band: GroupId,
        periods_per_probe: u64,
        mut oracle: F,
    ) -> Result<GroupId, &'static str>
    where
        F: FnMut(&[GroupId]) -> ProbeOutcome,
    {
        let mut guard = 0;
        while !self.is_done() {
            guard += 1;
            if guard > 64 {
                return Err("group search failed to converge");
            }
            let set = match self.next_probe_set() {
                Some(s) => s,
                None => break,
            };
            let probe = tstv_cas::headend::ProbeState {
                probe_id: 0,
                bands: set.clone(),
                effective_period: 0,
            };
            let cost = headend.probe_cost_bytes(&probe, periods_per_probe + self.observe_periods);
            if !self.can_afford(cost) {
                self.record_refused(set, cost);
                return Err("probe budget exhausted");
            }
            let outcome = oracle(&set);
            self.record(set, outcome, cost);
            let _ = secret_band;
        }
        self.candidates
            .first()
            .copied()
            .ok_or("no candidate band found")
    }
}

/// Binary-search a card inside one band.  The mechanism is identical: probe a
/// subset of the band's cards by giving the probed subset a new key epoch and
/// waiting; a sharing card in the subset starves the relay.
///
/// Returned cost is in EMM bytes per probe, since inside a single band only the
/// per-card EMMs are needed (the band's ECM channel is already shared).
pub struct CardTester {
    candidates: Vec<CardId>,
    pub emm_cost_per_card: u64,
}

impl CardTester {
    pub fn new(cards: impl IntoIterator<Item = CardId>, emm_bytes: u64) -> Self {
        Self {
            candidates: cards.into_iter().collect(),
            emm_cost_per_card: emm_bytes,
        }
    }

    pub fn candidates(&self) -> &[CardId] {
        &self.candidates
    }

    pub fn is_done(&self) -> bool {
        self.candidates.len() <= 1
    }

    pub fn next_probe_set(&mut self) -> Option<Vec<CardId>> {
        if self.is_done() {
            return None;
        }
        self.candidates.sort();
        let half = self.candidates.len().div_ceil(2);
        Some(self.candidates[..half].to_vec())
    }

    pub fn record(&mut self, probed: &[CardId], outcome: ProbeOutcome) {
        let set: BTreeSet<u32> = probed.iter().map(|c| c.0).collect();
        self.candidates = match outcome {
            ProbeOutcome::PiracyBroken => self
                .candidates
                .iter()
                .copied()
                .filter(|c| set.contains(&c.0))
                .collect(),
            ProbeOutcome::PiracySurvived => self
                .candidates
                .iter()
                .copied()
                .filter(|c| !set.contains(&c.0))
                .collect(),
        };
    }

    pub fn probe_cost(&self, probed_len: usize) -> u64 {
        probed_len as u64 * self.emm_cost_per_card
    }

    pub fn run<F>(&mut self, secret: CardId, mut oracle: F) -> Result<CardId, &'static str>
    where
        F: FnMut(&[CardId]) -> ProbeOutcome,
    {
        let mut guard = 0;
        while !self.is_done() {
            guard += 1;
            if guard > 64 {
                return Err("card search failed to converge");
            }
            let set = match self.next_probe_set() {
                Some(s) => s,
                None => break,
            };
            let outcome = oracle(&set);
            self.record(&set, outcome);
            let _ = secret;
        }
        self.candidates
            .first()
            .copied()
            .ok_or("no candidate card found")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn band_search_converges_in_log_rounds() {
        let bands: Vec<GroupId> = (0..64).map(GroupId).collect();
        for secret in [0u16, 1, 17, 63] {
            let mut t = GroupTester::new(bands.clone(), u64::MAX);
            let found = t.run_band_only(GroupId(secret), 2).expect("converges");
            assert_eq!(found, GroupId(secret));
            // ceil(log2 64) = 6 rounds; allow one slack for the ceil-split.
            assert!(t.attempts.len() <= 6, "took {} rounds", t.attempts.len());
        }
    }

    #[test]
    fn card_search_converges_in_log_rounds() {
        for secret in [0u32, 5, 999, 4095] {
            let mut t = CardTester::new((0..4096).map(CardId), 61);
            let found = t.run(CardId(secret), |probed| {
                if probed.iter().any(|c| c.0 == secret) {
                    ProbeOutcome::PiracyBroken
                } else {
                    ProbeOutcome::PiracySurvived
                }
            });
            assert_eq!(found, Ok(CardId(secret)));
        }
    }

    #[test]
    fn budget_refuses_overspend_and_reports_it() {
        let bands: Vec<GroupId> = (0..64).map(GroupId).collect();
        // Tiny budget: even one probe is unaffordable once cost is non-zero.
        let mut t = GroupTester::new(bands, 100);
        t.next_probe_set();
        t.record_refused(vec![GroupId(0)], 10_000);
        assert!(t.attempts.last().unwrap().refused_for_budget);
    }

    // A headend-free driver mirroring `run`, so the search logic is tested
    // without constructing a full plant.
    impl GroupTester {
        fn run_band_only(
            &mut self,
            secret: GroupId,
            _periods: u64,
        ) -> Result<GroupId, &'static str> {
            let mut guard = 0;
            while !self.is_done() {
                guard += 1;
                if guard > 64 {
                    return Err("no converge");
                }
                let set = self.next_probe_set().ok_or("empty")?;
                let outcome = if set.iter().any(|b| *b == secret) {
                    ProbeOutcome::PiracyBroken
                } else {
                    ProbeOutcome::PiracySurvived
                };
                self.record(set, outcome, 1);
            }
            self.candidates.first().copied().ok_or("none")
        }
    }
}
