//! The pirate relay.
//!
//! Threat model from `docs/DESIGN.md`: an attacker buys ONE legitimate card,
//! decrypts the CWs it receives, and re-broadcasts them over the internet to
//! thousands of pirate boxes that hold no card.  The relay's only weakness is
//! *time*: it can forward a CW only after the legitimate card produced it, and
//! that path is slower than the broadcast's own lookahead.
//!
//! ## The timing argument, stated precisely
//!
//! The headend delivers the CW for period `q` at wall-clock period
//! `q - (L-1)`, where `L` is the lookahead depth.  So a legitimate box holds
//! `CW_q` a full `(L-1)·P` milliseconds before period `q` begins.  A pirate
//! relay receives that CW from the cooperating card at the same instant and
//! needs it at the pirate box before `q` begins; it therefore has `(L-1)·P` ms
//! of budget and spends `relay_base + jitter` of it.
//!
//! * If `relay_base + jitter < (L-1)·P`, the relay wins and the pirate stream
//!   is clean for that period.
//! * Otherwise the CW lands after the boundary and that period is lost.
//!
//! This makes the design tension explicit and honest: **larger lookahead and
//! longer periods protect legitimate zero-glitch operation but also give the
//! pirate relay more time.**  Shortening the period shrinks the relay's timing
//! budget without costing a legitimate box anything, because the box's own
//! slack is still `(L-1)` periods.  The two effects are why the same knob can
//! be safe for subscribers and hostile to piracy at once.

use tstv_cas::params::Params;
use tstv_core::rng::SplitMix64;

#[derive(Clone, Debug, Default)]
pub struct PirateStats {
    pub served: u64,
    pub late: u64,
    pub starved: u64,
    pub colluders: usize,
}

impl PirateStats {
    pub fn service_rate(&self) -> f64 {
        let t = self.served + self.late + self.starved;
        if t == 0 {
            0.0
        } else {
            self.served as f64 / t as f64
        }
    }

    pub fn glitch_rate(&self) -> f64 {
        1.0 - self.service_rate()
    }
}

pub struct PirateRelay {
    pub stats: PirateStats,
    base_ms: i64,
    jitter_ms: i64,
    rng: SplitMix64,
}

impl PirateRelay {
    pub fn new(p: &Params, seed: u64) -> Self {
        Self {
            stats: PirateStats::default(),
            base_ms: p.relay_base_ms,
            jitter_ms: p.relay_jitter_ms,
            rng: SplitMix64::new(seed),
        }
    }

    /// Slack a relay has for one period given the plant's lookahead and period.
    pub fn slack_ms(p: &Params) -> i64 {
        // (L-1) periods of head start.
        (p.lookahead_periods.saturating_sub(1) as i64) * p.period_ms
    }

    /// Offer the relay the CW that the cooperating card produced for `period`.
    /// `cw` is `None` when the card could not open the ECM (e.g. it was just
    /// revoked, or a probe moved it off your key epoch) — the pirate box simply
    /// never gets that period.
    ///
    /// Returns whether the pirate box got the period in time.
    pub fn offer(&mut self, _period: u64, cw: Option<[u8; 16]>, slack_ms: i64) -> bool {
        if cw.is_none() {
            self.stats.starved += 1;
            return false;
        }
        let jitter = if self.jitter_ms > 0 {
            self.rng.below((2 * self.jitter_ms) as u32 + 1) as i64 - self.jitter_ms
        } else {
            0
        };
        let delay = (self.base_ms + jitter).max(0);
        let served = delay < slack_ms;
        if served {
            self.stats.served += 1;
        } else {
            self.stats.late += 1;
        }
        served
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shorter_periods_or_shallower_lookahead_serve_piracy_less() {
        // Relay delay = base(350) + jitter(-220..220) = 130..570 ms.  Slack must
        // straddle that range to show an effect.
        let mut served = Vec::new();
        for (look, period) in [(4usize, 1000i64), (3, 300), (2, 200), (2, 120)] {
            let mut p = Params::default();
            p.lookahead_periods = look;
            p.period_ms = period;
            let slack = PirateRelay::slack_ms(&p);
            let mut relay = PirateRelay::new(&p, 1);
            let mut s = 0;
            for _ in 0..2000 {
                if relay.offer(0, Some([0u8; 16]), slack) {
                    s += 1;
                }
            }
            served.push(s);
        }
        // slack: 3000, 600, 200, 120.
        assert_eq!(served[0], 2000, "3000ms slack always wins: {served:?}");
        assert_eq!(served[1], 2000, "600ms slack clears the 570ms worst case");
        assert!(served[2] < served[1], "200ms must lose some: {served:?}");
        assert!(
            served[3] < served[2],
            "120ms must lose more than 200ms: {served:?}"
        );
    }

    #[test]
    fn no_cw_means_starved_not_served() {
        let mut relay = PirateRelay::new(&Params::default(), 1);
        for _ in 0..100 {
            assert!(!relay.offer(0, None, 3000));
        }
        assert_eq!(relay.stats.served, 0);
        assert_eq!(relay.stats.starved, 100);
    }

    #[test]
    fn generous_slack_serves_everything() {
        let mut relay = PirateRelay::new(&Params::default(), 1);
        for _ in 0..1000 {
            assert!(relay.offer(0, Some([0u8; 16]), 100_000));
        }
        assert_eq!(relay.stats.late, 0);
    }
}
