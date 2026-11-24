//! Bandwidth accounting.  This is the constraint that decides how many bands
//! (and therefore how fast tracing converges) the plant can afford.

use tstv_core::wire;

use crate::params::Params;

/// Bytes in one ECM section for `periods` control words.
pub fn ecm_section_len(periods: usize) -> usize {
    wire::ECM_HEADER_LEN + periods * 16 + wire::ECM_TAG_LEN
}

/// Bytes in one EMM section.
pub fn emm_section_len() -> usize {
    wire::EMM_BODY_LEN + wire::EMM_TRAILER_LEN
}

/// What the ECM channel actually costs at a given parameter set.
#[derive(Clone, Debug, PartialEq, Default)]
pub struct BandwidthReport {
    pub ecm_bytes_per_sec: f64,
    pub ecm_bits_per_sec: u64,
    pub budget_bps: u64,
    pub utilisation: f64,
    pub ecm_section_bytes: usize,
    pub emm_section_bytes: usize,
}

impl BandwidthReport {
    pub fn within_budget(&self) -> bool {
        self.ecm_bits_per_sec <= self.budget_bps
    }

    /// Largest band count this budget could support at the same per-band cost.
    /// `self` must have been computed at a known band count.
    pub fn headroom_bands(&self, p: &Params) -> u64 {
        // Cost of one band's ECM channel at `p`'s cadence.
        let per_band = self.ecm_bits_per_sec as f64 / p.bands.max(1) as f64;
        if per_band <= 0.0 {
            return u64::MAX;
        }
        (self.budget_bps as f64 / per_band).floor() as u64
    }
}

/// Compute steady-state ECM channel usage.
///
/// Per period the headend emits `ecm_repeats` copies of a section covering
/// `lookahead_periods` CWs, per band.  Sections only carry *new* periods, so the
/// cost is one section per period per band, times repeats.
pub fn report(p: &Params) -> BandwidthReport {
    let ecm_bytes = ecm_section_len(p.lookahead_periods);
    let periods_per_sec = 1000.0 / p.period_ms as f64;
    let bytes_per_sec = ecm_bytes as f64 * periods_per_sec * p.ecm_repeats as f64 * p.bands as f64;
    let bits = bytes_per_sec * 8.0;
    BandwidthReport {
        ecm_bytes_per_sec: bytes_per_sec,
        ecm_bits_per_sec: bits as u64,
        budget_bps: p.ecm_budget_bps,
        utilisation: bits / p.ecm_budget_bps.max(1) as f64,
        ecm_section_bytes: ecm_bytes,
        emm_section_bytes: emm_section_len(),
    }
}

/// Budget tracker for probe traffic: probes may only spend what the steady
/// state leaves over, and must amortise over an epoch.
#[derive(Clone, Debug)]
pub struct BandwidthBudget {
    pub total_bps: u64,
    pub steady_bps: u64,
    pub spent_bytes_this_epoch: u64,
    pub epoch_ms: i64,
}

impl BandwidthBudget {
    pub fn new(report: &BandwidthReport, epoch_ms: i64) -> Self {
        Self {
            total_bps: report.budget_bps,
            steady_bps: report.ecm_bits_per_sec,
            spent_bytes_this_epoch: 0,
            epoch_ms,
        }
    }

    /// Bits/s available for probe traffic once steady ECM is paid for.
    pub fn spare_bps(&self) -> u64 {
        self.total_bps.saturating_sub(self.steady_bps)
    }

    /// Bytes the probe budget allows across one epoch.
    pub fn epoch_allowance_bytes(&self) -> u64 {
        (self.spare_bps() as u128 * self.epoch_ms.max(0) as u128 / 1000 / 8) as u64
    }

    pub fn remaining_bytes(&self) -> u64 {
        self.epoch_allowance_bytes()
            .saturating_sub(self.spent_bytes_this_epoch)
    }

    /// Try to charge `bytes`; returns false and charges nothing if it would
    /// exceed the epoch allowance.
    pub fn try_charge(&mut self, bytes: u64) -> bool {
        if bytes > self.remaining_bytes() {
            return false;
        }
        self.spent_bytes_this_epoch += bytes;
        true
    }

    pub fn reset_epoch(&mut self) {
        self.spent_bytes_this_epoch = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_params_fit_budget() {
        let p = Params::default();
        let r = report(&p);
        assert!(r.within_budget(), "{r:?}");
        assert_eq!(
            r.ecm_section_bytes,
            wire::ECM_HEADER_LEN + 4 * 16 + wire::ECM_TAG_LEN
        );
        // Cross-check the arithmetic against an independent recomputation.
        let expect = (r.ecm_section_bytes as f64)
            * (1000.0 / p.period_ms as f64)
            * p.ecm_repeats as f64
            * p.bands as f64
            * 8.0;
        assert!((r.ecm_bits_per_sec as f64 - expect).abs() < 2.0);
    }

    #[test]
    fn more_bands_or_shorter_periods_cost_more() {
        let mut p = Params::default();
        let base = report(&p).ecm_bits_per_sec;
        p.bands *= 2;
        assert!(report(&p).ecm_bits_per_sec > base);
        let mut p = Params::default();
        p.period_ms /= 2;
        assert!(report(&p).ecm_bits_per_sec > base);
    }

    #[test]
    fn bands_are_capped_by_the_ecm_budget() {
        // The number of bands (and so tracing speed) is not a free choice: too
        // many bands blows the ECM channel.  Find the largest power-of-two band
        // count that fits the default budget at the default cadence.
        let mut p = Params::default();
        let mut fit = 0u16;
        for b in [8u16, 16, 32, 64, 128, 256, 512, 1024] {
            p.bands = b;
            if report(&p).within_budget() {
                fit = b;
            } else {
                break;
            }
        }
        // At the default cadence (1 s periods, 2 repeats, 4-period lookahead)
        // 64 bands uses ~93 kbit/s of a 96 kbit/s budget — the ceiling is tight,
        // which is exactly the point: band count is bought with ECM bandwidth.
        assert_eq!(fit, 64, "default plant should top out at 64 bands");
        p.bands = 1024;
        let r = report(&p);
        assert!(!r.within_budget());
        assert!(r.utilisation > 1.0);
        // At default cadence the budget supports ~64 bands; the 1024-band plan
        // costs 16x too much.
        let default = Params::default();
        let default_report = report(&default);
        let headroom = default_report.headroom_bands(&default);
        assert!(
            (64..=65).contains(&headroom),
            "headroom {headroom} should be ~64 bands"
        );
    }

    #[test]
    fn budget_charges_and_refuses_overspend() {
        let p = Params::default();
        let r = report(&p);
        let mut b = BandwidthBudget::new(&r, 60_000);
        let allow = b.epoch_allowance_bytes();
        assert!(allow > 0);
        assert!(b.try_charge(allow));
        assert_eq!(b.remaining_bytes(), 0);
        assert!(!b.try_charge(1));
        b.reset_epoch();
        assert!(b.try_charge(1));
    }
}
