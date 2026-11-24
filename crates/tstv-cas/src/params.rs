//! Tunables, with validation.
//!
//! Every knob here is something a real plant would set per region and then be
//! stuck with for years, so the defaults encode "old boxes, tight bandwidth,
//! no glitches allowed" rather than what is theoretically nicest.

use tstv_core::Error;

/// All timing in milliseconds, all sizes in bytes unless the name says otherwise.
#[derive(Clone, Debug)]
pub struct Params {
    /// Control-word lifetime.  Shorter = piracy forward lateness hurts more,
    /// but every period costs an ECM slot.  1 s is a common real-world value.
    pub period_ms: i64,
    /// How far ahead ECMs are delivered, in periods.  Must be >= 2 so a single
    /// lost ECM never starves the buffer.
    pub lookahead_periods: usize,
    /// Redundancy: copies of each ECM per period slot.  Covers burst loss.
    pub ecm_repeats: u32,
    /// Number of broadcast bands (delivery groups).  Upper bound comes from
    /// bandwidth; see `bandwidth::BandwidthReport`.
    pub bands: u16,
    /// Epoch length in periods.  Band keys rotate per epoch.
    pub epoch_periods: u64,
    /// Network delivery jitter (ms) added to every packet, uniformly.
    pub jitter_ms: i64,
    /// Independent per-packet loss probability, in parts per million.
    pub loss_ppm: u32,
    /// Extra one-way latency of the attacker's sharing relay, in ms, base.
    pub relay_base_ms: i64,
    /// Peak-to-peak jitter of the relay, ms.
    pub relay_jitter_ms: i64,
    /// Maximum ECM channel budget in bits per second.
    pub ecm_budget_bps: u64,
}

impl Default for Params {
    fn default() -> Self {
        Self {
            period_ms: 1000,
            lookahead_periods: 4,
            ecm_repeats: 2,
            bands: 32,
            epoch_periods: 600,
            jitter_ms: 40,
            loss_ppm: 2_000, // 0.2 %
            relay_base_ms: 350,
            relay_jitter_ms: 220,
            ecm_budget_bps: 96_000,
        }
    }
}

impl Params {
    pub fn validate(&self) -> Result<(), Error> {
        let bad = |name: &'static str, detail: String| Err(Error::BadParam { name, detail });
        if self.period_ms < 100 {
            return bad("period_ms", format!("{} < 100", self.period_ms));
        }
        if self.lookahead_periods < 2 {
            return bad(
                "lookahead_periods",
                format!("{} < 2", self.lookahead_periods),
            );
        }
        if self.ecm_repeats == 0 {
            return bad("ecm_repeats", "must be >= 1".into());
        }
        if self.bands == 0 || !self.bands.is_power_of_two() {
            return bad("bands", format!("{} is not a power of two", self.bands));
        }
        if self.bands > 1024 {
            return bad("bands", format!("{} > 1024", self.bands));
        }
        if self.epoch_periods == 0 {
            return bad("epoch_periods", "must be >= 1".into());
        }
        if self.loss_ppm > 1_000_000 {
            return bad("loss_ppm", format!("{} > 1e6", self.loss_ppm));
        }
        if self.jitter_ms < 0 || self.relay_base_ms < 0 || self.relay_jitter_ms < 0 {
            return bad("timing", "negative jitter/latency".into());
        }
        Ok(())
    }

    pub fn period_of(&self, t_ms: i64) -> u64 {
        t_ms.max(0) as u64 / self.period_ms.max(1) as u64
    }

    pub fn period_start(&self, period: u64) -> i64 {
        (period * self.period_ms as u64) as i64
    }

    pub fn epoch_of(&self, period: u64) -> u32 {
        (period / self.epoch_periods.max(1)) as u32
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_valid() {
        Params::default().validate().unwrap();
    }

    #[test]
    fn rejects_bad_tunables() {
        let mut p = Params::default();
        p.period_ms = 10;
        assert!(p.validate().is_err());
        let mut p = Params::default();
        p.lookahead_periods = 1;
        assert!(p.validate().is_err());
        // 3 is fine now that the power-of-two restriction is gone.
        let mut p = Params::default();
        p.lookahead_periods = 3;
        assert!(p.validate().is_ok());
        let mut p = Params::default();
        p.bands = 48;
        assert!(p.validate().is_err());
        let mut p = Params::default();
        p.loss_ppm = 2_000_000;
        assert!(p.validate().is_err());
    }

    #[test]
    fn period_and_epoch_math() {
        let p = Params::default();
        assert_eq!(p.period_of(0), 0);
        assert_eq!(p.period_of(999), 0);
        assert_eq!(p.period_of(1000), 1);
        assert_eq!(p.period_start(3), 3000);
        assert_eq!(p.epoch_of(599), 0);
        assert_eq!(p.epoch_of(600), 1);
    }
}
