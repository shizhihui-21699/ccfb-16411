//! Result types and human-readable reporting.

use tstv_cas::bandwidth::BandwidthReport;
use tstv_cas::params::Params;

use crate::pirate::PirateStats;

#[derive(Clone, Debug, Default)]
pub struct SimReport {
    /// Legitimate-viewer glitches across every box over the measurement window.
    pub legit_glitches: u64,
    pub total_boxes: usize,
    pub lost_bursts: u64,
    pub pirate_periods: u64,
    pub pirate_served: u64,
    pub pirate_late: u64,
    pub pirate: PirateStats,
    pub bandwidth: BandwidthReport,
    pub params: Params,
}

/// Output of the tracing phase.
#[derive(Clone, Debug, Default)]
pub struct TraceReport {
    pub band_search_complete: bool,
    pub found_band: Option<tstv_core::ids::GroupId>,
    pub band_probe_rounds: u32,
    pub band_probe_bytes: u64,
    pub card_search_complete: bool,
    pub card_probe_rounds: u32,
    pub candidate_cards: usize,
    pub card_probe_bytes: u64,
    pub total_probe_bytes: u64,
    pub found_card: Option<tstv_core::ids::CardId>,
    pub correct: bool,
    pub bandwidth_exhausted: bool,
    /// Legit-viewer glitches caused by scheme-B suppression during the search.
    /// This is the honest cost of tracing to a single card; it is zero for a
    /// pure timing-fingerprint (scheme A) narrowing to a band.
    pub affected_legit_glitches: u64,
}

/// Output of the rectification phase.
#[derive(Clone, Debug, Default)]
pub struct RectifyReport {
    pub revoked: tstv_core::ids::CardId,
    /// Glitches among boxes other than the revoked card's own.
    pub other_legit_glitches: u64,
    /// Whether the revoked card's own box went dark (it must).
    pub revoked_box_went_dark: bool,
    pub pirate_starved_after: bool,
}

impl SimReport {
    pub fn legit_glitch_rate(&self) -> f64 {
        let periods = self.params_measure_periods();
        let denom = (self.total_boxes as u64).saturating_mul(periods).max(1);
        self.legit_glitches as f64 / denom as f64
    }

    fn params_measure_periods(&self) -> u64 {
        // The report does not carry the measurement length directly; derive it
        // from what the simulator accumulated where possible, else 1.
        self.pirate_periods.max(1)
    }

    pub fn pirate_glitch_rate(&self) -> f64 {
        let total = self.pirate_served + self.pirate_late;
        if total == 0 {
            0.0
        } else {
            self.pirate_late as f64 / total as f64
        }
    }
}

/// A compact, aligned summary for the CLI.
pub fn format_report(r: &SimReport) -> String {
    let p = &r.params;
    let mut s = String::new();
    s.push_str("== Plant =============================================\n");
    s.push_str(&format!(
        "period {:.0} ms | lookahead {} | repeats {} | bands {} | epoch {} periods\n",
        p.period_ms as f64, p.lookahead_periods, p.ecm_repeats, p.bands, p.epoch_periods
    ));
    s.push_str(&format!(
        "loss {:.2}% | jitter {} ms | relay {}±{} ms\n",
        p.loss_ppm as f64 / 10_000.0,
        p.jitter_ms,
        p.relay_base_ms,
        p.relay_jitter_ms
    ));
    s.push_str(&format!(
        "ECM channel: {:.1} KiB/s ({:.1} kbit/s), {:.0}% of {:.0} kbit/s budget, {} B/section\n",
        r.bandwidth.ecm_bytes_per_sec / 1024.0,
        r.bandwidth.ecm_bits_per_sec as f64 / 1000.0,
        r.bandwidth.utilisation * 100.0,
        r.bandwidth.budget_bps as f64 / 1000.0,
        r.bandwidth.ecm_section_bytes
    ));
    s.push_str("\n== Legitimate viewers ================================\n");
    s.push_str(&format!(
        "boxes {} | glitches {} | rate {:.3e}\n",
        r.total_boxes,
        r.legit_glitches,
        r.legit_glitch_rate()
    ));
    s.push_str("\n== Pirate service ====================================\n");
    s.push_str(&format!(
        "periods {} | served {} | late {} | glitch rate {:.1}%\n",
        r.pirate_periods,
        r.pirate_served,
        r.pirate_late,
        r.pirate_glitch_rate() * 100.0
    ));
    s
}

/// Human-readable tracing summary.
pub fn format_trace(r: &TraceReport) -> String {
    let mut s = String::new();
    s.push_str("\n== Tracing ===========================================\n");
    match r.found_band {
        Some(b) => s.push_str(&format!(
            "band: {b} (from delivery-timing fingerprint; zero-interference, external input)\n"
        )),
        None => s.push_str("band: not narrowed\n"),
    }
    if r.bandwidth_exhausted {
        s.push_str("  (budget exhausted before convergence)\n");
    }
    s.push_str(&format!(
        "card search (suppression, bounded glitch): {} bytes, {} candidates left, complete={}\n",
        r.card_probe_bytes, r.candidate_cards, r.card_search_complete
    ));
    match r.found_card {
        Some(c) => s.push_str(&format!("identified card {}  correct={}\n", c.0, r.correct)),
        None => s.push_str("identified card: none\n"),
    }
    s.push_str(&format!("total probe bytes: {}\n", r.total_probe_bytes));
    s.push_str(&format!(
        "legit viewer glitches caused by suppression: {}\n",
        r.affected_legit_glitches
    ));
    s
}
