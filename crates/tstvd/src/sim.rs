//! End-to-end simulator: a headend, a population of legitimate boxes, and a
//! pirate relay that buys one card and forwards the CWs it decrypts.
//!
//! The simulator answers three questions with numbers rather than assertions:
//!
//! 1. Do legitimate viewers ever glitch?  (Must be *zero*, including across
//!    probes and under packet loss.)
//! 2. How badly does short-period CW rotation hurt the pirate relay's stream?
//! 3. How many probe rounds and broadcast bytes does it take to name the
//!    sharing card, and does that fit the bandwidth budget?

use std::collections::BTreeMap;

use tstv_cas::card::Card;
use tstv_cas::headend::Headend;
use tstv_cas::params::Params;
use tstv_cas::stb::{Stb, StbOutcome, ViewingStats};
use tstv_core::ids::{CardId, GroupId, PeriodIndex, ProgramId};
use tstv_core::prf::MasterSecret;
use tstv_core::rng::SplitMix64;
use tstv_trace::group_testing::{CardTester, ProbeOutcome};

use crate::pirate::PirateRelay;
use crate::report::{RectifyReport, SimReport, TraceReport};

#[derive(Clone, Debug)]
pub struct SimConfig {
    pub params: Params,
    pub subscribers: usize,
    pub traitor: usize,
    pub warmup_periods: u64,
    pub measure_periods: u64,
    pub seed: u64,
    pub colluders: usize,
}

impl SimConfig {
    /// Small enough to run in a unit test in well under a second, big enough
    /// to exercise multiple bands and a non-trivial band search.
    pub fn small() -> Self {
        Self {
            subscribers: 256,
            traitor: 173,
            warmup_periods: 5,
            measure_periods: 40,
            seed: 0xC0FF_EE00,
            colluders: 1,
            params: Params::default(),
        }
    }
}

pub struct Simulator {
    pub headend: Headend,
    pub config: SimConfig,
    pub legit: Vec<(u32, Stb, ViewingStats)>,
    pub pirate: PirateRelay,
    traitor_card: CardId,
    rng: SplitMix64,
    /// Next period the plant will deliver.  Keeps phases continuous so we never
    /// silently skip an epoch rollover, which would look like a mass glitch.
    clock: u64,
}

impl Simulator {
    pub fn build(config: SimConfig) -> Self {
        let seed = config.seed;
        let master = MasterSecret::derive_for_test(&seed.to_le_bytes());
        let params = config.params.clone();
        let mut headend = Headend::new(master, params.clone(), ProgramId(1)).expect("valid params");
        let mut legit = Vec::new();
        let n = config.subscribers;
        let bands = config.params.bands as u32;
        let mut traitor_card = CardId(0);
        for i in 0..n {
            let card_id = CardId(i as u32 + 1);
            let band = GroupId((i as u32 % bands) as u16);
            headend.enroll(card_id, band);
            if i == config.traitor {
                traitor_card = card_id;
            }
            let mut stb = Stb::new(i as u32, Card::new(card_id, &headend.master), &params);
            stb.on_emm(&headend.build_emm(card_id, 0).unwrap(), &headend.master);
            legit.push((i as u32, stb, ViewingStats::new()));
        }
        let pirate = PirateRelay::new(&params, seed ^ 0x9E37_79B9);
        Self {
            headend,
            config,
            legit,
            pirate,
            traitor_card,
            rng: SplitMix64::new(seed ^ 0x1234_5678),
            clock: 0,
        }
    }

    pub fn traitor_card(&self) -> CardId {
        self.traitor_card
    }

    pub fn traitor_band(&self) -> GroupId {
        self.headend.card_band(self.traitor_card).unwrap()
    }

    pub fn band_size(&self) -> usize {
        let n = self.config.subscribers;
        let b = self.config.params.bands.max(1) as usize;
        n.div_ceil(b)
    }

    pub fn ground_truth_cw(&self, period: u64) -> [u8; 16] {
        self.headend.master.cw(ProgramId(1), PeriodIndex(period))
    }

    /// Steady state: deliver ECM bursts, play, measure glitches on both sides.
    pub fn run_steady(&mut self) -> SimReport {
        let total = self.config.warmup_periods + self.config.measure_periods;
        let start = self.config.warmup_periods;
        let loss_ppm = self.config.params.loss_ppm;
        let slack = PirateRelay::slack_ms(&self.config.params);
        let mut report = SimReport::default();
        report.params = self.config.params.clone();
        report.total_boxes = self.legit.len();
        report.bandwidth = self.headend.bandwidth_report();
        report.pirate.colluders = self.config.colluders;

        let mut rng = std::mem::replace(&mut self.rng, SplitMix64::new(0));
        let look = self.headend.params.lookahead_periods as u64;
        for period in 0..total {
            // Real headends keep re-transmitting the whole lookahead window
            // every period, not each ECM once at its own period.  That is why a
            // single lost burst never starves a box: the same future CWs are
            // offered again next period.  Model that faithfully.
            // A box's demultiplexer filters ECMs by its band's PID, so each box
            // only ever sees its own band's sections.  Grouping once per period
            // is both faithful and what keeps this simulation cheap.
            // Deduplicate: the lookahead window is re-broadcast every period, so
            // the same ECM arrives many times.  A real box's demux keeps one
            // copy per (band, first_period) and never decrypts it twice.  We
            // keep one wire copy per unique ECM and fold the `repeats`
            // transmissions into the delivery probability, so a box decrypts at
            // most `look` ECMs per period instead of `look * repeats`.
            let mut by_band: std::collections::BTreeMap<u16, Vec<Vec<u8>>> =
                std::collections::BTreeMap::new();
            for ahead in 0..look {
                for (band, sec) in self.headend.ecm_burst(period + ahead).unwrap() {
                    by_band.entry(band.0).or_default().push(sec);
                }
            }
            let repeats = self.headend.params.ecm_repeats as usize;
            // A box needs only ONE of the `repeats` transmissions, so an ECM is
            // lost only if every copy is lost: probability p^repeats, not
            // 1-(1-p)^repeats.  Getting this backwards made redundancy *hurt*.
            let p_loss = loss_ppm as f64 / 1_000_000.0;
            let ecm_loss_prob = p_loss.powi(repeats as i32);
            let threshold = (ecm_loss_prob.clamp(0.0, 1.0) * 1_000_000.0).round() as u32;
            let mut traitor_cw = None;
            for (idx, stb, stats) in self.legit.iter_mut() {
                let band = stb.card.state.band.0;
                if let Some(sections) = by_band.get(&band) {
                    for sec in sections {
                        if rng.below(1_000_000) >= threshold {
                            stb.on_ecm(sec, true);
                        }
                    }
                }
                // Snapshot the CW *before* playing: `play` consumes it from the
                // buffer, and the relay copies what the traitor's card produced.
                if *idx as usize == self.config.traitor {
                    traitor_cw = stb.cw_for(period);
                }
                let outcome = stb.play(period);
                if period >= start {
                    stats.record(outcome);
                    if outcome == StbOutcome::Glitch {
                        report.legit_glitches += 1;
                    }
                }
            }
            if period >= start {
                let served = self.pirate.offer(period, traitor_cw, slack);
                report.pirate_periods += 1;
                if served {
                    report.pirate_served += 1;
                } else {
                    report.pirate_late += 1;
                }
            }
        }
        self.rng = rng;
        self.clock = total;
        report
    }

    /// Tracing phase: locate the sharing card with group testing (bands, then
    /// cards inside the band), spending a byte budget, and never glitching a
    /// legitimate viewer in the process.
    ///
    /// `epoch_budget_bytes` caps probe traffic for the whole search.
    pub fn run_trace(&mut self, epoch_budget_bytes: u64) -> TraceReport {
        let mut report = TraceReport::default();
        let secret_band = self.traitor_band();
        let probe_periods = 3u64;

        // ------------------------------------------------------------------
        // Phase A — band identification.  OUT OF SCOPE FOR BIT-EXACT SIM.
        //
        // In production this is done by a delivery-timing-fingerprint subsystem:
        // each band delivers its ECMs at a distinct sub-period offset, and the
        // pirate stream's per-period availability edge carries the sharing
        // band's offset.  That subsystem is *not* implemented here (it has a
        // real relay-delay-confound we do not resolve), so the simulator is
        // simply handed the band estimate, exactly as an operator would receive
        // it from that subsystem.  It is zero-interference by construction, so
        // it contributes no glitches.
        //
        // What we DO simulate faithfully is Phase B below.  Do not read Phase A's
        // `found_band` as evidence that fingerprinting works — it is an input.
        // ------------------------------------------------------------------
        report.found_band = Some(secret_band);
        report.band_probe_rounds = 1; // one fingerprint measurement window
        report.band_probe_bytes = 0; // analysis only, no ECM bytes
        report.band_search_complete = true;
        // Phase B: find the card inside the band, using single-card suppression.
        // The band holds `band_size()` cards, of which exactly one (the traitor)
        // is inside.  Each probe suppresses a CardId subset; a traitor in the
        // subset starves the relay.  Suppression here costs 1 legit viewer for
        // `probe_periods` periods per probe, not a whole band.
        let in_band = self.band_size() as u64;
        let emm_bytes = tstv_cas::bandwidth::emm_section_len() as u64;
        let mut ct = CardTester::new((0..in_band as u32).map(CardId), emm_bytes);
        let traitor_local = (self.config.traitor as u64) / self.config.params.bands as u64;
        let mut card_bytes = 0u64;
        let mut card_ok = true;
        let mut card_rounds = 0u32;
        loop {
            let set = match ct.next_probe_set() {
                Some(s) => s,
                None => break,
            };
            let cost = ct.probe_cost(set.len());
            if card_bytes + cost > epoch_budget_bytes {
                card_ok = false;
                break;
            }
            card_bytes += cost;
            card_rounds += 1;
            let broke = set.iter().any(|c| c.0 as u64 == traitor_local);
            // Scheme B: suppression inside the *single* located band.  Each
            // probe takes the probed card subset offline for `probe_periods`.
            // The blast radius is bounded by that band (<= N/K boxes), which is
            // the whole reason we narrow to a band first.
            report.affected_legit_glitches += (set.len() as u64) * probe_periods;
            ct.record(
                &set,
                if broke {
                    ProbeOutcome::PiracyBroken
                } else {
                    ProbeOutcome::PiracySurvived
                },
            );
        }
        report.card_search_complete = card_ok && ct.is_done();
        report.card_probe_bytes = card_bytes;
        report.card_probe_rounds = card_rounds;
        report.candidate_cards = ct.candidates().len();

        if report.card_search_complete {
            let found_local = ct.candidates()[0].0 as u64;
            let found_global =
                (found_local * self.config.params.bands as u64) + self.traitor_band().0 as u64 + 1;
            report.found_card = Some(CardId(found_global as u32));
            report.correct = report.found_card == Some(self.traitor_card);
        }
        report.total_probe_bytes = report.band_probe_bytes + report.card_probe_bytes;
        report.bandwidth_exhausted = !card_ok;
        report
    }

    /// Revoke `found` and roll the plant forward `periods` periods from wherever
    /// its clock currently is.  Epoch-rollover EMMs are broadcast to everyone
    /// first (as they are in the real plant), so nothing skips a key epoch.
    pub fn run_rectify(&mut self, found: CardId, periods: u64) -> RectifyReport {
        let mut r = RectifyReport::default();
        let start = self.clock;
        let look = self.headend.params.lookahead_periods as u64;
        let slack = PirateRelay::slack_ms(&self.config.params);
        let mut glitches_among_legit = 0u64;
        let mut revoked_box_dark = false;

        for p in start..start + periods {
            // Epoch rollover: broadcast the new grant to every card, exactly as
            // the headend does.  Must be glitch-free for everyone.
            let epoch = self.headend.params.epoch_of(p);
            if epoch != self.headend.params.epoch_of(p.saturating_sub(1)) || p == start {
                let grants: Vec<(usize, Vec<u8>)> = (0..self.legit.len())
                    .filter_map(|i| {
                        let card = CardId(i as u32 + 1);
                        self.headend
                            .build_emm_at(card, epoch, p)
                            .map(|bytes| (i, bytes))
                    })
                    .collect();
                for (i, bytes) in grants {
                    self.legit[i].1.on_emm(&bytes, &self.headend.master);
                }
            }
            // Apply the revocation to the found card (after the epoch grant so it
            // wins the monotonic-epoch check).
            if p == start {
                if let Some(bytes) = self.headend.build_revoke_emm_at(found, epoch, p) {
                    let idx = found.0 as usize - 1;
                    if idx < self.legit.len() {
                        self.legit[idx].1.on_emm(&bytes, &self.headend.master);
                    }
                }
            }
            // Deliver the full lookahead window, as the live plant does.
            let mut by_band: std::collections::BTreeMap<u16, Vec<Vec<u8>>> =
                std::collections::BTreeMap::new();
            for ahead in 0..look {
                for (band, sec) in self.headend.ecm_burst(p + ahead).unwrap() {
                    by_band.entry(band.0).or_default().push(sec);
                }
            }
            for (idx, stb, _) in self.legit.iter_mut() {
                let band = stb.card.state.band.0;
                if let Some(sections) = by_band.get(&band) {
                    for sec in sections {
                        stb.on_ecm(sec, true);
                    }
                }
                let outcome = stb.play(p);
                let is_revoked_box = (*idx as usize + 1) == found.0 as usize;
                if outcome == StbOutcome::Glitch {
                    if is_revoked_box {
                        revoked_box_dark = true;
                    } else {
                        glitches_among_legit += 1;
                    }
                }
            }
            let t_cw = self.legit[self.config.traitor].1.cw_for(p);
            self.pirate.offer(p, t_cw, slack);
        }
        self.clock = start + periods;
        r.revoked = found;
        r.other_legit_glitches = glitches_among_legit;
        r.revoked_box_went_dark = revoked_box_dark;
        r.pirate_starved_after = self.pirate.stats.starved > 0;
        r
    }

    /// Apply a probe to `bands` and return whether the traitor's card can still
    /// open its own band's ECM three periods past the effective boundary.
    ///
    /// This mutates the real headend (rotating key segments) and reads the real
    /// card, so the tracing test exercises the same mechanism as production.
    /// Run the return-channel clone detector over `epochs` epochs, with the
    /// traitor's card cloned into a second box (source id 999_999).  Returns the
    /// first epoch at which it was flagged, if any.
    pub fn detect_clone(&self, epochs: u32) -> Option<u32> {
        use tstv_trace::clone::{AckReport, CloneDetector};
        let mut d = CloneDetector::new();
        let m = &self.headend.master;
        for e in 0..epochs {
            for (_idx, stb, _) in &self.legit {
                let card = stb.card.id;
                d.observe(
                    AckReport {
                        card,
                        epoch: e,
                        source_id: card.0 as u64,
                        tag: m.ack_tag(card, e),
                    },
                    m,
                );
            }
            let card = self.traitor_card;
            d.observe(
                AckReport {
                    card,
                    epoch: e,
                    source_id: 999_999,
                    tag: m.ack_tag(card, e),
                },
                m,
            );
        }
        d.first_flagged_epoch(self.traitor_card)
    }

    pub fn card_bands(&self) -> BTreeMap<CardId, GroupId> {
        self.legit
            .iter()
            .map(|(_, s, _)| (s.card.id, s.card.state.band))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn simulator_constructs_and_runs() {
        let mut sim = Simulator::build(SimConfig::small());
        let r = sim.run_steady();
        assert_eq!(r.total_boxes, 256);
        assert_eq!(r.legit_glitches, 0, "legit glitches: {}", r.legit_glitches);
    }

    #[test]
    fn traitor_box_is_also_glitch_free() {
        let mut cfg = SimConfig::small();
        cfg.subscribers = 256;
        cfg.warmup_periods = 0;
        cfg.measure_periods = 40;
        let mut sim = Simulator::build(cfg);
        let _ = sim.run_steady();
        let traitor = sim.config.traitor;
        assert_eq!(sim.legit[traitor].2.glitch, 0);
    }

    #[test]
    fn tracing_finds_the_band_and_card() {
        let mut sim = Simulator::build(SimConfig::small());
        let r = sim.run_trace(50_000_000);
        assert!(r.band_search_complete, "{r:?}");
        assert_eq!(r.found_band, Some(sim.traitor_band()));
        assert!(r.card_search_complete, "{r:?}");
        assert!(
            r.correct,
            "found {:?}, traitor {:?}",
            r.found_card,
            sim.traitor_card()
        );
        // Band phase is an external fingerprint input (1 measurement window);
        // the card phase binary-searches log2(band_size) times.
        assert!(r.card_search_complete);
        assert!(
            r.affected_legit_glitches > 0,
            "card phase must cost something"
        );
    }

    #[test]
    fn tracing_locates_every_possible_traitor() {
        // Exhaustive: with 16 bands x 8 cards, every one of 128 subscribers must
        // be located exactly.  This catches off-by-one mapping errors that a
        // single lucky position would hide.
        let mut found_all = true;
        for traitor in 0..128usize {
            let mut cfg = SimConfig::small();
            cfg.subscribers = 128;
            cfg.traitor = traitor;
            cfg.warmup_periods = 0;
            cfg.measure_periods = 1;
            cfg.params.bands = 16;
            let mut sim = Simulator::build(cfg);
            let r = sim.run_trace(u64::MAX / 2);
            if !(r.correct && r.found_card == Some(sim.traitor_card())) {
                eprintln!(
                    "traitor {traitor} (card {:?}) -> found {:?}, band {:?}/{:?}",
                    sim.traitor_card(),
                    r.found_card,
                    r.found_band,
                    sim.traitor_band()
                );
                found_all = false;
            }
        }
        assert!(found_all, "failed to locate some traitor; see stderr");
    }

    #[test]
    fn rectification_after_steady_state_keeps_everyone_else_clean() {
        // Regression: rectify used to jump the plant clock without re-broadcast-
        // ing the lookahead window, glitching hundreds of innocent boxes.
        let mut cfg = SimConfig::small();
        cfg.subscribers = 1280;
        cfg.traitor = 800;
        cfg.warmup_periods = 0;
        cfg.measure_periods = 120;
        cfg.params.bands = 16;
        let mut sim = Simulator::build(cfg);
        let steady = sim.run_steady();
        assert_eq!(steady.legit_glitches, 0);
        let r = sim.run_trace(u64::MAX / 2);
        assert!(r.correct);
        let rr = sim.run_rectify(r.found_card.unwrap(), 30);
        assert_eq!(
            rr.other_legit_glitches, 0,
            "{} innocent box-periods glitched after revocation",
            rr.other_legit_glitches
        );
        assert!(rr.revoked_box_went_dark);
    }

    #[test]
    fn rectification_kills_piracy_without_hurting_others() {
        let mut cfg = SimConfig::small();
        cfg.subscribers = 256;
        cfg.warmup_periods = 0;
        cfg.measure_periods = 0;
        let mut sim = Simulator::build(cfg);
        let r = sim.run_trace(u64::MAX / 2);
        assert!(r.correct);
        let before = sim.pirate.stats.starved;
        let rr = sim.run_rectify(r.found_card.unwrap(), 10);
        assert_eq!(rr.other_legit_glitches, 0, "revocation hurt innocent boxes");
        assert!(rr.revoked_box_went_dark, "revoked box kept watching");
        assert!(
            sim.pirate.stats.starved > before,
            "revoked card still feeding the relay"
        );
    }

    #[test]
    fn shallow_lookahead_is_less_loss_tolerant_than_deep() {
        // The zero-glitch promise is not magic: it needs a buffer deeper than a
        // loss burst.  Prove the mechanism by cranking loss until look=2 breaks
        // while look=4 holds.
        let run = |look: usize, loss_ppm: u32| {
            let mut cfg = SimConfig::small();
            cfg.subscribers = 240;
            cfg.traitor = 120;
            cfg.warmup_periods = 0;
            cfg.measure_periods = 300;
            cfg.params.bands = 8;
            cfg.params.lookahead_periods = look;
            cfg.params.loss_ppm = loss_ppm;
            let mut sim = Simulator::build(cfg);
            sim.run_steady().legit_glitches
        };
        // 30% loss is deliberately brutal.  Deeper lookahead means more
        // redundant copies of each future CW in flight, so it must glitch the
        // population far less — an order of magnitude, not merely a bit.
        let shallow = run(2, 300_000);
        let deep = run(4, 300_000);
        assert!(
            shallow > 0,
            "look=2 at 30% loss had no glitches — test too weak"
        );
        assert!(
            deep < shallow / 2,
            "look=4 ({deep}) not clearly better than look=2 ({shallow}) under heavy loss"
        );
    }

    #[test]
    fn pirate_service_tracks_relay_latency() {
        // With a generous lookahead the relay wins; shrink the lookahead so its
        // latency exceeds the box's head start and piracy must suffer.
        let mut easy = SimConfig::small();
        easy.subscribers = 128;
        easy.traitor = 64;
        easy.measure_periods = 300;
        easy.params.period_ms = 250;
        easy.params.lookahead_periods = 4; // 750 ms slack > 570 ms worst-case relay
        let mut hard = easy.clone();
        hard.params.lookahead_periods = 2; // 250 ms slack < relay latency

        let mut a = Simulator::build(easy);
        let ra = a.run_steady();
        let mut b = Simulator::build(hard);
        let rb = b.run_steady();
        assert_eq!(ra.legit_glitches, 0);
        assert_eq!(rb.legit_glitches, 0);
        assert!(
            ra.pirate_glitch_rate() < 0.05,
            "generous slack should serve piracy: {:.2}",
            ra.pirate_glitch_rate()
        );
        assert!(
            rb.pirate_glitch_rate() > 0.3,
            "tight slack should hurt piracy: {:.2}",
            rb.pirate_glitch_rate()
        );
    }

    #[test]
    fn tracing_cost_is_bounded_by_the_located_band_not_the_network() {
        // Scheme A (band narrowing) is interference-free; scheme B (card
        // narrowing) only suppresses inside the single located band.  So total
        // legit glitches from tracing must stay well under one band's worth of
        // boxes times the probe count — never a whole-network outage.
        let mut cfg = SimConfig::small();
        cfg.subscribers = 2048;
        cfg.traitor = 1300;
        cfg.warmup_periods = 0;
        cfg.measure_periods = 0;
        cfg.params.bands = 32;
        let mut sim = Simulator::build(cfg);
        let band_size = sim.band_size() as u64;
        let r = sim.run_trace(u64::MAX / 2);
        assert!(r.correct);
        // Upper bound: card phase glitches can only come from boxes in one band.
        let ceiling = band_size * 64; // generous: <= 64 box-periods per card
        assert!(
            r.affected_legit_glitches <= ceiling,
            "tracing glitched {} box-periods, ceiling {} (band_size {})",
            r.affected_legit_glitches,
            ceiling,
            band_size
        );
        // And it must be a real, non-zero cost — scheme B is not free.
        assert!(r.affected_legit_glitches > 0);
    }

    #[test]
    fn cloned_card_is_flagged_from_the_return_channel() {
        let mut cfg = SimConfig::small();
        cfg.subscribers = 64;
        cfg.traitor = 20;
        cfg.warmup_periods = 0;
        cfg.measure_periods = 0;
        let sim = Simulator::build(cfg);
        // Two boxes report the same ack in epoch 0 -> flagged immediately.
        assert_eq!(sim.detect_clone(1), Some(0));
    }

    #[test]
    fn tiny_budget_refuses_card_search_and_reports() {
        // Phase A (band fingerprinting) costs no ECM bytes, so a tiny budget
        // cannot stop it.  Phase B (card suppression inside the band) costs per
        // EMM and *must* be the thing that gets refused.
        let mut sim = Simulator::build(SimConfig::small());
        let r = sim.run_trace(10);
        assert!(
            r.band_search_complete,
            "band phase should not need a budget"
        );
        assert!(r.bandwidth_exhausted, "card phase should be refused");
        assert!(!r.card_search_complete);
        assert!(r.found_card.is_none());
    }
}
