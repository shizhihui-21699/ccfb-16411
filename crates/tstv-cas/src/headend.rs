//! The headend: generates ECM/EMM, manages bands, and schedules per-band key
//! segments.
//!
//! ## The one rule that shapes everything
//!
//! The CW for `(program, period)` is a **single global value**.  The headend
//! cannot send different viewers different CWs — the scrambled video is one
//! broadcast stream.  What *is* per-band is the **ECM channel**: each band gets
//! its own ECM section (own band key, own ciphertext, own nonce) carrying the
//! *same* CWs.  Differentiation lives on the delivery side, always.
//!
//! ## Why key-segment changes never glitch legitimate viewers
//!
//! A key change (ordinary epoch rollover, or a per-band [`ProbeState`] segment)
//! affects only periods `>= now + lookahead`.  Any CW a box needs within the next
//! `lookahead` periods is already held, decrypted under the *old* band key; ECMs
//! are split so a section never straddles a key boundary, and a card keeps
//! prev/cur/next key slots.  So there is no instant at which a legitimate box
//! lacks the CW for the period it is playing.
//!
//! **This is key-scheduling infrastructure, not the tracing mechanism.**  The
//! [`ProbeState`] type predates the corrected design and is kept because it is
//! exactly how a *suppression* channel is expressed: a probed band's ECMs can be
//! withheld/bound to a fresh key segment.  The tracing controller in
//! `tstv-trace` uses suppression, not "blind the sharing card" — see
//! `docs/DESIGN.md` §3.2.

use std::collections::BTreeMap;

use tstv_core::crypto::ctr_xor;
use tstv_core::ids::{CardId, GroupId, PeriodIndex, ProgramId};
use tstv_core::prf::MasterSecret;
use tstv_core::wire::{Ecm, Emm, EMM_FLAG_ENTITLED, EMM_FLAG_REVOKE};
use tstv_core::Result;

use crate::bandwidth;
use crate::params::Params;

/// A key-segment change scoped to a subset of bands.  Used by the tracing
/// controller to express a suppression channel; **not** a way to blind a
/// sharing card (that is physically impossible — see `docs/DESIGN.md` §3.2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProbeState {
    pub probe_id: u32,
    /// Bands being probed: they move to a fresh key epoch the others do not have.
    pub bands: Vec<GroupId>,
    /// First period that uses the new key epoch.
    pub effective_period: u64,
}

/// One segment of a band's key schedule.  `effective_period` is the first period
/// that uses `probe_offset`; before it, the previous segment applies.
#[derive(Clone, Copy, Debug)]
struct KeySegment {
    effective_period: u64,
    probe_offset: u32,
    probe_id: u32,
}

/// Per-band transmission state for a program.
///
/// The key schedule is a *piecewise* function of period, not a single flag.
/// That is what makes the zero-glitch guarantee true: a probe appends a segment
/// starting at `now + lookahead`, so every period already inside some box's
/// buffer keeps the key that box already holds.
#[derive(Clone, Debug, Default)]
struct BandState {
    segments: Vec<KeySegment>,
}

impl BandState {
    /// Segment in force for `period`.  Segments are sorted by effective period.
    fn offset_at(&self, period: u64) -> (u32, u32) {
        let mut best = (0u32, 0u32); // (offset, probe_id)
        for seg in &self.segments {
            if seg.effective_period <= period {
                best = (seg.probe_offset, seg.probe_id);
            } else {
                break;
            }
        }
        best
    }

    fn push(&mut self, seg: KeySegment) {
        // Keep sorted; probes always append at a non-decreasing effective period.
        debug_assert!(self
            .segments
            .last()
            .is_none_or(|s| s.effective_period <= seg.effective_period));
        self.segments.push(seg);
    }
}

#[derive(Clone)]
pub struct Headend {
    pub master: MasterSecret,
    pub params: Params,
    pub program: ProgramId,
    bands: Vec<BandState>,
    /// Cards we know about (for EMM generation and probing).
    cards: BTreeMap<CardId, GroupId>,
    pub next_probe_id: u32,
    pub active_probes: Vec<ProbeState>,
}

impl Headend {
    pub fn new(master: MasterSecret, params: Params, program: ProgramId) -> Result<Self> {
        params.validate()?;
        let bands = (0..params.bands).map(|_| BandState::default()).collect();
        Ok(Self {
            master,
            params,
            program,
            bands,
            cards: BTreeMap::new(),
            next_probe_id: 1,
            active_probes: Vec::new(),
        })
    }

    /// Register a card into a band.  Real plants do this at activation.
    pub fn enroll(&mut self, card: CardId, band: GroupId) {
        self.cards.insert(card, band);
    }

    pub fn card_band(&self, card: CardId) -> Option<GroupId> {
        self.cards.get(&card).copied()
    }

    pub fn card_count(&self) -> usize {
        self.cards.len()
    }

    /// Effective key epoch for `(band, period)`.
    fn band_epoch(&self, band: GroupId, period: u64) -> u32 {
        let base = self.params.epoch_of(period);
        let (off, _) = self.bands[band.0 as usize].offset_at(period);
        base.wrapping_add(off.wrapping_mul(1 << 16))
    }

    /// Band key in force at `period`.  Public for tests and the simulator's
    /// pirate relay, which must reproduce what a card would have decrypted.
    pub fn band_key(&self, band: GroupId, period: u64) -> [u8; 16] {
        self.master
            .band_key(self.program, band, self.band_epoch(band, period))
    }

    /// First period `>= from` at which `band`'s key epoch changes, if one lands
    /// within `[from, limit)`.
    fn next_key_boundary(&self, band: GroupId, from: u64, limit: u64) -> Option<u64> {
        // Two things can move the boundary: the ordinary epoch schedule, and a
        // pending probe segment.
        let mut best = None;
        // Ordinary epoch boundary.
        let ep = self.params.epoch_periods.max(1);
        let next_epoch = (from / ep + 1) * ep;
        if next_epoch < limit {
            best = Some(next_epoch);
        }
        // Probe segments.
        for seg in &self.bands[band.0 as usize].segments {
            if seg.effective_period > from && seg.effective_period < limit {
                best =
                    Some(best.map_or(seg.effective_period, |b: u64| b.min(seg.effective_period)));
            }
        }
        best
    }

    /// ECM sections a band transmits for `period`.  Each carries CWs for a run
    /// of periods that share ONE key epoch; a run never spans a key boundary, so
    /// a receiver needs exactly the single band key named in the section's
    /// `epoch` field to open it.
    ///
    /// Returns one or more sections.  Splitting at the boundary is what keeps
    /// the transition glitch-free: periods on the far side of a probe boundary
    /// are in a separate, independently-keyed section, and a card holding both
    /// the old and the new key (its two key slots) opens whichever half it is
    /// playing.
    pub fn build_ecms(&self, band: GroupId, period: u64) -> Result<Vec<Vec<u8>>> {
        let n = self.params.lookahead_periods as u64;
        let end = period + n;
        let mut out = Vec::new();
        let mut cursor = period;
        while cursor < end {
            let seg_end = self
                .next_key_boundary(band, cursor, end)
                .unwrap_or(end)
                .min(end);
            let count = (seg_end - cursor) as usize;
            let mut payload = Vec::with_capacity(count * 16);
            for i in 0..count as u64 {
                payload.extend_from_slice(&self.master.cw(self.program, PeriodIndex(cursor + i)));
            }
            let key = self.band_key(band, cursor);
            let mut ecm = Ecm {
                program: self.program,
                band,
                epoch: self.band_epoch(band, cursor),
                first_period: PeriodIndex(cursor),
                payload: Vec::new(),
            };
            debug_assert_eq!(key, self.band_key(band, seg_end - 1));
            ctr_xor(&key, &ecm.nonce(), &mut payload);
            ecm.payload = payload;
            out.push(ecm.encode(&key)?);
            cursor = seg_end;
        }
        Ok(out)
    }

    /// Single-section convenience for the common no-boundary case.  Panics in
    /// debug if the lookahead happens to straddle a key boundary; production
    /// code paths use [`build_ecms`].
    pub fn build_ecm(&self, band: GroupId, period: u64) -> Result<Vec<u8>> {
        let mut sections = self.build_ecms(band, period)?;
        debug_assert_eq!(sections.len(), 1, "lookahead straddles a key boundary");
        Ok(sections.remove(0))
    }

    /// All ECM sections a receiver would see at `period`, for every band.  May
    /// contain more than one section per band around a key boundary.
    pub fn ecm_burst(&self, period: u64) -> Result<Vec<(GroupId, Vec<u8>)>> {
        let mut out = Vec::new();
        for b in 0..self.bands.len() as u16 {
            let band = GroupId(b);
            for sec in self.build_ecms(band, period)? {
                out.push((band, sec));
            }
        }
        Ok(out)
    }

    /// The EMM that grants `card` its band and entitlements at service `epoch`.
    ///
    /// The card also needs to know which *key epoch* its band is on: at the
    /// current period (the card acts on this immediately) that is
    /// `band_epoch(band, now)`.  `now_period` must be the period the EMM is
    /// delivered in, so a pending probe's new segment is reflected.
    pub fn build_emm_at(&self, card: CardId, epoch: u32, now_period: u64) -> Option<Vec<u8>> {
        let band = *self.cards.get(&card)?;
        let (_, probe_id) = self.bands[band.0 as usize].offset_at(now_period);
        let emm = Emm {
            card,
            epoch,
            band,
            probe_id,
            key_epoch: self.band_epoch(band, now_period),
            flags: EMM_FLAG_ENTITLED,
            band_mask: 1u64 << band.0,
            trace_token: self.master.trace_token(card, epoch),
        };
        Some(emm.encode(&self.master.card_key(card)))
    }

    /// Convenience for the common case where "now" is period 0 (initial grant).
    pub fn build_emm(&self, card: CardId, epoch: u32) -> Option<Vec<u8>> {
        self.build_emm_at(card, epoch, 0)
    }

    pub fn build_revoke_emm_at(
        &self,
        card: CardId,
        epoch: u32,
        now_period: u64,
    ) -> Option<Vec<u8>> {
        let band = *self.cards.get(&card)?;
        let (_, probe_id) = self.bands[band.0 as usize].offset_at(now_period);
        let emm = Emm {
            card,
            epoch,
            band,
            probe_id,
            key_epoch: self.band_epoch(band, now_period),
            flags: EMM_FLAG_ENTITLED | EMM_FLAG_REVOKE,
            band_mask: 1u64 << band.0,
            trace_token: self.master.trace_token(card, epoch),
        };
        Some(emm.encode(&self.master.card_key(card)))
    }

    pub fn build_revoke_emm(&self, card: CardId, epoch: u32) -> Option<Vec<u8>> {
        self.build_revoke_emm_at(card, epoch, 0)
    }

    /// Start a scoped key-segment change against `bands`, effective
    /// `lookahead` periods out.  (See the module docs: this is the key-
    /// scheduling primitive behind a suppression channel.)
    ///
    /// The probed bands get a *new key segment* starting at
    /// `now + lookahead_periods`.  Periods before that boundary keep their old
    /// key, so any CW already buffered by a legitimate box stays valid — that is
    /// the whole safety argument.  Non-probed bands are untouched.
    ///
    /// After the boundary, ECMs on a probed band are encrypted under a key the
    /// rest of the plant does not have.  A pirate box fed by a card in a probed
    /// band stops opening them; if the sharing card is elsewhere, the pirate
    /// still gets the *same* CWs from an unprobed band.  That difference is the
    /// 1 bit each probe measures.
    pub fn start_probe(&mut self, bands: Vec<GroupId>, now_period: u64) -> ProbeState {
        let probe_id = self.next_probe_id;
        self.next_probe_id += 1;
        let effective_period = now_period + self.params.lookahead_periods as u64;
        for band in &bands {
            let st = &mut self.bands[band.0 as usize];
            let (cur_off, _) = st.offset_at(effective_period);
            let next_off = cur_off.wrapping_add(1);
            let seg = KeySegment {
                effective_period,
                probe_offset: next_off,
                probe_id,
            };
            // A previous probe may already be pending at the same boundary;
            // apply immediately in that case (offset still advances, so keys
            // rotate).  This keeps segments strictly increasing in period.
            st.push(seg);
        }
        let state = ProbeState {
            probe_id,
            bands: bands.clone(),
            effective_period,
        };
        self.active_probes.push(state.clone());
        state
    }

    /// EMMs announcing a probe to the cards inside the probed bands.  Only those
    /// cards need a new EMM, so probe EMM traffic scales with the probe subset,
    /// not with the network.
    pub fn probe_emms(&self, probe: &ProbeState, epoch: u32) -> Vec<(CardId, Vec<u8>)> {
        let mut out = Vec::new();
        let set: std::collections::BTreeSet<u16> = probe.bands.iter().map(|b| b.0).collect();
        for (&card, band) in &self.cards {
            if set.contains(&band.0) {
                // key_epoch must reflect the *effective* period, so cards in the
                // probed bands derive the post-probe key.
                if let Some(bytes) = self.build_emm_at(card, epoch, probe.effective_period) {
                    out.push((card, bytes));
                }
            }
        }
        out
    }

    /// Bytes a probe costs: ECMs on probed bands for `periods` periods plus the
    /// per-card EMMs.  Used by the budget-aware controller.
    pub fn probe_cost_bytes(&self, probe: &ProbeState, periods: u64) -> u64 {
        let ecm = bandwidth::ecm_section_len(self.params.lookahead_periods) as u64;
        let n_bands = probe.bands.len() as u64;
        let emm = bandwidth::emm_section_len() as u64;
        let set: std::collections::BTreeSet<u16> = probe.bands.iter().map(|b| b.0).collect();
        let n_cards = self.cards.values().filter(|b| set.contains(&b.0)).count() as u64;
        ecm * n_bands * periods * self.params.ecm_repeats as u64 + emm * n_cards
    }

    pub fn bandwidth_report(&self) -> bandwidth::BandwidthReport {
        bandwidth::report(&self.params)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::card::Card;

    fn headend() -> Headend {
        let m = MasterSecret::derive_for_test(b"headend-test");
        Headend::new(m, Params::default(), ProgramId(1)).unwrap()
    }

    #[test]
    fn ecm_carries_global_cws_for_the_band() {
        let he = headend();
        let band = GroupId(3);
        let key = he.band_key(band, 10);
        let bytes = he.build_ecm(band, 10).unwrap();
        let ecm = Ecm::decode(&bytes, &key).unwrap();
        assert_eq!(ecm.band, band);
        assert_eq!(ecm.first_period, PeriodIndex(10));
        let mut plain = ecm.payload.clone();
        ctr_xor(&key, &ecm.nonce(), &mut plain);
        for (i, chunk) in plain.chunks_exact(16).enumerate() {
            let expect = he.master.cw(ProgramId(1), PeriodIndex(10 + i as u64));
            assert_eq!(chunk, &expect);
        }
    }

    #[test]
    fn same_cw_different_band_ciphertext() {
        let he = headend();
        let a = he.build_ecm(GroupId(0), 5).unwrap();
        let b = he.build_ecm(GroupId(1), 5).unwrap();
        assert_ne!(a, b, "band ECMs must differ on the wire");
        // ...but they decrypt to identical CWs.
        let ka = he.band_key(GroupId(0), 5);
        let kb = he.band_key(GroupId(1), 5);
        let ea = Ecm::decode(&a, &ka).unwrap();
        let eb = Ecm::decode(&b, &kb).unwrap();
        let mut pa = ea.payload.clone();
        let mut pb = eb.payload.clone();
        ctr_xor(&ka, &ea.nonce(), &mut pa);
        ctr_xor(&kb, &eb.nonce(), &mut pb);
        assert_eq!(pa, pb);
    }

    #[test]
    fn probe_rotates_only_probed_band_keys_from_effective_period() {
        let mut he = headend();
        let now = 100;
        let before_probed = he.band_key(GroupId(2), now);
        let before_other = he.band_key(GroupId(5), now);

        let probe = he.start_probe(vec![GroupId(2)], now);
        assert_eq!(
            probe.effective_period,
            now + he.params.lookahead_periods as u64
        );

        // Current keys (already-delivered window) are unchanged.
        assert_eq!(he.band_key(GroupId(2), now), before_probed);
        // Future keys differ for the probed band only.
        let future = probe.effective_period + 10;
        assert_ne!(he.band_key(GroupId(2), future), {
            let mut fresh = headend();
            fresh.band_key(GroupId(2), future)
        });
        let mut fresh = headend();
        // Unprobed band is untouched even in the future... relative to a fresh plant.
        let _ = &mut fresh;
        // (The fresh headend shares the master, so this compares like with like.)
        assert_eq!(he.band_key(GroupId(5), future), {
            let f = headend();
            f.band_key(GroupId(5), future)
        });
        let _ = before_other;
    }

    #[test]
    fn probe_emms_only_cover_probed_bands() {
        let mut he = headend();
        for id in 0..10u32 {
            he.enroll(CardId(id), GroupId(id as u16 % 4));
        }
        let probe = he.start_probe(vec![GroupId(1)], 0);
        let emms = he.probe_emms(&probe, 1);
        // Cards in band 1: ids 1, 5, 9.
        assert_eq!(emms.len(), 3);
        for (card, bytes) in emms {
            assert_eq!(he.card_band(card).unwrap(), GroupId(1));
            let c = Card::new(card, &he.master);
            let mut c = c;
            // The card must accept the probe EMM and see the new key epoch.
            assert!(c.accept_emm(&bytes, &he.master).unwrap());
            assert_eq!(c.state.probe_id, probe.probe_id);
        }
    }

    #[test]
    fn legit_viewer_glitch_free_across_a_probe() {
        // The single most important property: a rekey probe changes key
        // material only outside every legitimate box's buffered window, so a
        // clean receiver never misses a period.
        let mut he = headend();
        let card = CardId(42);
        he.enroll(card, GroupId(6));
        let mut stb = crate::stb::Stb::new(0, Card::new(card, &he.master), &he.params);
        stb.on_emm(&he.build_emm(card, 0).unwrap(), &he.master);

        let mut glitches = 0;
        let mut split_sections = 0;
        let mut period = 0u64;
        // Steady state, then a probe fires at period 20.
        for _ in 0..80 {
            if period == 20 {
                let probe = he.start_probe(vec![GroupId(6)], period);
                // The box receives the probe EMM sometime before the boundary;
                // deliver it at the effective period's delivery slot.
                for (c, bytes) in he.probe_emms(&probe, he.params.epoch_of(period)) {
                    if c == card {
                        stb.on_emm(&bytes, &he.master);
                    }
                }
            }
            // At wall-clock period `period` the headend delivers ECMs for
            // `period..period+look` and the box plays `period` — which it
            // received `look` iterations ago and has held ever since.  The ring
            // is exactly `look` deep, so this is steady state.
            let bursts = he.ecm_burst(period).unwrap();
            if bursts.len() > he.params.bands as usize {
                split_sections += 1; // a key boundary split an ECM this period
            }
            stb.on_ecm_burst(&bursts, &mut |_| true);
            if stb.play(period) == crate::stb::StbOutcome::Glitch {
                glitches += 1;
            }
            period += 1;
        }
        // The probe must actually have bitten: it split at least one ECM at a
        // key boundary (otherwise this test proves nothing), and even so the
        // legitimate box never glitched.
        assert!(
            split_sections > 0,
            "probe never forced an ECM key split — test is vacuous"
        );
        assert_eq!(glitches, 0, "probe caused {glitches} legitimate glitches");
    }

    #[test]
    fn enrolled_card_opens_its_band_ecm() {
        let mut he = headend();
        let card = CardId(77);
        he.enroll(card, GroupId(4));
        let mut c = Card::new(card, &he.master);
        c.accept_emm(&he.build_emm(card, 0).unwrap(), &he.master)
            .unwrap();
        let ecm = he.build_ecm(GroupId(4), 20).unwrap();
        let got = c.open_ecm(&ecm).unwrap();
        assert_eq!(got.len(), he.params.lookahead_periods);
        // A card in another band cannot.
        let mut other = Card::new(CardId(78), &he.master);
        he.enroll(CardId(78), GroupId(5));
        other
            .accept_emm(&he.build_emm(CardId(78), 0).unwrap(), &he.master)
            .unwrap();
        assert!(other.open_ecm(&ecm).unwrap().is_empty());
    }
}
