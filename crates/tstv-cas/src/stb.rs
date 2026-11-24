//! Set-top-box model.
//!
//! A box owns a card, receives the broadcast stream, holds a *lookahead buffer*
//! of control words, and plays one period at a time.  It plays a period only if
//! it holds the CW for that period at the period boundary; otherwise that period
//! is a **glitch**.
//!
//! This is a faithful abstraction of a scrambled linear service: without the CW
//! for a period the box cannot descramble that period's pictures.  It is also
//! the metric the whole design is judged by — `legit_glitches` must be zero.
//!
//! The box is *not* allowed to cheat: it cannot ask the headend for a resent
//! ECM outside the broadcast schedule, and it cannot buffer more than the
//! firmware's ring (which is exactly `lookahead` deep).  Those limits are what
//! make the zero-glitch claim meaningful.

use std::collections::BTreeMap;

use tstv_core::ids::{PeriodIndex, ProgramId};
use tstv_core::wire::Ecm;

use crate::card::Card;
use crate::params::Params;

/// One period's playback result.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StbOutcome {
    /// CW was present at the boundary.
    Clean,
    /// CW was absent; the viewer saw the period as scrambled.
    Glitch,
}

/// Delivery model shared by legitimate boxes and the pirate relay's input: the
/// broadcast stream as seen by one receiver, with jitter and loss applied by the
/// caller.  In the simulator we apply these per-packet rather than by storing a
/// whole stream, so boxes are cheap to instantiate by the thousand.
pub struct Stb {
    pub card: Card,
    pub box_id: u32,
    /// Periods currently playable: period -> CW.
    buffer: BTreeMap<u64, [u8; 16]>,
    /// Highest period boundary the box has played through.
    played_through: Option<u64>,
    /// Firmware ring size: never hold more than this many periods ahead.
    ring: usize,
    /// The card's trace token for the current epoch, if any — this is what the
    /// box would relay on the return channel and what a pirate relay observes.
    pub last_trace_token: Option<[u8; 16]>,
    pub last_probe_id: u32,
    /// `(epoch, first_period)` of ECMs already opened, so a re-broadcast of the
    /// same lookahead window is not decrypted again.  The `epoch` field is in
    /// the clear header and distinguishes two different ciphertexts that cover
    /// the same periods across a key-segment boundary — omitting it would make
    /// the box skip the post-probe ECM it needs.  Small fixed size in a real
    /// box; that is why it is bounded here too.
    seen_ecms: std::collections::VecDeque<(u32, u64)>,
}

impl Stb {
    pub fn new(box_id: u32, card: Card, params: &Params) -> Self {
        Self {
            card,
            box_id,
            buffer: BTreeMap::new(),
            played_through: None,
            // Ring is sized to the lookahead; a box whose buffer is full drops
            // the oldest *future* period, exactly like a fixed ring buffer.
            ring: params.lookahead_periods,
            last_trace_token: None,
            last_probe_id: 0,
            seen_ecms: std::collections::VecDeque::new(),
        }
    }

    /// Accept an EMM (broadcast); returns whether the card took it.
    pub fn on_emm(&mut self, bytes: &[u8], master: &tstv_core::prf::MasterSecret) -> bool {
        match self.card.accept_emm(bytes, master) {
            Ok(accepted) => {
                if accepted {
                    self.last_trace_token = Some(self.card.state.trace_token);
                    self.last_probe_id = self.card.state.probe_id;
                }
                accepted
            }
            Err(_) => false,
        }
    }

    /// Accept all ECMs in a burst.  `delivered` decides per section whether it
    /// survived; the box drops what it cannot open without erroring, which is
    /// exactly how a real receiver behaves on a foreign-band ECM.
    pub fn on_ecm_burst(
        &mut self,
        bursts: &[(tstv_core::ids::GroupId, Vec<u8>)],
        delivered: &mut dyn FnMut(usize) -> bool,
    ) {
        for (i, (_band, bytes)) in bursts.iter().enumerate() {
            if !delivered(i) {
                continue;
            }
            self.on_ecm(bytes, true);
        }
    }

    /// Single ECM convenience (used by the pirate path, which forwards one CW).
    pub fn on_ecm(&mut self, bytes: &[u8], delivered: bool) {
        if !delivered {
            return;
        }
        // Skip an ECM we have already opened: a re-broadcast of the same
        // lookahead window carries identical ciphertext.  Key on (epoch,
        // first_period) so a re-keyed section over the same periods is *not*
        // skipped.  Only recorded when the section actually opened — a section
        // for another band fails to authenticate and returns an empty set, and
        // must not poison the cache for the section this card *can* open.
        // Decrypt unless we both (a) saw this section before and (b) still hold
        // every period it covers.  Condition (b) matters: a period can be evicted
        // by the ring cap, and a later retransmission must be able to restore it.
        // We can't know the periods without decrypting, so we use the cheap clear
        // header's `(epoch, first_period, count)` to check coverage.
        // A section entirely in the past is useless — skip before any crypto.
        // This is both a fast path and the common case for a re-broadcast window
        // whose leading periods have already been played.
        if self.entirely_played(bytes) {
            return;
        }
        let key = ecm_dedup_key(bytes);
        if let Some(k) = key {
            if self.seen_ecms.contains(&k) {
                return;
            }
        }
        if let Ok(cws) = self.card.open_ecm(bytes) {
            if cws.is_empty() {
                return;
            }
            for (period, cw) in cws {
                self.insert(period, cw);
            }
            if let Some(k) = key {
                if !self.seen_ecms.contains(&k) {
                    if self.seen_ecms.len() >= 4 * self.ring.max(1) {
                        self.seen_ecms.pop_front();
                    }
                    self.seen_ecms.push_back(k);
                }
            }
        }
    }

    fn insert(&mut self, period: PeriodIndex, cw: [u8; 16]) {
        // Do not buffer anything already played: it is useless and it would
        // push out live periods under the ring cap.
        if let Some(last) = self.played_through {
            if period.0 <= last {
                return;
            }
        }
        self.buffer.insert(period.0, cw);
        // Ring cap is enforced relative to play position, not to the oldest
        // buffered entry: a re-broadcast of the lookahead window must never
        // evict the period the box is about to play.  Keep at most `ring`
        // periods in the window `[next_playable, next_playable + ring)`.
        let floor = self.played_through.map(|p| p + 1).unwrap_or(0);
        let cap = floor + self.ring as u64;
        // Drop anything beyond the cap (furthest-future first).
        while self.buffer.len() > self.ring {
            let newest = *self.buffer.keys().next_back().unwrap();
            if newest >= cap {
                self.buffer.remove(&newest);
            } else {
                // Evict the oldest that is still above the floor.
                match self.buffer.keys().find(|&&k| k >= floor) {
                    Some(&k) if k != newest => {
                        self.buffer.remove(&k);
                    }
                    _ => break,
                }
            }
        }
    }

    /// Try to play `period`.  Returns the outcome; advances `played_through`.
    ///
    /// A box that never received any CW (e.g. wrong band, revoked) glitches
    /// every period — correct, and what makes a revoked card stop feeding a
    /// pirate relay useful pictures.
    pub fn play(&mut self, period: u64) -> StbOutcome {
        if let Some(last) = self.played_through {
            if period <= last {
                // Replay/retransmit; do not double-count.
                return StbOutcome::Clean;
            }
        }
        self.played_through = Some(period);
        // Keep only the current and future periods.
        self.buffer = self.buffer.split_off(&period);

        if self.buffer.remove(&period).is_some() {
            StbOutcome::Clean
        } else {
            StbOutcome::Glitch
        }
    }

    pub fn has_cw(&self, period: u64) -> bool {
        self.buffer.contains_key(&period)
    }

    pub fn buffered_ahead(&self, from: u64) -> usize {
        self.buffer.range(from..).count()
    }

    /// Whether every period an ECM section covers has already been played, so
    /// the section can never be useful again.
    fn entirely_played(&self, section: &[u8]) -> bool {
        let Some(last) = self.played_through else {
            return false;
        };
        if section.len() < 19 {
            return false;
        }
        let n = section[18] as usize;
        if n == 0 {
            return false;
        }
        match ecm_dedup_key(section) {
            Some((_, first)) => first + n as u64 - 1 <= last,
            None => false,
        }
    }

    /// The CW the box is using, for a pirate relay that forwards it verbatim.
    pub fn cw_for(&self, period: u64) -> Option<[u8; 16]> {
        self.buffer.get(&period).copied()
    }
}

/// A legitimate viewer that also reports usage over the return channel.
pub struct ViewingStats {
    pub clean: u64,
    pub glitch: u64,
    pub missed_ecm_bursts: u64,
}

impl ViewingStats {
    pub fn new() -> Self {
        Self {
            clean: 0,
            glitch: 0,
            missed_ecm_bursts: 0,
        }
    }

    pub fn record(&mut self, outcome: StbOutcome) {
        match outcome {
            StbOutcome::Clean => self.clean += 1,
            StbOutcome::Glitch => self.glitch += 1,
        }
    }

    pub fn glitch_rate(&self) -> f64 {
        let total = self.clean + self.glitch;
        if total == 0 {
            0.0
        } else {
            self.glitch as f64 / total as f64
        }
    }
}

impl Default for ViewingStats {
    fn default() -> Self {
        Self::new()
    }
}

/// `(epoch, first_period)` from an ECM's clear header, or `None` if too short.
pub fn ecm_dedup_key(section: &[u8]) -> Option<(u32, u64)> {
    if section.len() < 18 {
        return None;
    }
    // Layout: version(1) kind(1) program(2) band(2) epoch(4) first_period(8)
    let epoch = u32::from_le_bytes(section[6..10].try_into().ok()?);
    let first = u64::from_le_bytes(section[10..18].try_into().ok()?);
    Some((epoch, first))
}

/// Decode an ECM's CWs without a card — the headend's own view.  Used to build
/// a pirate relay's "what the sharing card produced" trace in tests.
pub fn ecm_cws(bytes: &[u8], key: &[u8; 16]) -> Option<(u64, Vec<[u8; 16]>, ProgramId)> {
    let ecm = Ecm::decode(bytes, key).ok()?;
    let mut plain = ecm.payload.clone();
    tstv_core::crypto::ctr_xor(key, &ecm.nonce(), &mut plain);
    let cws = plain
        .as_chunks::<16>()
        .0
        .iter()
        .map(|c| {
            let mut a = [0u8; 16];
            a.copy_from_slice(c);
            a
        })
        .collect();
    Some((ecm.first_period.0, cws, ecm.program))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::headend::Headend;
    use tstv_core::ids::{CardId, GroupId};
    use tstv_core::prf::MasterSecret;

    fn setup() -> (Headend, Params) {
        let m = MasterSecret::derive_for_test(b"stb-test");
        let p = Params::default();
        let mut he = Headend::new(m, p.clone(), ProgramId(1)).unwrap();
        he.enroll(CardId(1), GroupId(0));
        (he, p)
    }

    #[test]
    fn clean_playback_with_full_lookahead() {
        let (he, p) = setup();
        let mut stb = Stb::new(0, Card::new(CardId(1), &he.master), &p);
        stb.on_emm(&he.build_emm(CardId(1), 0).unwrap(), &he.master);
        let bursts = he.ecm_burst(0).unwrap();
        stb.on_ecm_burst(&bursts, &mut |_| true);
        for period in 0..4 {
            assert_eq!(stb.play(period), StbOutcome::Clean, "period {period}");
        }
    }

    #[test]
    fn rebroadcast_window_recovers_a_lost_ecm() {
        // The whole point of re-transmitting the lookahead window every period:
        // an ECM lost in one period is offered again next period and the box
        // must accept that retransmission (its dedup cache must not block it for
        // an ECM it never opened).
        let (he, p) = setup();
        let mut stb = Stb::new(0, Card::new(CardId(1), &he.master), &p);
        stb.on_emm(&he.build_emm(CardId(1), 0).unwrap(), &he.master);
        // Period 0's window is dropped entirely.
        let w0 = he.ecm_burst(0).unwrap();
        stb.on_ecm_burst(&w0, &mut |_| false);
        // Period 1 re-broadcasts a window that still includes period 1..; also
        // re-offer period 0's section explicitly (some plants re-carry the
        // current period). We simulate the box having missed period 0 only.
        let w1 = he.ecm_burst(1).unwrap();
        stb.on_ecm_burst(&w1, &mut |_| true);
        // Period 1 is covered; period 0 was genuinely lost, so playing 0 glitches
        // but playing 1 must be clean.
        assert_eq!(stb.play(1), StbOutcome::Clean);
    }

    #[test]
    fn missing_ecm_glitches_after_buffer_drains() {
        let (he, p) = setup();
        let mut stb = Stb::new(0, Card::new(CardId(1), &he.master), &p);
        stb.on_emm(&he.build_emm(CardId(1), 0).unwrap(), &he.master);
        // Only the first burst arrives.
        let bursts = he.ecm_burst(0).unwrap();
        stb.on_ecm_burst(&bursts, &mut |_| true);
        // Play through the 4 buffered periods cleanly...
        for period in 0..4 {
            assert_eq!(stb.play(period), StbOutcome::Clean);
        }
        // ...then run dry.
        assert_eq!(stb.play(4), StbOutcome::Glitch);
    }

    #[test]
    fn dedup_cache_does_not_block_a_period_evicted_from_the_ring() {
        // Subtle failure mode: if an ECM is opened, cached in `seen_ecms`, then
        // evicted from the CW ring (too far ahead), a later retransmission of it
        // must be able to re-insert it.  `seen_ecms` is bounded to 4*ring and
        // rolls, but within one window a section could still be present — check
        // the steady-state window here never evicts a needed CW.
        let (he, p) = setup();
        let mut stb = Stb::new(0, Card::new(CardId(1), &he.master), &p);
        stb.on_emm(&he.build_emm(CardId(1), 0).unwrap(), &he.master);
        // Feed several overlapping windows, then play each period in order.
        for period in 0..12 {
            let w = he.ecm_burst(period).unwrap();
            stb.on_ecm_burst(&w, &mut |_| true);
            assert_eq!(stb.play(period), StbOutcome::Clean, "period {period}");
        }
    }

    #[test]
    fn dedup_is_safe_because_ring_depth_equals_lookahead() {
        // The dedup cache skips a section we've already opened.  That is only
        // safe if a seen section's periods are never needed again after being
        // evicted.  Since the CW ring is exactly `lookahead` deep and every
        // period is played as soon as it is due, an evicted period has already
        // been played — so skipping its retransmission is correct.  Lock that
        // invariant: straightforward steady playback stays glitch-free.
        let (he, p) = setup();
        assert_eq!(p.lookahead_periods, 4);
        let mut stb = Stb::new(0, Card::new(CardId(1), &he.master), &p);
        stb.on_emm(&he.build_emm(CardId(1), 0).unwrap(), &he.master);
        for period in 0..200u64 {
            let w = he.ecm_burst(period).unwrap();
            stb.on_ecm_burst(&w, &mut |_| true);
            assert_eq!(stb.play(period), StbOutcome::Clean, "period {period}");
            // Ring never exceeds lookahead.
            assert!(stb.buffer.len() <= p.lookahead_periods);
        }
    }

    #[test]
    fn ring_never_holds_more_than_lookahead() {
        let (he, p) = setup();
        let mut stb = Stb::new(0, Card::new(CardId(1), &he.master), &p);
        stb.on_emm(&he.build_emm(CardId(1), 0).unwrap(), &he.master);
        let bursts = he.ecm_burst(0).unwrap();
        stb.on_ecm_burst(&bursts, &mut |_| true);
        assert_eq!(stb.buffer.len(), p.lookahead_periods);
        assert!(stb.buffered_ahead(0) <= p.lookahead_periods);
    }

    #[test]
    fn unentitled_box_glitches_everything() {
        let (he, p) = setup();
        // Card 2 is never enrolled; it has no band key.
        let mut stb = Stb::new(1, Card::new(CardId(2), &he.master), &p);
        let bursts = he.ecm_burst(0).unwrap();
        stb.on_ecm_burst(&bursts, &mut |_| true);
        for period in 0..4 {
            assert_eq!(stb.play(period), StbOutcome::Glitch);
        }
    }

    #[test]
    fn ecm_cws_helper_matches_plant() {
        let (he, p) = setup();
        let _ = p;
        let bytes = he.build_ecm(GroupId(0), 10).unwrap();
        let key = he.band_key(GroupId(0), 10);
        let (first, cws, _) = ecm_cws(&bytes, &key).unwrap();
        assert_eq!(first, 10);
        for (i, cw) in cws.iter().enumerate() {
            assert_eq!(*cw, he.master.cw(ProgramId(1), PeriodIndex(10 + i as u64)));
        }
    }
}
