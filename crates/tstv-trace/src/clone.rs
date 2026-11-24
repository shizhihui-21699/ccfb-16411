//! Clone detection from return-channel acks.
//!
//! A card computes `ack = HMAC(K_card, "ack" ‖ epoch)`.  Its own box reports it
//! upstream together with a `source_id` the return path can observe (the same
//! device/network identifier old PPV cards already send).  A genuine card has
//! one source; a *cloned* card used in two boxes produces the **same ack** from
//! **two different sources** in the same epoch — detectable server-side with no
//! change to the card or its software.
//!
//! Limits, stated plainly:
//! * Requires a return channel.  Pure-broadcast cards can't do this; they are
//!   traced by the group-testing path only.
//! * A clone kept in one box (e.g. copied then the original destroyed) is
//!   indistinguishable.  This catches *simultaneous* double-use, which is what
//!   commercial sharing operations actually do.
//! * The headend never stores per-card state: it recomputes the expected ack
//!   from `(card, epoch)`, so detection is stateless across epochs.

use std::collections::BTreeMap;

use tstv_core::ids::CardId;
use tstv_core::prf::MasterSecret;

/// An ack as it arrives on the return channel.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AckReport {
    pub card: CardId,
    pub epoch: u32,
    pub source_id: u64,
    pub tag: [u8; 16],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CloneFinding {
    pub card: CardId,
    pub epoch: u32,
    pub sources: Vec<u64>,
}

/// Per-epoch accumulator.  Feed it every ack the return channel sees.
#[derive(Default)]
pub struct CloneDetector {
    /// (card, epoch) -> (tag -> set of sources)
    seen: BTreeMap<(CardId, u32), BTreeMap<[u8; 16], Vec<u64>>>,
    /// Acks that failed validation (not counted as clones; counted as `forged`).
    pub forged: u64,
    pub accepted: u64,
}

impl CloneDetector {
    pub fn new() -> Self {
        Self::default()
    }

    /// Validate the ack against what the card *should* have produced, then record
    /// the source.  An ack that does not verify is forged and ignored for clone
    /// purposes — otherwise anyone could frame a card by replaying a made-up tag
    /// from a second source.
    pub fn observe(&mut self, ack: AckReport, master: &MasterSecret) -> bool {
        let expected = master.ack_tag(ack.card, ack.epoch);
        if expected != ack.tag {
            self.forged += 1;
            return false;
        }
        self.accepted += 1;
        let sources = self
            .seen
            .entry((ack.card, ack.epoch))
            .or_default()
            .entry(ack.tag)
            .or_default();
        if !sources.contains(&ack.source_id) {
            sources.push(ack.source_id);
        }
        true
    }

    /// All cards seen from more than one source in a single epoch.
    pub fn findings(&self) -> Vec<CloneFinding> {
        let mut out = Vec::new();
        for (&(card, epoch), by_tag) in &self.seen {
            let mut sources: Vec<u64> = by_tag.values().flatten().copied().collect();
            sources.sort_unstable();
            sources.dedup();
            if sources.len() > 1 {
                out.push(CloneFinding {
                    card,
                    epoch,
                    sources,
                });
            }
        }
        out
    }

    /// Number of epochs until `card` is first flagged, given one ack per source
    /// per epoch starting at `start`.
    pub fn first_flagged_epoch(&self, card: CardId) -> Option<u32> {
        self.findings()
            .into_iter()
            .filter(|f| f.card == card)
            .map(|f| f.epoch)
            .min()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn master() -> MasterSecret {
        MasterSecret::derive_for_test(b"clone-test")
    }

    fn ack(m: &MasterSecret, card: u32, epoch: u32, source: u64) -> AckReport {
        AckReport {
            card: CardId(card),
            epoch,
            source_id: source,
            tag: m.ack_tag(CardId(card), epoch),
        }
    }

    #[test]
    fn single_source_is_not_a_clone() {
        let m = master();
        let mut d = CloneDetector::new();
        for e in 0..5 {
            assert!(d.observe(ack(&m, 7, e, 100), &m));
        }
        assert!(d.findings().is_empty());
    }

    #[test]
    fn two_sources_same_epoch_is_a_clone() {
        let m = master();
        let mut d = CloneDetector::new();
        d.observe(ack(&m, 7, 3, 100), &m);
        d.observe(ack(&m, 7, 3, 200), &m);
        let f = d.findings();
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].card, CardId(7));
        assert_eq!(f[0].sources, vec![100, 200]);
        assert_eq!(d.first_flagged_epoch(CardId(7)), Some(3));
    }

    #[test]
    fn different_epochs_different_sources_are_not_a_clone() {
        // A subscriber who legitimately moves their card to a new box between
        // epochs must not be flagged.
        let m = master();
        let mut d = CloneDetector::new();
        d.observe(ack(&m, 7, 1, 100), &m);
        d.observe(ack(&m, 7, 2, 200), &m);
        assert!(d.findings().is_empty());
    }

    #[test]
    fn forged_ack_cannot_frame_a_card() {
        let m = master();
        let mut d = CloneDetector::new();
        let good = ack(&m, 7, 3, 100);
        d.observe(good, &m);
        // Attacker replays a bogus tag from another source.
        let forged = AckReport {
            card: CardId(7),
            epoch: 3,
            source_id: 999,
            tag: [0u8; 16],
        };
        assert!(!d.observe(forged, &m));
        assert_eq!(d.forged, 1);
        assert!(d.findings().is_empty());
    }

    #[test]
    fn detects_only_the_cloned_card_among_many() {
        let m = master();
        let mut d = CloneDetector::new();
        for e in 0..4 {
            for c in 0..50u32 {
                d.observe(ack(&m, c, e, c as u64), &m);
            }
            // Card 13 is simultaneously cloned in a second box.
            d.observe(ack(&m, 13, e, 9000), &m);
        }
        let f = d.findings();
        assert_eq!(f.len(), 4, "one finding per epoch");
        assert!(f.iter().all(|x| x.card == CardId(13)));
    }
}
