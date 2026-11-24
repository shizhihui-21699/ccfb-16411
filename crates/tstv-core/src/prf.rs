//! Domain-separated key derivation.
//!
//! Every key in the system comes from one [`MasterSecret`] through HMAC-SHA256
//! with a textual `info` label.  Labels are part of the wire ABI: changing one
//! silently re-keys the whole plant, so they live here and only here.
//!
//! The headend regenerates control words on demand (`cw`), which is what lets it
//! re-send an ECM for a past period after a delivery hiccup without storing
//! anything.  Cards never derive CWs themselves — they receive them — so the
//! derivation path is headend-only.

use crate::crypto::{kdf, kdf_key};
use crate::ids::{CardId, GroupId, PeriodIndex, ProgramId};

/// 32 bytes of root secret.  In production this is split across HSMs.
#[derive(Clone)]
pub struct MasterSecret([u8; 32]);

impl MasterSecret {
    pub fn from_bytes(b: [u8; 32]) -> Self {
        Self(b)
    }

    /// Deterministic test/plant construction.  Not for production use.
    pub fn derive_for_test(seed: &[u8]) -> Self {
        let mut b = [0u8; 32];
        kdf(seed, b"tstv/master", &mut b).expect("32 bytes within limit");
        Self(b)
    }

    fn raw(&self) -> &[u8; 32] {
        &self.0
    }

    /// The control word for `(program, period)`.  16 bytes.
    ///
    /// This value is **network-common**: every receiver must obtain the same CW
    /// to descramble the same video.  See `docs/DESIGN.md` §"Why per-card CWs
    /// are impossible" — it is the single most important constraint in the
    /// design, and the reason differentiation happens on the *delivery* side
    /// rather than the *value* side.
    pub fn cw(&self, program: ProgramId, period: PeriodIndex) -> [u8; 16] {
        let mut info = [0u8; 24];
        info[..4].copy_from_slice(b"cw\0\0");
        info[4..6].copy_from_slice(&program.0.to_le_bytes());
        info[6..14].copy_from_slice(&period.0.to_le_bytes());
        kdf_key(self.raw(), &info)
    }

    /// Long-term AES key burned into a card at manufacture, keyed by card id.
    pub fn card_key(&self, card: CardId) -> [u8; 16] {
        let mut info = [0u8; 12];
        info[..8].copy_from_slice(b"card\0\0\0\0");
        info[8..12].copy_from_slice(&card.0.to_le_bytes());
        kdf_key(self.raw(), &info)
    }

    /// Service/band key: the key that decrypts band `g`'s ECM payload.  A card
    /// is entitled to exactly the bands in its profile; possessing `K_g` is what
    /// "being in band g" *means* cryptographically.
    pub fn band_key(&self, program: ProgramId, band: GroupId, epoch: u32) -> [u8; 16] {
        let mut info = [0u8; 22];
        info[..6].copy_from_slice(b"band\0\0");
        info[6..8].copy_from_slice(&program.0.to_le_bytes());
        info[8..10].copy_from_slice(&band.0.to_le_bytes());
        info[10..14].copy_from_slice(&epoch.to_le_bytes());
        kdf_key(self.raw(), &info)
    }

    /// Per-card trace token delivered inside the card's EMM for one epoch.
    /// Unique per (card, epoch); this is the "differentiated authorization
    /// information" that makes an entitled card individually identifiable.
    pub fn trace_token(&self, card: CardId, epoch: u32) -> [u8; 16] {
        let mut info = [0u8; 16];
        info[..6].copy_from_slice(b"tok\0\0\0");
        info[6..10].copy_from_slice(&card.0.to_le_bytes());
        info[10..14].copy_from_slice(&epoch.to_le_bytes());
        kdf_key(self.raw(), &info)
    }

    /// The value a card returns on the usage-report channel to prove it holds
    /// `trace_token(card, epoch)`.  Stateless for the headend: it can recompute
    /// any card's expected ack without storing per-card state.
    pub fn ack_tag(&self, card: CardId, epoch: u32) -> [u8; 16] {
        let mut info = [0u8; 16];
        info[..6].copy_from_slice(b"ack\0\0\0");
        info[6..10].copy_from_slice(&card.0.to_le_bytes());
        info[10..14].copy_from_slice(&epoch.to_le_bytes());
        kdf_key(self.raw(), &info)
    }

    /// Pseudo-random band assignment for a card.  `bands` must be a power of two
    /// for the split to be uniform; the caller enforces that.
    pub fn home_band(&self, card: CardId, bands: u16) -> GroupId {
        let mut info = [0u8; 12];
        info[..8].copy_from_slice(b"hband\0\0\0");
        info[8..12].copy_from_slice(&card.0.to_le_bytes());
        let mut out = [0u8; 4];
        kdf(self.raw(), &info, &mut out).expect("4 bytes");
        GroupId((u32::from_le_bytes(out) % bands as u32) as u16)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ms() -> MasterSecret {
        MasterSecret::derive_for_test(b"unit-test")
    }

    #[test]
    fn cw_changes_every_period_and_program() {
        let m = ms();
        let p = ProgramId(1);
        let a = m.cw(p, PeriodIndex(10));
        assert_ne!(a, m.cw(p, PeriodIndex(11)));
        assert_ne!(a, m.cw(ProgramId(2), PeriodIndex(10)));
        assert_eq!(a, m.cw(p, PeriodIndex(10)));
    }

    #[test]
    fn domains_never_collide() {
        let m = ms();
        let c = CardId(42);
        assert_ne!(m.card_key(c), m.trace_token(c, 0));
        assert_ne!(m.trace_token(c, 0), m.ack_tag(c, 0));
        assert_ne!(m.trace_token(c, 0), m.trace_token(c, 1));
    }

    #[test]
    fn home_band_is_stable_and_spread() {
        let m = ms();
        let mut counts = vec![0u32; 16];
        for id in 0..16_000u32 {
            let b = m.home_band(CardId(id), 16);
            assert_eq!(b, m.home_band(CardId(id), 16));
            counts[b.0 as usize] += 1;
        }
        for &c in &counts {
            assert!((800..1200).contains(&c), "band skew: {counts:?}");
        }
    }
}
