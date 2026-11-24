//! Smart-card model.
//!
//! Deliberately dumb, because the cards in the field are dumb: a card
//!   * holds one long-term key `K_card` and cannot export it,
//!   * accepts only EMMs whose MAC verifies under `K_card`,
//!   * holds a set of band keys `K_band` (granted by EMM),
//!   * decrypts ECMs for bands it holds, and hands CWs to the host box,
//!   * optionally sends a periodic `ack` on the return channel.
//!
//! What it does *not* do: derive CWs, talk to the headend on demand, or hold
//! per-period state beyond the box's CW buffer.  Every one of those omissions is
//! a deliberate mirror of shipped hardware.

use tstv_core::crypto::ctr_xor;
use tstv_core::ids::{CardId, GroupId, PeriodIndex};
use tstv_core::prf::MasterSecret;
use tstv_core::wire::{Ecm, Emm};
use tstv_core::{Error, Result};

/// One band's key material.  Real cards hold a small fixed set of key slots per
/// entitlement — conventionally *current* and *next* — precisely so they can
/// straddle a key change without a gap.  We model three: `prev`, `cur`, `next`.
/// `prev` exists only so a section still in flight across a boundary can be
/// opened; it is dropped as soon as a newer key arrives beyond it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BandSlots {
    pub prev: Option<[u8; 16]>,
    pub cur: Option<[u8; 16]>,
    pub next: Option<[u8; 16]>,
}

impl BandSlots {
    fn all(&self) -> impl Iterator<Item = &[u8; 16]> {
        self.prev
            .iter()
            .chain(self.cur.iter())
            .chain(self.next.iter())
    }

    /// Install `key` for `epoch` relative to the currently-known `cur_epoch`.
    /// Idempotent; installing the same key twice is a no-op.
    fn install(&mut self, key: [u8; 16], key_epoch: u32, cur_epoch: &mut Option<u32>) {
        match *cur_epoch {
            Some(c) if key_epoch == c => {
                if self.cur != Some(key) {
                    // Same epoch id but different key can only happen on a probe
                    // key change with no epoch bump; treat as roll-forward.
                    self.prev = self.cur.take();
                    self.cur = Some(key);
                }
            }
            Some(c) if key_epoch > c => {
                self.prev = self.cur.take();
                self.cur = self.next.take().filter(|k| *k == key);
                self.cur = Some(key);
                *cur_epoch = Some(key_epoch);
            }
            Some(_) => {
                // Older key than current: keep in `next`-less prev slot only if
                // we have no prev and it is plausibly still in flight.
                if self.prev.is_none() {
                    self.prev = Some(key);
                }
            }
            None => {
                self.cur = Some(key);
                *cur_epoch = Some(key_epoch);
            }
        }
    }
}

/// Keys a card currently holds.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CardState {
    pub epoch: u32,
    pub band: GroupId,
    pub band_mask: u64,
    pub probe_id: u32,
    pub trace_token: [u8; 16],
    pub revoked: bool,
    pub entitled: bool,
    /// Band id -> key slots for the current epoch (and its neighbours during a
    /// transition).
    pub band_keys: Vec<(GroupId, BandSlots, Option<u32>)>,
}

impl CardState {
    pub fn key_for(&self, band: GroupId) -> Option<&[u8; 16]> {
        self.band_keys
            .iter()
            .find(|(b, _, _)| *b == band)
            .and_then(|(_, s, _)| s.cur.as_ref())
    }

    pub fn grants(&self, band: GroupId) -> bool {
        band.0 < 64 && self.entitled && !self.revoked && self.band_mask & (1u64 << band.0) != 0
    }
}

pub struct Card {
    pub id: CardId,
    key: [u8; 16],
    pub state: CardState,
    /// Highest epoch whose EMM has been applied; older EMMs are ignored to stop
    /// a stale broadcast from rolling a card back to a pre-revocation state.
    pub applied_epoch: u32,
}

impl Card {
    pub fn new(id: CardId, master: &MasterSecret) -> Self {
        Self {
            id,
            key: master.card_key(id),
            state: CardState::default(),
            applied_epoch: 0,
        }
    }

    /// Process a broadcast EMM.  Returns whether it was accepted.
    ///
    /// A card ignores EMMs for other cards *before* doing crypto on them?  No —
    /// it must do the MAC first, because the card id is inside the signed body
    /// and an attacker could otherwise forge a "not for me" section to mask a
    /// real one.  The MAC check is cheap (one CMAC) and hardware-accelerated.
    pub fn accept_emm(&mut self, bytes: &[u8], master: &MasterSecret) -> Result<bool> {
        let emm = match Emm::decode(bytes, &self.key) {
            Ok(e) => e,
            // Sections for other cards simply fail to authenticate; that is the
            // normal case for ~all broadcast traffic and is not an error.
            Err(Error::AuthFailed) => return Ok(false),
            Err(e) => return Err(e),
        };
        if emm.card != self.id {
            return Ok(false);
        }
        // Monotonic epoch: never regress.
        if emm.epoch < self.applied_epoch {
            return Ok(false);
        }
        self.applied_epoch = emm.epoch;
        self.state.epoch = emm.epoch;
        self.state.band = emm.band;
        self.state.band_mask = emm.band_mask;
        self.state.probe_id = emm.probe_id;
        self.state.entitled = emm.entitled();
        self.state.revoked = emm.revoked();

        if emm.revoked() {
            // A revocation wipes every key immediately; a revoked card feeds
            // nothing.
            self.state.band_keys.clear();
        } else if emm.entitled() {
            let want: Vec<GroupId> = (0..64u16)
                .map(GroupId)
                .filter(|g| emm.grants_band(*g))
                .collect();
            // Drop slots for bands no longer granted.
            self.state.band_keys.retain(|(g, _, _)| want.contains(g));
            for g in want {
                let key = master.band_key(program_of(&emm), g, emm.key_epoch);
                if let Some(slot) = self.state.band_keys.iter_mut().find(|(b, _, _)| *b == g) {
                    slot.1.install(key, emm.key_epoch, &mut slot.2);
                } else {
                    let mut slots = BandSlots::default();
                    let mut ce = None;
                    slots.install(key, emm.key_epoch, &mut ce);
                    self.state.band_keys.push((g, slots, ce));
                }
            }
        }
        self.state.trace_token = emm.trace_token;
        Ok(true)
    }

    /// Decrypt an ECM into `(period, cw)` pairs.  Returns the pairs the card
    /// could actually open; an empty vec means "wrong band or not entitled",
    /// which the box treats as a missed ECM, not an error.
    pub fn open_ecm(&self, bytes: &[u8]) -> Result<Vec<(PeriodIndex, [u8; 16])>> {
        // Try every slot key we hold — a handful of CMACs, same as a real card's
        // key-search loop.  A section is opened by whichever slot matches its
        // key epoch; during a probe transition both `cur` and `next` are live.
        let mut last_err = None;
        for (band, slots, _) in &self.state.band_keys {
            for key in slots.all() {
                match Ecm::decode(bytes, key) {
                    Ok(ecm) => {
                        debug_assert_eq!(ecm.band, *band);
                        if !self.state.grants(ecm.band) {
                            return Ok(Vec::new());
                        }
                        let mut plain = ecm.payload.clone();
                        ctr_xor(key, &ecm.nonce(), &mut plain);
                        let mut out = Vec::with_capacity(plain.len() / 16);
                        for (i, chunk) in plain.as_chunks::<16>().0.iter().enumerate() {
                            let mut cw = [0u8; 16];
                            cw.copy_from_slice(chunk);
                            out.push((PeriodIndex(ecm.first_period.0 + i as u64), cw));
                        }
                        return Ok(out);
                    }
                    Err(e) => last_err = Some(e),
                }
            }
        }
        match last_err {
            Some(Error::AuthFailed) | None => Ok(Vec::new()),
            Some(e) => Err(e),
        }
    }

    /// The return-channel ack for an epoch.  Cards that share what they decrypt
    /// still produce this, and it is what makes per-card attribution possible.
    pub fn ack(&self, epoch: u32, master: &MasterSecret) -> [u8; 16] {
        master.ack_tag(self.id, epoch)
    }

    pub fn trace_token(&self, epoch: u32, master: &MasterSecret) -> [u8; 16] {
        master.trace_token(self.id, epoch)
    }

    pub fn key_fingerprint(&self) -> [u8; 32] {
        tstv_core::crypto::sha256(&self.key)
    }
}

/// The EMM carries the program implicitly via its band mask domain, but band
/// keys are per-program in `MasterSecret`.  This stack models one program per
/// headend instance; multi-program plants would carry the program id in the EMM
/// (the field exists in the ECM and is free to add to the EMM in a v2 format).
fn program_of(_emm: &Emm) -> tstv_core::ids::ProgramId {
    tstv_core::ids::ProgramId(1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tstv_core::ids::ProgramId;

    fn master() -> MasterSecret {
        MasterSecret::derive_for_test(b"card-test")
    }

    fn emm(card: u32, epoch: u32, band: u16, flags: u8, mask: u64, m: &MasterSecret) -> Vec<u8> {
        Emm {
            card: CardId(card),
            epoch,
            band: GroupId(band),
            probe_id: 0,
            key_epoch: epoch,
            flags,
            band_mask: mask,
            trace_token: [0; 16],
        }
        .encode(&m.card_key(CardId(card)))
    }

    #[test]
    fn card_rejects_emm_for_other_card() {
        let m = master();
        let mut a = Card::new(CardId(1), &m);
        let mut b = Card::new(CardId(2), &m);
        let bytes = emm(1, 1, 0, 0x01, 0xFFFF, &m);
        assert!(!b.accept_emm(&bytes, &m).unwrap());
        assert!(a.accept_emm(&bytes, &m).unwrap());
        assert!(a.state.entitled);
    }

    #[test]
    fn card_ignores_stale_epoch() {
        let m = master();
        let mut c = Card::new(CardId(7), &m);
        assert!(c.accept_emm(&emm(7, 5, 0, 0x01, 0xFFFF, &m), &m).unwrap());
        assert!(!c.accept_emm(&emm(7, 4, 0, 0x01, 0xFFFF, &m), &m).unwrap());
        assert_eq!(c.state.epoch, 5);
    }

    #[test]
    fn revocation_wipes_keys_and_blocks_ecm() {
        let m = master();
        let mut c = Card::new(CardId(9), &m);
        c.accept_emm(&emm(9, 10, 0, 0x01, 0x0001, &m), &m).unwrap();
        assert!(c.state.grants(GroupId(0)));
        assert!(!c.state.grants(GroupId(1)));

        let ecm = build_ecm(
            &m,
            GroupId(0),
            10,
            100,
            &[[1; 16], [2; 16], [3; 16], [4; 16]],
        );
        assert_eq!(c.open_ecm(&ecm).unwrap().len(), 4);

        c.accept_emm(&emm(9, 11, 0, 0x01 | 0x02, 0x0001, &m), &m)
            .unwrap();
        assert!(c.state.revoked);
        assert!(c.state.band_keys.is_empty());
        assert!(c.open_ecm(&ecm).unwrap().is_empty());
    }

    #[test]
    fn card_without_band_key_cannot_open_ecm() {
        let m = master();
        let c = Card::new(CardId(3), &m);
        let ecm = build_ecm(&m, GroupId(2), 1, 50, &[[9; 16], [9; 16]]);
        assert!(c.open_ecm(&ecm).unwrap().is_empty());
    }

    #[test]
    fn ecm_opens_to_expected_cw_values() {
        let m = master();
        let mut c = Card::new(CardId(4), &m);
        c.accept_emm(&emm(4, 0, 1, 0x01, 0b10, &m), &m).unwrap();
        let ecm = build_ecm(
            &m,
            GroupId(1),
            0,
            200,
            &[[0xAA; 16], [0xAA; 16], [0xAA; 16]],
        );
        let got = c.open_ecm(&ecm).unwrap();
        assert_eq!(got.len(), 3);
        for (i, (period, cw)) in got.iter().enumerate() {
            assert_eq!(*period, PeriodIndex(200 + i as u64));
            assert_eq!(*cw, m.cw(ProgramId(1), *period));
        }
    }

    #[test]
    fn key_epoch_drives_band_key_not_service_epoch() {
        // A probe bumps key_epoch ahead of the service epoch; the card must
        // derive band keys from key_epoch or it cannot open post-probe ECMs.
        let m = master();
        let mut c = Card::new(CardId(11), &m);
        let mut e = Emm {
            card: CardId(11),
            epoch: 0, // service epoch
            band: GroupId(2),
            probe_id: 9,
            key_epoch: 100, // probe-derived key epoch
            flags: 0x01,
            band_mask: 0b100,
            trace_token: [0; 16],
        }
        .encode(&m.card_key(CardId(11)));
        assert!(c.accept_emm(&e, &m).unwrap());
        e.clear();
        // ECM encrypted under the key_epoch key opens; under the service-epoch
        // key it must not.
        let good = build_ecm(&m, GroupId(2), 100, 10, &[[7; 16], [7; 16]]);
        let bad = build_ecm(&m, GroupId(2), 0, 10, &[[7; 16], [7; 16]]);
        assert_eq!(c.open_ecm(&good).unwrap().len(), 2);
        assert!(c.open_ecm(&bad).unwrap().is_empty());
    }

    fn build_ecm(
        m: &MasterSecret,
        band: GroupId,
        key_epoch: u32,
        first: u64,
        cws: &[[u8; 16]],
    ) -> Vec<u8> {
        let mut ecm = Ecm {
            program: ProgramId(1),
            band,
            epoch: key_epoch,
            first_period: PeriodIndex(first),
            payload: Vec::new(),
        };
        // Payload is always the plant's real CWs for those periods — the test
        // helpers below pass placeholder values only to choose the count.
        let mut payload = Vec::new();
        for i in 0..cws.len() as u64 {
            payload.extend_from_slice(&m.cw(ProgramId(1), PeriodIndex(first + i)));
        }
        let key = m.band_key(ProgramId(1), band, key_epoch);
        ctr_xor(&key, &ecm.nonce(), &mut payload);
        ecm.payload = payload;
        ecm.encode(&key).unwrap()
    }
}
