//! Wire formats for ECM and EMM sections.
//!
//! Two rules, both enforced by the decoders:
//!
//! 1. **No implicit trailing data.** A decoder consumes exactly the bytes it was
//!    told the section contains; leftover bytes are a length error, not silently
//!    ignored.  Broadcast corruption is the normal case on these links, and a
//!    decoder that ignores junk is how a bogus section becomes a bogus CW.
//! 2. **Authenticate before you act.** The tag covers every byte before it,
//!    including lengths and markers, so a spliced section cannot pass.
//!
//! ## ECM layout
//!
//! ```text
//!  off  len  field
//!   0    1   version = 1
//!   1    1   kind    = 0xEC
//!   2    2   program_id          (u16 LE)
//!   4    2   band_id             (u16 LE)
//!   6    4   epoch               (u32 LE)
//!  10    8   first_period        (u64 LE)
//!  18    1   period_count        (1..=MAX_PERIODS)
//!  19  16*n ciphertext: n * 16-byte CWs, CTR-XOR'd under band key
//!   -    8   tag = short_tag("ecm", everything above)
//! ```
//!
//! The nonce is `(program, band, epoch)` truncated to 8 bytes — every field is
//! itself authenticated, so a receiver cannot be tricked into a nonce collision.
//!
//! ## EMM layout
//!
//! ```text
//!   0    1   version = 1
//!   1    1   kind    = 0xEE
//!   2    4   card_id             (u32 LE)
//!   6    4   epoch               (u32 LE)
//!  10    2   band_id             (u16 LE)
//!  12    4   probe_id            (u32 LE)     0 = ordinary grant
//!  16    4   key_epoch           (u32 LE)     epoch to derive band keys from
//!  20    1   flags               bit0 entitl, bit1 revoke
//!  21    8   band_mask           (u64 LE)     bit i = entitlement to band i
//!  29   16   trace_token         (16 B)
//!  45    8   mac = short_tag(card key, "emm", bytes 0..45)
//!  53    4   crc32 over bytes 0..53
//!  57    4   reserved (zero)
//! ```
//!
//! EMM MAC is 8 bytes from the *card key*, so only the target card can validate
//! it.  The CRC catches link corruption before the expensive MAC check, and the
//! reserved word keeps the section a comfortable 4-byte multiple for the old
//! firmware's section parser.

use crate::crc32::crc32;
use crate::crypto::{ct_eq_slice, short_tag, AES_KEY, SHORT_TAG};
use crate::error::{Error, Result};
use crate::ids::{CardId, GroupId, PeriodIndex, ProgramId};

pub const ECM_VERSION: u8 = 1;
pub const ECM_KIND: u8 = 0xEC;
pub const EMM_KIND: u8 = 0xEE;

/// Hard ceiling on periods per ECM.  A receiver that is asked to buffer more
/// than this is being fed a hostile section; the old firmware also caps its CW
/// ring buffer here, so going over would silently drop the tail.
pub const MAX_PERIODS: usize = 8;

pub const ECM_HEADER_LEN: usize = 19;

/// Length of the ECM section MAC.
pub const ECM_TAG_LEN: usize = SHORT_TAG;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ecm {
    pub program: ProgramId,
    pub band: GroupId,
    pub epoch: u32,
    pub first_period: PeriodIndex,
    /// Ciphertext: `period_count * 16` bytes.
    pub payload: Vec<u8>,
}

impl Ecm {
    pub fn period_count(&self) -> usize {
        self.payload.len() / 16
    }

    pub fn encode_body(&self) -> Result<Vec<u8>> {
        let n = self.payload.len() / 16;
        if !self.payload.len().is_multiple_of(16) || n == 0 || n > MAX_PERIODS {
            return Err(Error::BadLength {
                field: "ecm periods",
                value: n,
            });
        }
        let mut out = Vec::with_capacity(ECM_HEADER_LEN + self.payload.len() + SHORT_TAG);
        out.push(ECM_VERSION);
        out.push(ECM_KIND);
        out.extend_from_slice(&self.program.0.to_le_bytes());
        out.extend_from_slice(&self.band.0.to_le_bytes());
        out.extend_from_slice(&self.epoch.to_le_bytes());
        out.extend_from_slice(&self.first_period.0.to_le_bytes());
        out.push(n as u8);
        out.extend_from_slice(&self.payload);
        Ok(out)
    }

    /// Serialise with the section MAC appended.
    pub fn encode(&self, band_key: &[u8; AES_KEY]) -> Result<Vec<u8>> {
        let body = self.encode_body()?;
        let tag = short_tag(band_key, b"ecm", &body);
        let mut out = body;
        out.extend_from_slice(&tag);
        Ok(out)
    }

    /// Parse and authenticate.
    pub fn decode(bytes: &[u8], band_key: &[u8; AES_KEY]) -> Result<Ecm> {
        if bytes.len() < ECM_HEADER_LEN + 16 + SHORT_TAG {
            return Err(Error::Truncated {
                need: ECM_HEADER_LEN + 16 + SHORT_TAG,
                have: bytes.len(),
            });
        }
        let body_len = bytes.len() - SHORT_TAG;
        let (body, tag) = bytes.split_at(body_len);
        let expect = short_tag(band_key, b"ecm", body);
        if !ct_eq_slice(&expect, tag) {
            return Err(Error::AuthFailed);
        }
        if body[0] != ECM_VERSION {
            return Err(Error::BadMarker {
                field: "ecm version",
                value: body[0],
            });
        }
        if body[1] != ECM_KIND {
            return Err(Error::BadMarker {
                field: "ecm kind",
                value: body[1],
            });
        }
        let program = ProgramId(u16::from_le_bytes([body[2], body[3]]));
        let band = GroupId(u16::from_le_bytes([body[4], body[5]]));
        let epoch = u32::from_le_bytes([body[6], body[7], body[8], body[9]]);
        let first_period = PeriodIndex(u64::from_le_bytes(
            body[10..18].try_into().expect("8 bytes"),
        ));
        let n = body[18] as usize;
        if n == 0 || n > MAX_PERIODS {
            return Err(Error::BadLength {
                field: "ecm periods",
                value: n,
            });
        }
        let payload_len = n * 16;
        let payload_start = ECM_HEADER_LEN;
        let payload_end = payload_start + payload_len;
        if body.len() != payload_end {
            return Err(Error::BadLength {
                field: "ecm body",
                value: body.len(),
            });
        }
        Ok(Ecm {
            program,
            band,
            epoch,
            first_period,
            payload: body[payload_start..payload_end].to_vec(),
        })
    }

    /// Nonce bound to this section's identity fields.
    pub fn nonce(&self) -> [u8; 8] {
        let mut n = [0u8; 8];
        n[..4].copy_from_slice(&self.epoch.to_le_bytes());
        n[4..6].copy_from_slice(&self.program.0.to_le_bytes());
        n[6..8].copy_from_slice(&self.band.0.to_le_bytes());
        n
    }
}

/// EMM flags.
pub const EMM_FLAG_ENTITLED: u8 = 0x01;
pub const EMM_FLAG_REVOKE: u8 = 0x02;

pub const EMM_BODY_LEN: usize = 45;
pub const EMM_TRAILER_LEN: usize = 16; // 8-byte MAC + 4-byte CRC + 4 reserved

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Emm {
    pub card: CardId,
    /// Service epoch: the authorization period this grant belongs to.  Drives
    /// the return-channel ack and monotonicity, independent of probe keys.
    pub epoch: u32,
    pub band: GroupId,
    /// Which probe (if any) this grant is part of; 0 for ordinary grants.  Part
    /// of the per-card fingerprint that identifies a sharing card.
    pub probe_id: u32,
    /// Epoch the card must use to derive its band keys.  Equals the service
    /// epoch until a probe inserts a new key segment, after which it moves
    /// ahead on probed bands only.
    pub key_epoch: u32,
    pub flags: u8,
    /// Bit `i` = entitlement to band `i`.  64 bands covers the default plant;
    /// the wire field is fixed-width so this needs no length prefix.
    pub band_mask: u64,
    pub trace_token: [u8; 16],
}

impl Emm {
    pub fn entitled(&self) -> bool {
        self.flags & EMM_FLAG_ENTITLED != 0
    }
    pub fn revoked(&self) -> bool {
        self.flags & EMM_FLAG_REVOKE != 0
    }
    pub fn grants_band(&self, b: GroupId) -> bool {
        b.0 < 64 && self.band_mask & (1u64 << b.0) != 0
    }

    fn body(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(EMM_BODY_LEN);
        out.push(ECM_VERSION);
        out.push(EMM_KIND);
        out.extend_from_slice(&self.card.0.to_le_bytes());
        out.extend_from_slice(&self.epoch.to_le_bytes());
        out.extend_from_slice(&self.band.0.to_le_bytes());
        out.extend_from_slice(&self.probe_id.to_le_bytes());
        out.extend_from_slice(&self.key_epoch.to_le_bytes());
        out.push(self.flags);
        out.extend_from_slice(&self.band_mask.to_le_bytes());
        out.extend_from_slice(&self.trace_token);
        debug_assert_eq!(out.len(), EMM_BODY_LEN);
        out
    }

    pub fn encode(&self, card_key: &[u8; AES_KEY]) -> Vec<u8> {
        let mut out = self.body();
        let mac = short_tag(card_key, b"emm", &out);
        out.extend_from_slice(&mac);
        let crc = crc32(&out);
        out.extend_from_slice(&crc.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes()); // reserved
        out
    }

    pub fn decode(bytes: &[u8], card_key: &[u8; AES_KEY]) -> Result<Emm> {
        if bytes.len() != EMM_BODY_LEN + EMM_TRAILER_LEN {
            return Err(Error::BadLength {
                field: "emm section",
                value: bytes.len(),
            });
        }
        let (signed, trailer) = bytes.split_at(EMM_BODY_LEN);
        let (mac, rest) = trailer.split_at(SHORT_TAG);
        let (crc_bytes, _reserved) = rest.split_at(4);
        let got_crc = u32::from_le_bytes(crc_bytes.try_into().expect("4 bytes"));
        let expect_crc = crc32(&bytes[..EMM_BODY_LEN + SHORT_TAG]);
        if got_crc != expect_crc {
            return Err(Error::BadCrc {
                expect: expect_crc,
                got: got_crc,
            });
        }
        let expect = short_tag(card_key, b"emm", signed);
        if !ct_eq_slice(&expect, mac) {
            return Err(Error::AuthFailed);
        }
        if signed[0] != ECM_VERSION {
            return Err(Error::BadMarker {
                field: "emm version",
                value: signed[0],
            });
        }
        if signed[1] != EMM_KIND {
            return Err(Error::BadMarker {
                field: "emm kind",
                value: signed[1],
            });
        }
        let card = CardId(u32::from_le_bytes(
            signed[2..6].try_into().expect("4 bytes"),
        ));
        let epoch = u32::from_le_bytes(signed[6..10].try_into().expect("4 bytes"));
        let band = GroupId(u16::from_le_bytes(
            signed[10..12].try_into().expect("2 bytes"),
        ));
        let probe_id = u32::from_le_bytes(signed[12..16].try_into().expect("4 bytes"));
        let key_epoch = u32::from_le_bytes(signed[16..20].try_into().expect("4 bytes"));
        let flags = signed[20];
        let band_mask = u64::from_le_bytes(signed[21..29].try_into().expect("8 bytes"));
        let mut trace_token = [0u8; 16];
        trace_token.copy_from_slice(&signed[29..45]);
        Ok(Emm {
            card,
            epoch,
            band,
            probe_id,
            key_epoch,
            flags,
            band_mask,
            trace_token,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_ecm() -> Ecm {
        Ecm {
            program: ProgramId(3),
            band: GroupId(5),
            epoch: 7,
            first_period: PeriodIndex(1000),
            payload: (0..48u8).collect(),
        }
    }

    fn sample_emm() -> Emm {
        Emm {
            card: CardId(1234),
            epoch: 7,
            band: GroupId(5),
            probe_id: 0,
            key_epoch: 7,
            flags: EMM_FLAG_ENTITLED,
            band_mask: 0b101,
            trace_token: [9u8; 16],
        }
    }

    #[test]
    fn ecm_roundtrip() {
        let key = [1u8; 16];
        let ecm = sample_ecm();
        let bytes = ecm.encode(&key).unwrap();
        let back = Ecm::decode(&bytes, &key).unwrap();
        assert_eq!(back, ecm);
        assert_eq!(back.period_count(), 3);
    }

    #[test]
    fn ecm_rejects_tamper_and_wrong_key() {
        let key = [1u8; 16];
        let mut bytes = sample_ecm().encode(&key).unwrap();
        let idx = ECM_HEADER_LEN + 2;
        bytes[idx] ^= 1;
        assert_eq!(Ecm::decode(&bytes, &key), Err(Error::AuthFailed));
        let bytes = sample_ecm().encode(&key).unwrap();
        assert_eq!(Ecm::decode(&bytes, &[2u8; 16]), Err(Error::AuthFailed));
    }

    #[test]
    fn ecm_rejects_trailing_junk_and_absurd_counts() {
        let key = [1u8; 16];
        let mut ecm = sample_ecm();
        ecm.payload.push(0);
        assert!(ecm.encode(&key).is_err());

        let mut bytes = sample_ecm().encode(&key).unwrap();
        bytes.push(0xAA);
        assert!(Ecm::decode(&bytes, &key).is_err());
    }

    #[test]
    fn ecm_nonce_distinguishes_sections() {
        let mut a = sample_ecm();
        let mut b = sample_ecm();
        assert_eq!(a.nonce(), b.nonce());
        b.epoch += 1;
        assert_ne!(a.nonce(), b.nonce());
        a.program = ProgramId(4);
        assert_ne!(a.nonce(), sample_ecm().nonce());
    }

    #[test]
    fn emm_roundtrip_and_auth() {
        let key = [3u8; 16];
        let emm = sample_emm();
        let bytes = emm.encode(&key);
        let back = Emm::decode(&bytes, &key).unwrap();
        assert_eq!(back, emm);
        assert!(back.entitled());
        assert!(!back.revoked());
        assert!(back.grants_band(GroupId(0)));
        assert!(back.grants_band(GroupId(2)));
        assert!(!back.grants_band(GroupId(1)));

        assert_eq!(Emm::decode(&bytes, &[4u8; 16]), Err(Error::AuthFailed));
    }

    #[test]
    fn emm_crc_catches_corruption_before_mac() {
        let key = [3u8; 16];
        let mut bytes = sample_emm().encode(&key);
        bytes[EMM_BODY_LEN + 2] ^= 0xFF;
        assert!(matches!(
            Emm::decode(&bytes, &key),
            Err(Error::BadCrc { .. })
        ));
    }

    #[test]
    fn emm_rejects_wrong_length() {
        let key = [3u8; 16];
        let bytes = sample_emm().encode(&key);
        assert!(Emm::decode(&bytes[..bytes.len() - 1], &key).is_err());
    }
}
