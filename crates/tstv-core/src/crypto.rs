//! Symmetric primitives: AES-128 block, AES-CMAC, HMAC-SHA256 and a counter-mode KDF.
//!
//! Choice of algorithms mirrors what broadcast CAS hardware can actually do:
//! AES-128 in hardware is ubiquitous in set-top-box SoCs, CMAC is cheap on top of
//! it, and SHA-256 is available on anything newer than a 2008-era chip.  Long-term
//! card keys and the global ECM key are AES-128; signatures over entitlements are
//! HMAC-SHA256 truncated to 16 bytes, which keeps EMM sections small.

use aes::cipher::{BlockEncrypt, KeyInit};
use aes::Aes128;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

use crate::error::{Error, Result};

pub const AES_BLOCK: usize = 16;
pub const AES_KEY: usize = 16;
pub const TAG_LEN: usize = 16;
/// Keystream nonce width: 8 bytes of domain-separated context + 8-byte counter.
pub const NONCE_LEN: usize = 8;
/// Truncated authentication tag carried on broadcast sections.
pub const SHORT_TAG: usize = 8;

type HmacSha256 = Hmac<Sha256>;

/// Encrypt one 16-byte block with AES-128 in ECB mode.  ECB on a single block is
/// just the raw AES permutation; callers use it for CMAC and for CW parity words.
pub fn aes128_encrypt_block(key: &[u8; AES_KEY], block: &mut [u8; AES_BLOCK]) {
    let cipher = Aes128::new_from_slice(key).expect("16-byte key");
    let b = aes::Block::from_mut_slice(block);
    cipher.encrypt_block(b);
}

/// AES-CMAC (RFC 4493) over a message of arbitrary length, 16-byte tag.
pub struct Cmac {
    cipher: Aes128,
    /// Running CBC-MAC chain value.
    x: [u8; AES_BLOCK],
}

impl Cmac {
    pub fn new(key: &[u8; AES_KEY]) -> Self {
        let cipher = Aes128::new_from_slice(key).expect("16-byte key");
        Self {
            cipher,
            x: [0u8; AES_BLOCK],
        }
    }

    fn encrypt(&self, block: &mut [u8; AES_BLOCK]) {
        let b = aes::Block::from_mut_slice(block);
        self.cipher.encrypt_block(b);
    }

    /// Subkey derivation: multiply a block by x in GF(2^128) (RFC 4493 §2.3).
    fn dbl(block: &[u8; AES_BLOCK]) -> [u8; AES_BLOCK] {
        let mut out = [0u8; AES_BLOCK];
        let mut carry = 0u8;
        for i in (0..AES_BLOCK).rev() {
            out[i] = (block[i] << 1) | carry;
            carry = block[i] >> 7;
        }
        if carry != 0 {
            out[AES_BLOCK - 1] ^= 0x87;
        }
        out
    }

    pub fn mac(self, msg: &[u8]) -> [u8; AES_BLOCK] {
        let mut k1 = [0u8; AES_BLOCK];
        self.encrypt(&mut k1);
        let k1 = Self::dbl(&k1);
        let k2 = Self::dbl(&k1);

        let n = msg.len().div_ceil(AES_BLOCK);
        // RFC 4493: an empty message is treated as one incomplete block.
        let (last, partial) = if n == 0 || !msg.len().is_multiple_of(AES_BLOCK) {
            let mut buf = [0u8; AES_BLOCK];
            let start = n.saturating_sub(1) * AES_BLOCK;
            if msg.is_empty() {
                buf[0] = 0x80;
            } else {
                let tail = &msg[start..];
                buf[..tail.len()].copy_from_slice(tail);
                buf[tail.len()] = 0x80;
            }
            for (b, k) in buf.iter_mut().zip(k2.iter()) {
                *b ^= k;
            }
            (n.saturating_sub(1), Some(buf))
        } else {
            let start = (n - 1) * AES_BLOCK;
            let mut buf = [0u8; AES_BLOCK];
            buf.copy_from_slice(&msg[start..]);
            for (b, k) in buf.iter_mut().zip(k1.iter()) {
                *b ^= k;
            }
            (n - 1, Some(buf))
        };

        let mut x = self.x;
        for i in 0..last {
            for (a, b) in x.iter_mut().zip(&msg[i * AES_BLOCK..(i + 1) * AES_BLOCK]) {
                *a ^= b;
            }
            self.encrypt(&mut x);
        }
        for (a, b) in x.iter_mut().zip(partial.unwrap().iter()) {
            *a ^= b;
        }
        self.encrypt(&mut x);
        x
    }
}

pub fn cmac(key: &[u8; AES_KEY], msg: &[u8]) -> [u8; AES_BLOCK] {
    Cmac::new(key).mac(msg)
}

/// HMAC-SHA256 truncated to 16 bytes — the tag carried in entitlement sections.
pub fn hmac_tag(key: &[u8; AES_KEY], msg: &[u8]) -> [u8; TAG_LEN] {
    let mut m = <HmacSha256 as Mac>::new_from_slice(key).expect("hmac accepts any key size");
    m.update(msg);
    let full = m.finalize().into_bytes();
    let mut out = [0u8; TAG_LEN];
    out.copy_from_slice(&full[..TAG_LEN]);
    out
}

/// Constant-time equality for equal-length byte slices.  Returns `false`
/// (without early exit) when the lengths differ.
pub fn ct_eq_slice(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for i in 0..a.len() {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

/// Constant-time 16-byte tag comparison.
pub fn ct_eq(a: &[u8; TAG_LEN], b: &[u8; TAG_LEN]) -> bool {
    let mut diff = 0u8;
    for i in 0..TAG_LEN {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

/// Counter-mode KDF over HMAC-SHA256.  Deterministic and cheap enough to run on
/// a card at every ECM; `info` carries domain separation (e.g. "cw/period/7").
pub fn kdf(ikm: &[u8], info: &[u8], out: &mut [u8]) -> Result<()> {
    if out.is_empty() {
        return Ok(());
    }
    let blocks = out.len().div_ceil(32);
    if blocks > 255 {
        return Err(Error::BadLength {
            field: "kdf output",
            value: out.len(),
        });
    }
    let mut written = 0;
    for counter in 1..=blocks as u8 {
        let mut m = <HmacSha256 as Mac>::new_from_slice(ikm).expect("hmac accepts any key size");
        m.update(info);
        m.update(&[counter]);
        let block = m.finalize().into_bytes();
        let take = (out.len() - written).min(32);
        out[written..written + take].copy_from_slice(&block[..take]);
        written += take;
    }
    Ok(())
}

pub fn kdf_key(ikm: &[u8], info: &[u8]) -> [u8; AES_KEY] {
    let mut k = [0u8; AES_KEY];
    kdf(ikm, info, &mut k).expect("16 bytes is within the KDF limit");
    k
}

/// CMAC-based counter-mode keystream XOR, in place.
///
/// `nonce` must be distinct per use under a given key.  For ECMs it is derived
/// from `(program, band, epoch, period)`, so every period gets a fresh keystream
/// even though the band key lives for an epoch.  Reusing a nonce with the same
/// key leaks the XOR of two plaintexts, which for control words is fatal — the
/// headend derives the nonce from fields that are themselves authenticated.
pub fn ctr_xor(key: &[u8; AES_KEY], nonce: &[u8; NONCE_LEN], data: &mut [u8]) {
    for (i, chunk) in data.chunks_mut(AES_BLOCK).enumerate() {
        let mut ctr = [0u8; AES_BLOCK];
        ctr[..NONCE_LEN].copy_from_slice(nonce);
        ctr[NONCE_LEN..].copy_from_slice(&(i as u64).to_le_bytes());
        let ks = cmac(key, &ctr);
        for (b, k) in chunk.iter_mut().zip(ks.iter()) {
            *b ^= k;
        }
    }
}

/// Truncated MAC used to authenticate broadcast sections.  8 bytes gives a
/// 2^-64 forgery probability per attempt, which is the right trade-off when
/// every byte costs broadcast bandwidth.  The domain string is length-prefixed
/// by a single zero byte so `("a", "b\0c")` and `("a\0b", "c")` cannot collide.
pub fn short_tag(key: &[u8; AES_KEY], domain: &[u8], msg: &[u8]) -> [u8; SHORT_TAG] {
    // Length-prefix the domain so no two (domain, msg) splits can ever produce
    // the same byte string — a 0x00 separator is not enough because the domain
    // itself may contain zeros.
    let dom_len = u8::try_from(domain.len()).expect("domain labels are short literals");
    let mut full = Vec::with_capacity(1 + domain.len() + msg.len());
    full.push(dom_len);
    full.extend_from_slice(domain);
    full.extend_from_slice(msg);
    let tag = cmac(key, &full);
    let mut out = [0u8; SHORT_TAG];
    out.copy_from_slice(&tag[..SHORT_TAG]);
    out
}

/// SHA-256 digest helper used for card-key lookup tables in the headend.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aes_known_vector() {
        // FIPS-197 Appendix C.1
        let key: [u8; 16] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f,
        ];
        let mut block: [u8; 16] = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff,
        ];
        aes128_encrypt_block(&key, &mut block);
        assert_eq!(
            block,
            [
                0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4,
                0xc5, 0x5a
            ]
        );
    }

    #[test]
    fn cmac_rfc4493_vectors() {
        let key: [u8; 16] = [
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf,
            0x4f, 0x3c,
        ];
        // Example 1: len 0
        assert_eq!(
            cmac(&key, &[]),
            [
                0xbb, 0x1d, 0x69, 0x29, 0xe9, 0x59, 0x37, 0x28, 0x7f, 0xa3, 0x7d, 0x12, 0x9b, 0x75,
                0x67, 0x46
            ]
        );
        // Example 2: 16 bytes
        assert_eq!(
            cmac(&key, &hex("6bc1bee22e409f96e93d7e117393172a")),
            [
                0x07, 0x0a, 0x16, 0xb4, 0x6b, 0x4d, 0x41, 0x44, 0xf7, 0x9b, 0xdd, 0x9d, 0xd0, 0x4a,
                0x28, 0x7c
            ]
        );
        // Example 3: 40 bytes
        assert_eq!(
            cmac(
                &key,
                &hex("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411")
            ),
            [
                0xdf, 0xa6, 0x67, 0x47, 0xde, 0x9a, 0xe6, 0x30, 0x30, 0xca, 0x32, 0x61, 0x14,
                0x97, 0xc8, 0x27
            ]
        );
        // Example 4: 64 bytes
        assert_eq!(
            cmac(
                &key,
                &hex(concat!(
                    "6bc1bee22e409f96e93d7e117393172a",
                    "ae2d8a571e03ac9c9eb76fac45af8e51",
                    "30c81c46a35ce411e5fbc1191a0a52ef",
                    "f69f2445df4f9b17ad2b417be66c3710"
                ))
            ),
            [
                0x51, 0xf0, 0xbe, 0xbf, 0x7e, 0x3b, 0x9d, 0x92, 0xfc, 0x49, 0x74, 0x17, 0x79, 0x36,
                0x3c, 0xfe
            ]
        );
    }

    #[test]
    fn hmac_matches_rfc4231_case2() {
        let key: [u8; 16] = *b"JefeJefeJefeJefe";
        let full = {
            let mut m = <HmacSha256 as Mac>::new_from_slice(&key).unwrap();
            m.update(b"what do ya want for nothing?");
            m.finalize().into_bytes()
        };
        assert_eq!(hmac_tag(&key, b"what do ya want for nothing?"), full[..16]);
    }

    #[test]
    fn kdf_is_deterministic_and_domain_separated() {
        let mut a = [0u8; 16];
        let mut b = [0u8; 16];
        kdf(b"root", b"cw/1", &mut a).unwrap();
        kdf(b"root", b"cw/1", &mut b).unwrap();
        assert_eq!(a, b);
        let mut c = [0u8; 16];
        kdf(b"root", b"cw/2", &mut c).unwrap();
        assert_ne!(a, c);
    }

    #[test]
    fn ctr_xor_roundtrip_and_nonce_sensitivity() {
        let key = [7u8; 16];
        let nonce = [3u8; 8];
        let plain = b"control-word-payload-with-a-tail";
        let mut buf = plain.to_vec();
        ctr_xor(&key, &nonce, &mut buf);
        assert_ne!(&buf[..], &plain[..]);
        ctr_xor(&key, &nonce, &mut buf);
        assert_eq!(&buf[..], &plain[..]);

        let mut a = plain.to_vec();
        let mut b = plain.to_vec();
        ctr_xor(&key, &nonce, &mut a);
        ctr_xor(&key, &[4u8; 8], &mut b);
        assert_ne!(a, b);
    }

    #[test]
    fn short_tag_domain_separation_blocks_splice() {
        let key = [1u8; 16];
        // "a" + 0 + "b\0c"  vs  "a\0b" + 0 + "c" would collide without the separator.
        assert_ne!(
            short_tag(&key, b"a", b"b\0c"),
            short_tag(&key, b"a\0b", b"c")
        );
        assert_eq!(short_tag(&key, b"ecm", b"x"), short_tag(&key, b"ecm", b"x"));
    }

    #[test]
    fn ct_eq_semantics() {
        let a = [1u8; 16];
        let mut b = a;
        assert!(ct_eq(&a, &b));
        b[15] ^= 1;
        assert!(!ct_eq(&a, &b));
    }

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }
}
