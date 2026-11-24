//! Cryptographic and encoding primitives for the TSTV conditional-access research stack.
//!
//! Everything in this crate is *deterministic*: no OS entropy is read.  Tests and the
//! simulator must be bit-for-bit reproducible, so all randomness flows through
//! [`rng::SplitMix64`] and all keys are derived through [`prf::Prf`].

#![deny(unsafe_code)]

pub mod crc32;
pub mod crypto;
pub mod error;
pub mod ids;
pub mod prf;
pub mod rng;
pub mod time;
pub mod wire;

pub use error::{Error, Result};
pub use ids::{CardId, GroupId, PeriodIndex, ProgramId};
pub use time::{Millis, TimeWindow};
