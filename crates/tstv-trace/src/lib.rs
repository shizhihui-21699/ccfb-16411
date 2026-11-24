//! Tracing: find which card is feeding a pirate relay, and withstand small
//! coalitions.
//!
//! Two independent tools, used in sequence:
//!
//! * [`group_testing`] — binary-search the band the sharing card sits in
//!   (interference-free via delivery-timing fingerprints), then binary-search
//!   the cards inside that band (short, bounded ECM suppression).  Needs only a
//!   1-bit oracle ("did piracy stop?") and spends O(log N) probes.
//! * [`fingerprint`] — a q-ary collusion-secure-ish code so that when *several*
//!   cards feed one relay, decoding still names at least one of them.
//!
//! [`clone`] additionally catches a card physically cloned into two boxes, from
//! the return channel alone.  None of these touch a CW value; they work on
//! delivery channels, timing and per-card acks (see `docs/DESIGN.md` §3–§5).

pub mod clone;
pub mod fingerprint;
pub mod group_testing;

pub use clone::{AckReport, CloneDetector, CloneFinding};
pub use fingerprint::{FingerprintCode, TraceResult};
pub use group_testing::{GroupTester, ProbeOutcome};
