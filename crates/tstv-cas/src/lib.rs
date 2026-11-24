//! Conditional-access system: headend, smart card and set-top box models.
//!
//! See `docs/DESIGN.md` for the threat model this code implements.  The short
//! version: control words are network-common by physics, so every
//! anti-sharing measure here works on *delivery* (bands, per-card EMMs,
//! timing) and none of it touches the CW value a legitimate viewer relies on.

pub mod bandwidth;
pub mod card;
pub mod headend;
pub mod params;
pub mod stb;

pub use bandwidth::{BandwidthBudget, BandwidthReport};
pub use card::{Card, CardState};
pub use headend::{Headend, ProbeState};
pub use params::Params;
pub use stb::{Stb, StbOutcome, ViewingStats};
