//! Simulator library: plant, pirate relay, tracing and reporting.
//!
//! The `tstvd` binary is a thin CLI over this crate; tests live here so they can
//! drive the full plant without shelling out.

pub mod pirate;
pub mod report;
pub mod sim;

pub use report::{RectifyReport, SimReport, TraceReport};
pub use sim::{SimConfig, Simulator};
