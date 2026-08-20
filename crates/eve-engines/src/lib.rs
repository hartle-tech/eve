//! eve's engines: the commands, each built on the same safety core.
//!
//! Every engine that deletes does so by producing [`eve_core::Operation`]
//! values and handing them to the funnel. None of them removes anything
//! directly, which is what keeps the safety guarantees in one place.

pub mod analyze;
pub mod clean;
pub mod installer;
pub mod optimize;
pub mod status;
pub mod uninstall;

pub use clean::{CategoryResult, CleanReport, Cleaner, Selection};
