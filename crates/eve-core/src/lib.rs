//! eve-core — the safety engine.
//!
//! Every deletion eve performs, from any frontend and at any privilege level,
//! passes through the same five-stage funnel in [`funnel`]:
//!
//! 1. [`path`]      syntactic validation + the ancestor-symlink guard
//! 2. [`policy`]    protection lists and the user whitelist
//! 3. [`liveness`]  refuse caches whose owning process is still alive
//! 4. [`executor`]  Trash-by-default, dry-run aware
//! 5. [`journal`]   append-only record of what actually happened
//!
//! The privileged peer ([`privilege`]) re-runs the entire funnel as root. It
//! does not trust the parent's verdict, only its request — so a compromised or
//! merely buggy parent cannot talk root into deleting something policy forbids.

pub mod error;
pub mod executor;
pub mod funnel;
pub mod journal;
pub mod liveness;
pub mod path;
pub mod policy;
pub mod privilege;
pub mod risk;
pub mod size;

pub use error::{Denial, EveError, Result};
pub use executor::{Disposition, ExecOutcome, Executor};
pub use funnel::{Funnel, FunnelReport, Operation};
pub use journal::{Journal, JournalEntry};
pub use liveness::{Liveness, LivenessVerdict};
pub use path::PathValidator;
pub use policy::Policy;
pub use privilege::{Plan, PrivilegeBroker, SudoWorker};
pub use risk::RiskTier;
pub use size::{human_bytes, measure};
