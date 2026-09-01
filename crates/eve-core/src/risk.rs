use serde::{Deserialize, Serialize};

/// How dangerous a category is, and therefore what it takes to run it.
///
/// The tier is a property of the *target*, not of the caller. That is the whole
/// point: `ios_backups` is `NeverAuto` because iPhone backups are user data
/// misfiled as cache, and no caller — however convenient — gets to opt out of
/// that by forgetting a flag.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RiskTier {
    /// Regenerable caches. No confirmation, safe unattended.
    Safe,
    /// Adjacent to user data (browser storage, Mail downloads). Explicit opt-in.
    Review,
    /// Requires root. Safe unattended once a privileged peer exists.
    Privileged,
    /// App removal, system assets. Typed confirmation.
    Destructive,
    /// Real user data misfiled as cache. Never runs unattended, ever.
    NeverAuto,
}

impl RiskTier {
    /// Whether an unattended (no human present) run may touch this tier.
    pub fn allowed_unattended(self) -> bool {
        matches!(self, RiskTier::Safe | RiskTier::Privileged)
    }

    /// Whether this tier is enabled without the user explicitly naming it.
    pub fn on_by_default(self) -> bool {
        matches!(self, RiskTier::Safe | RiskTier::Privileged)
    }

    /// Whether a setting the user stored on disk may stand in for a human at
    /// the keyboard, and let an unattended run reach this tier.
    ///
    /// `Review` only. Its worst outcome is losing something regenerable or
    /// already discarded; a stored, deliberate "always do this" is a fair
    /// substitute for confirming it each time. `Destructive` and `NeverAuto`
    /// lose real user data, and nothing recorded in a file gets to speak for
    /// the user there — which is what keeps iPhone backups structurally out of
    /// reach of the LaunchAgent no matter what any preference says.
    pub fn unlockable_by_consent(self) -> bool {
        matches!(self, RiskTier::Review)
    }

    /// Whether running this tier requires the user to type a confirmation word.
    pub fn needs_typed_confirmation(self) -> bool {
        matches!(self, RiskTier::Destructive | RiskTier::NeverAuto)
    }

    /// Whether "delete outright instead of moving to the Trash" may apply to
    /// this tier.
    ///
    /// The same doctrine as [`RiskTier::unlockable_by_consent`], drawn one
    /// tier tighter: permanent deletion is offered where the worst case is
    /// something regenerable. `Review` sits next to real user data — Mail
    /// downloads, browser storage — and keeps the recoverable delete however
    /// the preference is set, because "I wanted my caches gone in one pass"
    /// must never be able to mean "and my mail attachments with them".
    pub fn permanent_delete_applies(self) -> bool {
        matches!(self, RiskTier::Safe | RiskTier::Privileged)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            RiskTier::Safe => "safe",
            RiskTier::Review => "review",
            RiskTier::Privileged => "privileged",
            RiskTier::Destructive => "destructive",
            RiskTier::NeverAuto => "never-auto",
        }
    }
}

impl std::fmt::Display for RiskTier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Where a category's work must run.
///
/// `User` is the declarative form of a lesson that cost real debugging time:
/// Homebrew hard-refuses to run as root, and Docker as root addresses root's
/// own context rather than the user's Docker Desktop socket. Encoding it as
/// data means the scheduler routes those categories correctly on its own
/// instead of a human remembering to split the run into two passes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RunContext {
    /// Must run as the invoking user, never as root.
    User,
    /// Runs correctly in either context.
    Any,
}
