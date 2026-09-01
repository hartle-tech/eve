use std::path::PathBuf;

use serde::{Deserialize, Serialize};

pub type Result<T> = std::result::Result<T, EveError>;

/// Why the funnel refused a path.
///
/// Every variant is a *refusal to act*, never a partial action. If a `Denial`
/// is returned nothing on disk was touched.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Denial {
    /// Empty path string.
    Empty,
    /// Relative path. Deletion targets are always absolute.
    NotAbsolute(PathBuf),
    /// `..` appeared as a whole path component.
    Traversal(PathBuf),
    /// Control characters (including newline) in the path.
    ControlCharacter(PathBuf),
    /// The path is a symlink whose target is protected.
    SymlinkToProtected { link: PathBuf, target: PathBuf },
    /// A symlink could not be read, so its target cannot be judged.
    UnreadableSymlink(PathBuf),
    /// An ancestor is a symlink and the canonicalized path lands somewhere protected.
    ResolvesIntoProtected { literal: PathBuf, resolved: PathBuf },
    /// Matched a protected-path rule.
    Protected { path: PathBuf, rule: String },
    /// Matched a user whitelist pattern.
    Whitelisted { path: PathBuf, pattern: String },
    /// The owning process of this cache is still running (or could not be ruled out).
    LiveOwner { path: PathBuf, detail: String },
    /// Inside a directory the user locked. The strongest refusal eve has:
    /// nothing lifts it — not an exemption, not a tier, not root.
    Locked { path: PathBuf, locked: PathBuf },
    /// Requires root and no privileged peer is available.
    NeedsPrivilege(PathBuf),
    /// macOS marks this as system-restricted or immutable.
    SystemRestricted(PathBuf),
    /// Refused because the request arrived from an unattended context.
    UnattendedRefused { path: PathBuf, tier: String },
    /// Kept out of the Trash emptying by an exclusion pattern.
    TrashExcluded { path: PathBuf, pattern: String },
    /// The directory could not be read, so its contents could not be judged.
    ///
    /// On macOS this is nearly always TCC: `~/.Trash` is one of the paths that
    /// needs Full Disk Access, and without it `read_dir` fails outright.
    /// Treating that as "the directory is empty" reports a permission problem
    /// as a successful no-op, which is the failure mode where the user never
    /// finds out why nothing was ever reclaimed.
    Unreadable { path: PathBuf, detail: String },
}

impl Denial {
    pub fn path(&self) -> &PathBuf {
        match self {
            Denial::Empty => {
                static EMPTY: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();
                EMPTY.get_or_init(PathBuf::new)
            }
            Denial::NotAbsolute(p)
            | Denial::Traversal(p)
            | Denial::ControlCharacter(p)
            | Denial::UnreadableSymlink(p)
            | Denial::SystemRestricted(p)
            | Denial::NeedsPrivilege(p) => p,
            Denial::SymlinkToProtected { link, .. } => link,
            Denial::ResolvesIntoProtected { literal, .. } => literal,
            Denial::Protected { path, .. }
            | Denial::Whitelisted { path, .. }
            | Denial::LiveOwner { path, .. }
            | Denial::TrashExcluded { path, .. }
            | Denial::Unreadable { path, .. }
            | Denial::Locked { path, .. }
            | Denial::UnattendedRefused { path, .. } => path,
        }
    }

    /// Whether this refusal is worth showing the user. Whitelist hits are
    /// routine and expected; everything else is a signal.
    pub fn is_noteworthy(&self) -> bool {
        !matches!(
            self,
            Denial::Whitelisted { .. } | Denial::SystemRestricted(_)
        )
    }
}

impl std::fmt::Display for Denial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Denial::Empty => write!(f, "empty path"),
            Denial::NotAbsolute(p) => write!(f, "not an absolute path: {}", p.display()),
            Denial::Traversal(p) => write!(f, "path traversal component: {}", p.display()),
            Denial::ControlCharacter(p) => {
                write!(f, "control character in path: {:?}", p)
            }
            Denial::SymlinkToProtected { link, target } => write!(
                f,
                "symlink points at a protected path: {} -> {}",
                link.display(),
                target.display()
            ),
            Denial::UnreadableSymlink(p) => write!(f, "unreadable symlink: {}", p.display()),
            Denial::ResolvesIntoProtected { literal, resolved } => write!(
                f,
                "resolves into a protected path: {} -> {}",
                literal.display(),
                resolved.display()
            ),
            Denial::Protected { path, rule } => {
                write!(f, "protected ({}): {}", rule, path.display())
            }
            Denial::Whitelisted { path, pattern } => {
                write!(f, "whitelisted ({}): {}", pattern, path.display())
            }
            Denial::LiveOwner { path, detail } => {
                write!(f, "owner still running ({}): {}", detail, path.display())
            }
            Denial::Locked { path, locked } => write!(
                f,
                "you locked {} — nothing inside it is ever removed: {}",
                locked.display(),
                path.display()
            ),
            Denial::NeedsPrivilege(p) => {
                write!(f, "requires root, no privileged peer: {}", p.display())
            }
            Denial::SystemRestricted(p) => write!(
                f,
                "protected by macOS (system-restricted): {}",
                p.display()
            ),
            Denial::UnattendedRefused { path, tier } => write!(
                f,
                "tier {} is never run unattended: {}",
                tier,
                path.display()
            ),
            Denial::TrashExcluded { path, pattern } => write!(
                f,
                "kept in the Trash by exclusion {pattern:?}: {}",
                path.display()
            ),
            Denial::Unreadable { path, detail } => write!(
                f,
                "could not read {} ({detail}) — grant eve Full Disk Access in \
                 System Settings > Privacy & Security",
                path.display()
            ),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum EveError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("trash: {0}")]
    Trash(String),
    /// The operation is possible, but only as root.
    ///
    /// Distinct from a refusal: eve is not declining on policy grounds, POSIX
    /// simply will not let this user do it. The message must therefore name the
    /// remedy rather than sounding like a verdict.
    #[error("{0}")]
    NeedsAdmin(String),
    #[error("privileged peer: {0}")]
    Privilege(String),
    #[error("{0}")]
    Other(String),
}

impl From<trash::Error> for EveError {
    fn from(e: trash::Error) -> Self {
        EveError::Trash(e.to_string())
    }
}
