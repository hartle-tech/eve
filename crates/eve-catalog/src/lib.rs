//! The declarative target catalog.
//!
//! Categories are **data, not code**. That is what lets eve carry a full
//! cleaner's inventory plus the privileged extras without the catalog turning
//! into thousands of lines of imperative special cases — and it is what makes
//! the safety properties reviewable, because every category's tier, context
//! and exemptions are visible in one place.

pub mod dynamic;

use std::path::PathBuf;

use eve_core::executor::Disposition;
use eve_core::risk::{RiskTier, RunContext};
use serde::{Deserialize, Serialize};

/// Where a category appears in the UI.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Group {
    User,
    AppCaches,
    Browsers,
    Developer,
    Apps,
    Projects,
    System,
    Assets,
}

impl Group {
    pub fn title(self) -> &'static str {
        match self {
            Group::User => "User essentials",
            Group::AppCaches => "App caches",
            Group::Browsers => "Browsers",
            Group::Developer => "Developer tools",
            Group::Apps => "Applications",
            Group::Projects => "Project artifacts",
            Group::System => "System (root)",
            Group::Assets => "System assets",
        }
    }

    pub fn all() -> [Group; 8] {
        [
            Group::User,
            Group::AppCaches,
            Group::Browsers,
            Group::Developer,
            Group::Apps,
            Group::Projects,
            Group::System,
            Group::Assets,
        ]
    }
}

/// Something to remove.
#[derive(Debug, Clone, Serialize)]
pub enum Target {
    /// An absolute path, already expanded.
    Path(PathBuf),
    /// A glob, already expanded against the real filesystem.
    Glob(String),
    /// Computed at scan time — see [`dynamic`].
    Dynamic(dynamic::Kind),
}

/// A maintenance command.
///
/// Commands are a **fixed allowlist** defined in this file. They never
/// incorporate user input, and nothing at runtime can add to the list. That is
/// the entire safety argument for them, since they do not pass through the
/// path funnel — there is no path to validate.
#[derive(Debug, Clone, Serialize)]
pub struct Cmd {
    pub program: &'static str,
    pub args: &'static [&'static str],
    /// Requires root.
    pub privileged: bool,
    /// What this reclaims, for the preview. Commands are opaque to `du`.
    pub note: &'static str,
}

/// Something that must be true before a category is offered.
#[derive(Debug, Clone, Serialize)]
pub enum Precondition {
    /// A binary must be resolvable on PATH.
    Binary(&'static str),
    /// A path must exist.
    Exists(PathBuf),
}

impl Precondition {
    pub fn satisfied(&self) -> bool {
        match self {
            Precondition::Binary(b) => which(b).is_some(),
            Precondition::Exists(p) => p.exists(),
        }
    }
}

/// Resolve a binary on PATH.
///
/// launchd hands jobs a bare PATH (`/usr/bin:/bin:/usr/sbin:/sbin`), so under
/// an unattended run brew, docker, npm and mise all resolve to nothing and
/// their categories silently do not run — no error, no log line, just missing
/// reclaim. The unattended agent must therefore be given an explicit PATH;
/// this function is where that failure would otherwise hide.
pub fn which(bin: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|d| d.join(bin))
        .find(|c| c.is_file())
}

/// One cleanable category.
#[derive(Debug, Clone, Serialize)]
pub struct Category {
    pub key: &'static str,
    pub title: &'static str,
    pub description: &'static str,
    pub group: Group,
    pub tier: RiskTier,
    pub context: RunContext,
    pub disposition: Disposition,
    pub targets: Vec<Target>,
    pub commands: Vec<Cmd>,
    /// Normally-protected paths this category is explicitly permitted to touch.
    pub exemptions: Vec<PathBuf>,
    pub preconditions: Vec<Precondition>,
}

impl Category {
    pub fn available(&self) -> bool {
        self.preconditions.iter().all(|p| p.satisfied())
    }

    pub fn on_by_default(&self) -> bool {
        self.tier.on_by_default()
    }

    pub fn needs_root(&self) -> bool {
        self.tier == RiskTier::Privileged || self.commands.iter().any(|c| c.privileged)
    }
}

struct Builder {
    home: PathBuf,
}

impl Builder {
    fn h(&self, rel: &str) -> Target {
        Target::Path(self.home.join(rel))
    }
    fn p(&self, abs: &str) -> Target {
        Target::Path(PathBuf::from(abs))
    }
    fn hg(&self, rel: &str) -> Target {
        Target::Glob(self.home.join(rel).to_string_lossy().into_owned())
    }
}

/// Build the full catalog for a given home directory.
pub fn catalog_for(home: impl Into<PathBuf>) -> Vec<Category> {
    let b = Builder { home: home.into() };
    let home = b.home.clone();

    let mut c: Vec<Category> = Vec::new();

    let mut add = |key,
                   title,
                   description,
                   group,
                   tier,
                   context,
                   disposition,
                   targets: Vec<Target>,
                   commands: Vec<Cmd>,
                   exemptions: Vec<PathBuf>,
                   preconditions: Vec<Precondition>| {
        c.push(Category {
            key,
            title,
            description,
            group,
            tier,
            context,
            disposition,
            targets,
            commands,
            exemptions,
            preconditions,
        });
    };

    // ---------------------------------------------------------------- user
    add(
        "trash",
        "Trash",
        "Empty the user's Trash on the internal disk.",
        Group::User,
        RiskTier::Review,
        RunContext::User,
        Disposition::Permanent,
        vec![b.h(".Trash")],
        vec![],
        vec![],
        vec![],
    );

    add(
        "user_caches",
        "User caches",
        "~/Library/Caches and ~/.cache. Contents only — apps expect the directory to exist.",
        Group::User,
        RiskTier::Safe,
        RunContext::User,
        Disposition::EmptyContents,
        vec![b.h("Library/Caches"), b.h(".cache")],
        vec![],
        vec![],
        vec![],
    );

    add(
        "saved_state",
        "Saved application state",
        "Window/session restore data. Costs you reopened windows, nothing more.",
        Group::User,
        RiskTier::Safe,
        RunContext::User,
        Disposition::EmptyContents,
        vec![b.h("Library/Saved Application State")],
        vec![],
        vec![],
        vec![],
    );

    add(
        "user_logs",
        "User logs",
        "~/Library/Logs and diagnostic reports.",
        Group::User,
        RiskTier::Safe,
        RunContext::User,
        Disposition::EmptyContents,
        vec![
            b.h("Library/Logs"),
            b.h("Library/Application Support/CrashReporter"),
        ],
        vec![],
        vec![],
        vec![],
    );

    add(
        "darwin_scratch",
        "Per-user scratch space",
        "The private /var/folders cache and temp directories for this user.",
        Group::User,
        RiskTier::Safe,
        RunContext::User,
        Disposition::EmptyContents,
        vec![Target::Dynamic(dynamic::Kind::DarwinUserScratch)],
        vec![],
        vec![],
        vec![],
    );

    add(
        "quicklook",
        "QuickLook thumbnails",
        "Thumbnail cache; regenerates on demand.",
        Group::User,
        RiskTier::Safe,
        RunContext::User,
        Disposition::EmptyContents,
        vec![b.h("Library/Caches/com.apple.QuickLook.thumbnailcache")],
        vec![Cmd {
            program: "qlmanage",
            args: &["-r", "cache"],
            privileged: false,
            note: "reset the QuickLook cache",
        }],
        vec![],
        vec![Precondition::Binary("qlmanage")],
    );

    // ---------------------------------------------------------- app caches
    add(
        "container_caches",
        "Sandboxed app caches",
        "Cache directories inside ~/Library/Containers and Group Containers.",
        Group::AppCaches,
        RiskTier::Safe,
        RunContext::User,
        Disposition::EmptyContents,
        vec![Target::Dynamic(dynamic::Kind::ContainerCaches)],
        vec![],
        vec![],
        vec![],
    );

    add(
        "electron_caches",
        "Electron app caches",
        "Cache / Code Cache / GPUCache / ShaderCache inside Electron-style apps.",
        Group::AppCaches,
        RiskTier::Safe,
        RunContext::User,
        Disposition::Trash,
        vec![Target::Dynamic(dynamic::Kind::ElectronCaches)],
        vec![],
        vec![],
        vec![],
    );

    add(
        "mail_downloads",
        "Mail downloads",
        "Attachments Mail saved to disk. Not the mail store itself.",
        Group::Apps,
        RiskTier::Review,
        RunContext::User,
        Disposition::Trash,
        vec![
            b.h("Library/Containers/com.apple.mail/Data/Library/Mail Downloads"),
            b.h("Library/Mail Downloads"),
        ],
        vec![],
        vec![],
        vec![],
    );

    // ------------------------------------------------------------ browsers
    add(
        "browser_caches",
        "Browser caches",
        "Cache and service-worker storage. Never history, bookmarks or passwords.",
        Group::Browsers,
        RiskTier::Review,
        RunContext::User,
        Disposition::Trash,
        vec![
            b.h("Library/Caches/com.apple.Safari"),
            b.h("Library/Caches/Google/Chrome"),
            b.h("Library/Caches/Firefox"),
            b.h("Library/Caches/BraveSoftware"),
            b.h("Library/Caches/com.microsoft.edgemac"),
            b.hg("Library/Application Support/Google/Chrome/*/Cache"),
            b.hg("Library/Application Support/Google/Chrome/*/Code Cache"),
            b.hg("Library/Application Support/Google/Chrome/*/Service Worker/CacheStorage"),
            b.hg("Library/Application Support/BraveSoftware/Brave-Browser/*/Cache"),
        ],
        vec![],
        vec![],
        vec![],
    );

    // ----------------------------------------------------------- developer
    add(
        "xcode_derived",
        "Xcode derived data",
        "DerivedData and Archives. Rebuilt on next build.",
        Group::Developer,
        RiskTier::Safe,
        RunContext::User,
        Disposition::Trash,
        vec![
            b.h("Library/Developer/Xcode/DerivedData"),
            b.h("Library/Developer/Xcode/Archives"),
        ],
        vec![],
        vec![],
        vec![Precondition::Exists(home.join("Library/Developer/Xcode"))],
    );

    add(
        "xcode_device_support",
        "Xcode device support",
        "Symbol caches for every iOS/watchOS/tvOS version you ever attached.",
        Group::Developer,
        RiskTier::Safe,
        RunContext::User,
        Disposition::Trash,
        vec![
            b.h("Library/Developer/Xcode/iOS DeviceSupport"),
            b.h("Library/Developer/Xcode/watchOS DeviceSupport"),
            b.h("Library/Developer/Xcode/tvOS DeviceSupport"),
            b.h("Library/Developer/CoreSimulator/Caches"),
        ],
        vec![],
        vec![],
        vec![Precondition::Exists(home.join("Library/Developer"))],
    );

    add(
        "simulators",
        "Unavailable simulators",
        "Simulator runtimes for SDKs you no longer have.",
        Group::Developer,
        RiskTier::Safe,
        RunContext::User,
        Disposition::Trash,
        vec![],
        vec![Cmd {
            program: "xcrun",
            args: &["simctl", "delete", "unavailable"],
            privileged: false,
            note: "delete unavailable simulators",
        }],
        vec![],
        vec![Precondition::Binary("xcrun")],
    );

    add(
        "package_caches",
        "Package manager caches",
        "npm, pnpm, pip, cargo, maven and gradle download caches.",
        Group::Developer,
        RiskTier::Safe,
        RunContext::User,
        Disposition::Trash,
        vec![
            b.h(".npm/_cacache"),
            b.h(".npm/_logs"),
            b.h("Library/pnpm/store"),
            b.h("Library/Caches/pip"),
            b.h(".cargo/registry/cache"),
            b.h(".cargo/registry/src"),
            b.h(".gradle/daemon"),
        ],
        vec![],
        vec![],
        vec![],
    );

    add(
        "go_cache",
        "Go build and module cache",
        "go clean -cache -modcache -testcache -fuzzcache.",
        Group::Developer,
        RiskTier::Safe,
        RunContext::User,
        Disposition::Trash,
        vec![],
        vec![Cmd {
            program: "go",
            args: &["clean", "-cache", "-modcache", "-testcache", "-fuzzcache"],
            privileged: false,
            note: "clear the Go caches",
        }],
        vec![],
        vec![Precondition::Binary("go")],
    );

    add(
        "homebrew",
        "Homebrew cleanup",
        "Prune old downloads and unused dependencies.",
        Group::Developer,
        RiskTier::Safe,
        // Homebrew hard-refuses to run as root. This is why the field exists.
        RunContext::User,
        Disposition::Trash,
        vec![],
        vec![
            Cmd {
                program: "brew",
                args: &["cleanup", "-s", "--prune=all"],
                privileged: false,
                note: "prune Homebrew downloads",
            },
            Cmd {
                program: "brew",
                args: &["autoremove"],
                privileged: false,
                note: "remove unused dependencies",
            },
        ],
        vec![],
        vec![Precondition::Binary("brew")],
    );

    add(
        "docker",
        "Docker unused data",
        "Prune stopped containers, unused images and volumes. Deletes volume data.",
        Group::Developer,
        RiskTier::Review,
        // As root, docker addresses root's context rather than the user's
        // Docker Desktop socket, and the prune silently no-ops.
        RunContext::User,
        Disposition::Trash,
        vec![],
        vec![Cmd {
            program: "docker",
            args: &["system", "prune", "-a", "--volumes", "-f"],
            privileged: false,
            note: "prune all unused Docker data",
        }],
        vec![],
        vec![Precondition::Binary("docker")],
    );

    add(
        "gradle_wrappers",
        "Old Gradle distributions",
        "Every Gradle wrapper except the most recently used one.",
        Group::Developer,
        RiskTier::Safe,
        RunContext::User,
        Disposition::Trash,
        vec![Target::Dynamic(dynamic::Kind::GradleOldWrappers)],
        vec![],
        vec![],
        vec![],
    );

    add(
        "pyenv_old",
        "Old pyenv versions",
        "Every installed Python except the one ~/.pyenv/version pins.",
        Group::Developer,
        RiskTier::Review,
        RunContext::User,
        Disposition::Trash,
        vec![Target::Dynamic(dynamic::Kind::PyenvOldVersions)],
        vec![],
        vec![],
        vec![Precondition::Exists(home.join(".pyenv/versions"))],
    );

    add(
        "pycache",
        "Python bytecode caches",
        "__pycache__ directories under your source tree.",
        Group::Projects,
        RiskTier::Safe,
        RunContext::User,
        Disposition::Trash,
        vec![Target::Dynamic(dynamic::Kind::PyCache)],
        vec![],
        // Lives under ~/Projects, which the policy protects as source code.
        vec![home.join("Projects")],
        vec![],
    );

    add(
        "node_modules",
        "Stale node_modules",
        "node_modules in projects untouched for 90 days. Reinstallable.",
        Group::Projects,
        RiskTier::Review,
        RunContext::User,
        Disposition::Trash,
        vec![Target::Dynamic(dynamic::Kind::StaleNodeModules)],
        vec![],
        vec![home.join("Projects")],
        vec![],
    );

    add(
        "terraform_providers",
        "Duplicate Terraform providers",
        "Drops registry.terraform.io provider copies, keeps the OpenTofu ones.",
        Group::Projects,
        RiskTier::Safe,
        RunContext::User,
        Disposition::Trash,
        vec![Target::Dynamic(dynamic::Kind::TerraformProviders)],
        vec![],
        vec![home.join("Projects")],
        vec![],
    );

    // ------------------------------------------------------- AI tool debris
    add(
        "claude_vm",
        "Claude Code sandbox images",
        "Cached sandbox VM bundles. Regenerate on demand and are frequently the single largest item on the disk.",
        Group::Developer,
        RiskTier::Safe,
        RunContext::User,
        Disposition::Trash,
        vec![b.h("Library/Application Support/Claude/vm_bundles")],
        vec![],
        vec![],
        vec![],
    );

    add(
        "claude_versions",
        "Old Claude CLI versions",
        "Superseded CLI installs; keeps whatever ~/.local/bin/claude points at.",
        Group::Developer,
        RiskTier::Safe,
        RunContext::User,
        Disposition::Trash,
        vec![Target::Dynamic(dynamic::Kind::ClaudeOldVersions)],
        vec![],
        vec![],
        vec![],
    );

    add(
        "claude_tool_results",
        "Claude tool-result caches",
        "Cached tool output under ~/.claude/projects.",
        Group::Developer,
        RiskTier::Safe,
        RunContext::User,
        Disposition::Trash,
        vec![Target::Dynamic(dynamic::Kind::ClaudeToolResults)],
        vec![],
        vec![],
        vec![],
    );

    add(
        "codex_cache",
        "Codex logs and screenshot cache",
        "Codex's local log database and computer-use screenshot cache.",
        Group::Developer,
        RiskTier::Safe,
        RunContext::User,
        Disposition::Trash,
        vec![
            b.h(".codex/logs_2.sqlite"),
            b.h(".codex/logs_2.sqlite-wal"),
            b.h(".codex/logs_2.sqlite-shm"),
            b.h(".codex/computer-use"),
        ],
        vec![],
        vec![],
        vec![],
    );

    // -------------------------------------------------------------- system
    add(
        "system_caches",
        "System caches",
        "/Library/Caches. Requires root.",
        Group::System,
        RiskTier::Privileged,
        RunContext::Any,
        Disposition::EmptyContents,
        vec![b.p("/Library/Caches")],
        vec![],
        vec![],
        vec![],
    );

    add(
        "system_logs",
        "System logs",
        "ASL archives, diagnostic messages and system crash reports.",
        Group::System,
        RiskTier::Privileged,
        RunContext::Any,
        Disposition::Permanent,
        vec![
            b.p("/private/var/log/asl"),
            b.p("/private/var/log/DiagnosticMessages"),
            b.p("/Library/Logs/DiagnosticReports"),
        ],
        vec![],
        vec![],
        vec![],
    );

    add(
        "unified_logs",
        "Unified logging archives",
        "The macOS unified log store. Frequently 1-2 GB.",
        Group::System,
        RiskTier::Privileged,
        RunContext::Any,
        Disposition::Permanent,
        vec![
            b.p("/private/var/db/diagnostics"),
            b.p("/private/var/db/uuidtext"),
        ],
        vec![Cmd {
            program: "log",
            args: &["erase", "--all"],
            privileged: true,
            note: "erase the unified log store",
        }],
        vec![],
        vec![],
    );

    add(
        "sleepimage",
        "Hibernation image",
        "/private/var/vm/sleepimage — as large as your RAM. Regenerates only if hibernate engages.",
        Group::System,
        RiskTier::Privileged,
        RunContext::Any,
        Disposition::Permanent,
        vec![b.p("/private/var/vm/sleepimage")],
        vec![],
        vec![],
        vec![],
    );

    add(
        "hidden_data_dirs",
        "Hidden data-volume directories",
        "Document revisions, previous-system information and chunky /private/var/db logs.",
        Group::System,
        RiskTier::Privileged,
        RunContext::Any,
        Disposition::EmptyContents,
        vec![
            b.p("/System/Volumes/Data/.DocumentRevisions-V100"),
            b.p("/System/Volumes/Data/.PreviousSystemInformation"),
        ],
        vec![],
        // These live under /System, which is critical. Reaching them requires
        // an explicit, auditable declaration — exactly what exemptions are for.
        vec![PathBuf::from("/System/Volumes/Data")],
        vec![],
    );

    add(
        "installer_leftovers",
        "Leftover installer packages",
        "/Library/Updates and App Store install state.",
        Group::System,
        RiskTier::Privileged,
        RunContext::Any,
        Disposition::Permanent,
        vec![
            b.p("/Library/Updates"),
            b.h("Library/Application Support/App Store/installState"),
        ],
        vec![],
        vec![],
        vec![],
    );

    add(
        "local_snapshots",
        "APFS local snapshots",
        "Time Machine local snapshots pinning deleted data.",
        Group::System,
        RiskTier::Privileged,
        RunContext::Any,
        Disposition::Permanent,
        vec![],
        // `thinlocalsnapshots` asks the system to reclaim up to N bytes at the
        // given urgency, rather than naming snapshots individually. That keeps
        // this a fixed command with no interpolated arguments, and lets macOS
        // decide which snapshots it can safely drop.
        vec![Cmd {
            program: "tmutil",
            args: &["thinlocalsnapshots", "/", "21474836480", "4"],
            privileged: true,
            note: "thin local snapshots (up to 20 GB)",
        }],
        vec![],
        vec![Precondition::Binary("tmutil")],
    );

    add(
        "spotlight_reindex",
        "Spotlight index rebuild",
        "Discards the Spotlight index and reindexes. Search is degraded until it finishes.",
        Group::System,
        RiskTier::Destructive,
        RunContext::Any,
        Disposition::Permanent,
        vec![],
        vec![
            Cmd {
                program: "mdutil",
                args: &["-i", "off", "/"],
                privileged: true,
                note: "disable indexing",
            },
            Cmd {
                program: "mdutil",
                args: &["-E", "/"],
                privileged: true,
                note: "erase and rebuild the index",
            },
            Cmd {
                program: "mdutil",
                args: &["-i", "on", "/"],
                privileged: true,
                note: "re-enable indexing",
            },
        ],
        vec![],
        vec![Precondition::Binary("mdutil")],
    );

    // ------------------------------------------------------- never / assets
    add(
        "ios_backups",
        "iOS device backups",
        "iPhone and iPad backups. These are photos and videos, not cache — and TCC-protected, so they measure as 0 bytes.",
        Group::Assets,
        // Never unattended, ever. The tier is the guard, not a caller's flag.
        RiskTier::NeverAuto,
        RunContext::User,
        Disposition::Trash,
        vec![b.h("Library/Application Support/MobileSync/Backup")],
        vec![],
        vec![home.join("Library/Application Support/MobileSync")],
        vec![],
    );

    add(
        "siri_assets",
        "Siri and speech assets",
        "Siri understanding, TTS voices and dictation packs. SIP normally blocks this — see the Settings hints.",
        Group::Assets,
        RiskTier::Destructive,
        RunContext::Any,
        Disposition::Permanent,
        vec![Target::Dynamic(dynamic::Kind::SiriAssets)],
        vec![],
        vec![PathBuf::from("/System/Library/AssetsV2")],
        vec![Precondition::Exists(PathBuf::from(
            "/System/Library/AssetsV2",
        ))],
    );

    c
}

/// Build the catalog for the current user.
pub fn catalog() -> Vec<Category> {
    catalog_for(dirs::home_dir().unwrap_or_else(|| PathBuf::from("/")))
}

/// SIP-safe routes to evict system assets through Apple's own APIs.
///
/// Fighting SIP loses. These panes make macOS release the packs itself, which
/// is the only approach that actually works on a stock machine.
pub const SETTINGS_HINTS: &[(&str, &str, &str)] = &[
    (
        "TTS voices",
        "Accessibility > Spoken Content > Manage Voices",
        "x-apple.systempreferences:com.apple.Accessibility-Settings.extension",
    ),
    (
        "Keyboard / input sources",
        "Keyboard > Text Input > Edit input sources",
        "x-apple.systempreferences:com.apple.Keyboard-Settings.extension",
    ),
    (
        "Languages",
        "General > Language & Region > Preferred Languages",
        "x-apple.systempreferences:com.apple.Localization-Settings.extension",
    ),
    (
        "Siri understanding",
        "Apple Intelligence & Siri (toggle off; drains over days)",
        "x-apple.systempreferences:com.apple.Siri-Settings.extension",
    ),
    (
        "Photos analysis",
        "General > Storage > Photos > Optimize",
        "x-apple.systempreferences:com.apple.settings.Storage",
    ),
    (
        "Dictation",
        "Keyboard > Dictation (toggle off)",
        "x-apple.systempreferences:com.apple.Keyboard-Settings.extension",
    ),
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalog_builds_and_keys_are_unique() {
        let cats = catalog_for("/Users/tester");
        assert!(cats.len() > 25, "catalog is suspiciously small");

        let mut keys: Vec<&str> = cats.iter().map(|c| c.key).collect();
        keys.sort_unstable();
        let before = keys.len();
        keys.dedup();
        assert_eq!(before, keys.len(), "duplicate category keys");
    }

    /// The single most important invariant in the catalog.
    #[test]
    fn ios_backups_can_never_run_unattended() {
        let cats = catalog_for("/Users/tester");
        let ios = cats.iter().find(|c| c.key == "ios_backups").unwrap();
        assert_eq!(ios.tier, RiskTier::NeverAuto);
        assert!(!ios.tier.allowed_unattended());
        assert!(!ios.on_by_default());
    }

    /// Homebrew and Docker misbehave as root in opposite ways. Both must be
    /// pinned to the user context.
    #[test]
    fn root_hostile_categories_are_pinned_to_user_context() {
        let cats = catalog_for("/Users/tester");
        for key in ["homebrew", "docker"] {
            let cat = cats.iter().find(|c| c.key == key).unwrap();
            assert_eq!(
                cat.context,
                RunContext::User,
                "{key} must be pinned to the user context"
            );
        }
    }

    #[test]
    fn every_category_touching_a_protected_root_declares_an_exemption() {
        let home = PathBuf::from("/Users/tester");
        let cats = catalog_for(&home);
        for cat in &cats {
            for t in &cat.targets {
                if let Target::Path(p) = t {
                    let touches_protected = p.starts_with(home.join("Library/Application Support/MobileSync"))
                        || p.starts_with("/System");
                    if touches_protected {
                        assert!(
                            !cat.exemptions.is_empty(),
                            "{} touches a protected root without declaring an exemption",
                            cat.key
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn privileged_categories_are_reported_as_needing_root() {
        let cats = catalog_for("/Users/tester");
        let sleep = cats.iter().find(|c| c.key == "sleepimage").unwrap();
        assert!(sleep.needs_root());
        let caches = cats.iter().find(|c| c.key == "user_caches").unwrap();
        assert!(!caches.needs_root());
    }

    #[test]
    fn default_on_set_excludes_review_and_worse() {
        let cats = catalog_for("/Users/tester");
        for cat in &cats {
            if cat.on_by_default() {
                assert!(
                    matches!(cat.tier, RiskTier::Safe | RiskTier::Privileged),
                    "{} is on by default at tier {}",
                    cat.key,
                    cat.tier
                );
            }
        }
    }
}
