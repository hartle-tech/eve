//! Application uninstallation.
//!
//! The riskiest engine, so it is also the most conservative. Leftover removal
//! is gated by a **sibling guard**: when another install of the same bundle id
//! exists, shared support files belong to it too, and only the selected bundle
//! is removed. Absence of a sibling must be *proven* — a timeout or an
//! unreadable volume degrades to the narrow plan rather than the broad one.

use std::path::{Path, PathBuf};
use std::time::Duration;

use rayon::prelude::*;
use serde::Serialize;

use eve_core::size::{measure, Measurement};

/// What kind of thing an installed application is.
///
/// A flat alphabetical list of everything in `/Applications` makes the user do
/// the sorting: Xcode and a menu-bar toy look identical, and the things that
/// cannot be removed at all are mixed in with the things that can.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum AppKind {
    /// Toolchains, IDEs and the rest of a development machine.
    Development,
    /// Everything else the user installed.
    User,
    /// Apple's, but user-owned and in `/Applications` — the App Store extras
    /// like iMovie, GarageBand and Pages. These really are removable.
    AppleExtra,
    /// Part of macOS, on the sealed system volume. Listed so the space is
    /// visible; never removable, by anyone, on any Mac since Catalina.
    MacOs,
}

impl AppKind {
    pub fn title(self) -> &'static str {
        match self {
            AppKind::Development => "Development",
            AppKind::User => "Installed by you",
            AppKind::AppleExtra => "Apple extras",
            AppKind::MacOs => "Part of macOS",
        }
    }

    /// Whether eve can remove this at all.
    pub fn removable(self) -> bool {
        !matches!(self, AppKind::MacOs)
    }
}

/// Bundle-id and name fragments that mark a development tool.
///
/// Matched on the bundle identifier first, because that is stable across
/// renames and localisations; the display name is a fallback for the handful
/// of tools that ship without a usable identifier.
const DEV_MARKERS: &[&str] = &[
    "com.apple.dt.xcode", "com.microsoft.vscode", "com.vscodium", "com.visualstudio",
    "org.eclipse", "com.jetbrains", "com.google.android.studio", "dev.zed",
    "com.sublimetext", "com.docker", "com.googlecode.iterm2", "com.postmanlabs",
    "com.github.githubclient", "org.rust-lang", "org.python", "com.oracle.java",
    "org.qt-project", "com.unity3d", "io.dbeaver", "com.sequelpro", "org.gnu.emacs",
    "org.vim", "com.panic.nova", "com.figma", "com.tinyapp.tableplus",
];
const DEV_NAME_MARKERS: &[&str] = &[
    "xcode", "visual studio", "vscodium", "eclipse", "intellij", "pycharm", "webstorm",
    "goland", "clion", "rustrover", "datagrip", "rider", "android studio", "docker",
    "postman", "iterm", "sublime text", "zed", "godot", "unity", "dbeaver", "tableplus",
    "sourcetree", "fork", "tower", "insomnia", "kicad", "arduino", "platformio", "thonny",
];

fn classify(path: &Path, bundle_id: Option<&str>, name: &str) -> AppKind {
    // Location decides first and cannot be overridden. Anything on the sealed
    // system volume is part of macOS whatever it is signed with.
    let p = path.to_string_lossy();
    if p.starts_with("/System/") {
        return AppKind::MacOs;
    }

    let id = bundle_id.unwrap_or_default().to_ascii_lowercase();
    let lower = name.to_ascii_lowercase();

    if DEV_MARKERS.iter().any(|m| id.starts_with(m))
        || DEV_NAME_MARKERS.iter().any(|m| lower.contains(m))
    {
        return AppKind::Development;
    }
    // Apple's own, sitting in /Applications rather than on the system volume:
    // the App Store extras, which are ordinary removable bundles.
    if id.starts_with("com.apple.") {
        return AppKind::AppleExtra;
    }
    AppKind::User
}

#[derive(Debug, Clone, Serialize)]
pub struct App {
    pub name: String,
    pub bundle_id: Option<String>,
    pub path: PathBuf,
    pub bytes: u64,
    pub version: Option<String>,
    /// The system owns this bundle, so this user cannot move it anywhere.
    ///
    /// Anything an installer package placed in `/Applications` is `root:wheel`,
    /// and POSIX will not let you move a directory you cannot write into a
    /// different parent — the move rewrites its `..`. Write access to
    /// `/Applications` is irrelevant. Known *before* the attempt so the UI can
    /// say so up front rather than after a removal appears to fail.
    pub needs_admin: bool,
    pub kind: AppKind,
    /// False for anything on the sealed system volume. Distinct from
    /// `needs_admin`, which means "a password would fix this" — no password
    /// fixes this one.
    pub removable: bool,
}

/// Whether we could prove no other install of this bundle id exists.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum SiblingScan {
    /// Proven: this is the only install.
    Sole,
    /// Another install exists — shared leftovers stay.
    SiblingFound,
    /// Could not complete the scan. Treated as `SiblingFound`.
    Indeterminate,
}

impl SiblingScan {
    /// Only a complete "no other install" result unlocks full leftover removal.
    pub fn unlocks_shared_leftovers(self) -> bool {
        self == SiblingScan::Sole
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct UninstallPlan {
    pub app: App,
    pub bundle_path: PathBuf,
    pub leftovers: Vec<Leftover>,
    pub siblings: SiblingScan,
    pub total_bytes: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct Leftover {
    pub path: PathBuf,
    pub bytes: u64,
    pub kind: &'static str,
    /// Shared leftovers are withheld unless the sibling scan proves solitude.
    pub shared: bool,
}

/// List installed applications.
pub fn list_apps(extra_roots: &[PathBuf]) -> Vec<App> {
    list_apps_with_system(extra_roots, false)
}

/// As [`list_apps`], optionally including everything macOS ships.
///
/// The system volume holds nearly two hundred bundles and none of them can be
/// removed, so they are off by default: walking 4 GB of sealed volume to render
/// a list of things nobody can act on is a poor trade on every launch. The
/// Applications screen asks for them when the user opens that section.
pub fn list_apps_with_system(extra_roots: &[PathBuf], include_system: bool) -> Vec<App> {
    let mut roots = vec![PathBuf::from("/Applications")];
    if let Some(home) = dirs::home_dir() {
        roots.push(home.join("Applications"));
    }
    if include_system {
        roots.push(PathBuf::from("/System/Applications"));
        roots.push(PathBuf::from("/System/Applications/Utilities"));
    }
    roots.extend_from_slice(extra_roots);

    let mut bundles = Vec::new();
    for root in roots {
        let Ok(entries) = std::fs::read_dir(&root) else {
            continue;
        };
        for e in entries.flatten() {
            let p = e.path();
            if p.extension().map(|x| x == "app").unwrap_or(false) {
                bundles.push(p);
            }
        }
    }

    // Each app is sized by walking its whole bundle, and there are typically
    // fifty of them. In series that is the several-second stall the
    // Applications screen opened with; the work is filesystem-bound, so it
    // overlaps almost perfectly.
    let mut out: Vec<App> = bundles.par_iter().map(|p| read_app(p)).collect();
    out.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase()));
    out
}

fn read_app(path: &Path) -> App {
    let plist = path.join("Contents/Info.plist");
    let bundle_id = plist_value(&plist, "CFBundleIdentifier");
    let version = plist_value(&plist, "CFBundleShortVersionString");
    let name = path
        .file_stem()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let kind = classify(path, bundle_id.as_deref(), &name);
    App {
        kind,
        removable: kind.removable(),
        name,
        bundle_id,
        bytes: measure(path, Duration::from_secs(8)).bytes,
        version,
        needs_admin: eve_core::executor::Executor::needs_admin_to_relocate(path),
        path: path.to_path_buf(),
    }
}

/// Read one key out of an Info.plist via PlistBuddy.
fn plist_value(plist: &Path, key: &str) -> Option<String> {
    let out = std::process::Command::new("/usr/libexec/PlistBuddy")
        .arg("-c")
        .arg(format!("Print :{key}"))
        .arg(plist)
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let v = String::from_utf8_lossy(&out.stdout).trim().to_string();
    (!v.is_empty()).then_some(v)
}

/// Where an app's remnants live, and whether each is exclusively its own.
fn leftover_roots(home: &Path, bundle_id: &str, name: &str) -> Vec<(PathBuf, &'static str, bool)> {
    let mut v: Vec<(PathBuf, &'static str, bool)> = vec![
        (home.join(format!("Library/Caches/{bundle_id}")), "cache", false),
        (
            home.join(format!("Library/Preferences/{bundle_id}.plist")),
            "preferences",
            true,
        ),
        (
            home.join(format!("Library/Containers/{bundle_id}")),
            "container",
            true,
        ),
        (
            home.join(format!("Library/Application Scripts/{bundle_id}")),
            "app scripts",
            true,
        ),
        (
            home.join(format!("Library/HTTPStorages/{bundle_id}")),
            "web storage",
            false,
        ),
        (
            home.join(format!("Library/WebKit/{bundle_id}")),
            "webkit data",
            false,
        ),
        (
            home.join(format!("Library/Saved Application State/{bundle_id}.savedState")),
            "saved state",
            false,
        ),
        (
            home.join(format!("Library/LaunchAgents/{bundle_id}.plist")),
            "launch agent",
            true,
        ),
    ];
    // Support directories are keyed by display name as often as by bundle id,
    // and those are the ones most likely to hold real user data.
    v.push((
        home.join(format!("Library/Application Support/{name}")),
        "application support",
        true,
    ));
    v.push((
        home.join(format!("Library/Application Support/{bundle_id}")),
        "application support",
        true,
    ));
    v.push((home.join(format!("Library/Logs/{name}")), "logs", false));
    v
}

/// Look for another install of the same bundle id.
pub fn scan_for_siblings(bundle_id: &str, exclude: &Path) -> SiblingScan {
    let out = std::process::Command::new("/usr/bin/mdfind")
        .arg(format!("kMDItemCFBundleIdentifier == '{bundle_id}'"))
        .output();

    let Ok(out) = out else {
        // Cannot prove solitude, so do not assume it.
        return SiblingScan::Indeterminate;
    };
    if !out.status.success() {
        return SiblingScan::Indeterminate;
    }

    let found: Vec<PathBuf> = String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(PathBuf::from)
        .filter(|p| p != exclude)
        .collect();

    if found.is_empty() {
        SiblingScan::Sole
    } else {
        SiblingScan::SiblingFound
    }
}

/// Build the removal plan for one app.
pub fn plan(app: &App, home: &Path) -> UninstallPlan {
    let siblings = match &app.bundle_id {
        Some(id) => scan_for_siblings(id, &app.path),
        // With no bundle id we cannot reason about siblings at all.
        None => SiblingScan::Indeterminate,
    };

    let mut leftovers = Vec::new();
    if let Some(id) = &app.bundle_id {
        for (path, kind, shared) in leftover_roots(home, id, &app.name) {
            if !path.exists() {
                continue;
            }
            let Measurement { bytes, .. } = measure(&path, Duration::from_secs(5));
            // A shared leftover is only offered when solitude is proven.
            if shared && !siblings.unlocks_shared_leftovers() {
                continue;
            }
            leftovers.push(Leftover {
                path,
                bytes,
                kind,
                shared,
            });
        }
    }

    let total_bytes = app.bytes + leftovers.iter().map(|l| l.bytes).sum::<u64>();
    UninstallPlan {
        bundle_path: app.path.clone(),
        app: app.clone(),
        leftovers,
        siblings,
        total_bytes,
    }
}

/// Turn a plan into funnel operations.
///
/// The app bundle lives under `/Applications`, which the policy protects — so
/// uninstalling declares an exemption for exactly the bundle being removed,
/// and nothing wider. That exemption is load-bearing: `/Applications` used to
/// be a *critical* rule, and critical rules ignore exemptions by design, so
/// every bundle removal was silently refused while its leftovers in
/// `~/Library` were deleted normally. eve gutted applications instead of
/// uninstalling them, and reported the plan's total as though it had worked.
pub fn plan_to_operations(p: &UninstallPlan) -> Vec<eve_core::funnel::Operation> {
    use eve_core::executor::Disposition;
    use eve_core::funnel::Operation;
    use eve_core::risk::RiskTier;

    let mut ops = vec![Operation::new("uninstall", &p.bundle_path, RiskTier::Destructive)
        .with_disposition(Disposition::Trash)
        .with_exemptions(vec![p.bundle_path.clone()])];

    for l in &p.leftovers {
        ops.push(
            Operation::new("uninstall:leftover", &l.path, RiskTier::Destructive)
                .with_disposition(Disposition::Trash),
        );
    }
    ops
}

#[cfg(test)]
mod tests {
    use super::*;

    fn app(bundle: Option<&str>) -> App {
        App {
            name: "Example".into(),
            bundle_id: bundle.map(str::to_string),
            path: PathBuf::from("/Applications/Example.app"),
            bytes: 1000,
            version: None,
            needs_admin: false,
            kind: AppKind::User,
            removable: true,
        }
    }

    /// Location beats every other signal. Nothing on the sealed system volume
    /// is removable, whatever it is called or signed with — so a "Development"
    /// or "Apple extra" verdict must never be reachable for one.
    #[test]
    fn nothing_on_the_system_volume_is_ever_removable() {
        for (path, id, name) in [
            ("/System/Applications/Music.app", "com.apple.Music", "Music"),
            // Named and signed exactly like the removable App Store extra, but
            // on the system volume.
            ("/System/Applications/GarageBand.app", "com.apple.garageband", "GarageBand"),
            // A development tool by every name test, in the wrong place.
            ("/System/Applications/Utilities/Terminal.app", "com.apple.Terminal", "Xcode"),
        ] {
            let k = classify(Path::new(path), Some(id), name);
            assert_eq!(k, AppKind::MacOs, "{path} classified as {k:?}");
            assert!(!k.removable(), "{path} was offered as removable");
        }
    }

    #[test]
    fn development_tools_are_recognised_by_id_or_name() {
        for (path, id, name) in [
            ("/Applications/Xcode.app", "com.apple.dt.Xcode", "Xcode"),
            ("/Applications/VSCodium.app", "com.vscodium", "VSCodium"),
            ("/Applications/IntelliJ IDEA.app", "com.jetbrains.intellij", "IntelliJ IDEA"),
            // No usable bundle id: the name carries it.
            ("/Applications/Eclipse.app", "", "Eclipse"),
            ("/Applications/Thonny.app", "org.thonny.Thonny", "Thonny"),
        ] {
            assert_eq!(
                classify(Path::new(path), Some(id), name),
                AppKind::Development,
                "{name} was not recognised as a development tool"
            );
        }
    }

    /// Apple's own bundles that live in /Applications are the App Store extras,
    /// and those genuinely are removable — unlike everything with the same
    /// vendor prefix on the system volume.
    #[test]
    fn apple_extras_are_separated_from_macos_itself() {
        let extra = classify(
            Path::new("/Applications/iMovie.app"),
            Some("com.apple.iMovie"),
            "iMovie",
        );
        assert_eq!(extra, AppKind::AppleExtra);
        assert!(extra.removable(), "an App Store extra must be removable");

        assert_eq!(
            classify(Path::new("/Applications/Slack.app"), Some("com.tinyspeck.slackmacgap"), "Slack"),
            AppKind::User
        );
    }

    #[test]
    fn only_a_proven_sole_install_unlocks_shared_leftovers() {
        assert!(SiblingScan::Sole.unlocks_shared_leftovers());
        assert!(!SiblingScan::SiblingFound.unlocks_shared_leftovers());
        assert!(
            !SiblingScan::Indeterminate.unlocks_shared_leftovers(),
            "an incomplete scan must degrade to the narrow plan"
        );
    }

    #[test]
    fn an_app_with_no_bundle_id_gets_no_leftovers() {
        let tmp = tempfile::tempdir().unwrap();
        let p = plan(&app(None), tmp.path());
        assert_eq!(p.siblings, SiblingScan::Indeterminate);
        assert!(p.leftovers.is_empty());
    }

    #[test]
    fn shared_leftovers_are_withheld_when_solitude_is_unproven() {
        let tmp = tempfile::tempdir().unwrap();
        let support = tmp.path().join("Library/Application Support/Example");
        std::fs::create_dir_all(&support).unwrap();
        std::fs::write(support.join("data"), vec![0u8; 500]).unwrap();

        // No bundle id -> Indeterminate -> shared entries must not appear.
        let p = plan(&app(None), tmp.path());
        assert!(
            !p.leftovers.iter().any(|l| l.shared),
            "shared leftover offered without proof of solitude"
        );
    }

    #[test]
    fn operations_exempt_only_the_bundle_being_removed() {
        let p = UninstallPlan {
            app: app(Some("com.example.app")),
            bundle_path: PathBuf::from("/Applications/Example.app"),
            leftovers: vec![],
            siblings: SiblingScan::Sole,
            total_bytes: 1000,
        };
        let ops = plan_to_operations(&p);
        assert_eq!(ops.len(), 1);
        assert_eq!(ops[0].exemptions.0, vec![PathBuf::from("/Applications/Example.app")]);
    }

    #[test]
    fn every_uninstall_operation_is_destructive_tier() {
        let p = UninstallPlan {
            app: app(Some("com.example.app")),
            bundle_path: PathBuf::from("/Applications/Example.app"),
            leftovers: vec![Leftover {
                path: PathBuf::from("/tmp/x"),
                bytes: 1,
                kind: "cache",
                shared: false,
            }],
            siblings: SiblingScan::Sole,
            total_bytes: 1,
        };
        for op in plan_to_operations(&p) {
            assert_eq!(op.tier, eve_core::risk::RiskTier::Destructive);
            assert!(!op.tier.allowed_unattended());
        }
    }
}
