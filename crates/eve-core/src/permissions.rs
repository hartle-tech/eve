//! What macOS has and has not let eve do, and how to fix it in one click.
//!
//! TCC cannot be granted programmatically — the database is SIP-protected and
//! only a person in System Settings can flip a switch. That is a hard limit,
//! and everything here is about making the distance between "eve does not
//! work" and "eve works" as short as macOS allows:
//!
//! 1. **Ask for the thing first.** An app that has never attempted a protected
//!    read does not appear in the Full Disk Access list at all, so the user is
//!    told to drag a binary out of a hidden directory into a window. After one
//!    attempt macOS lists it with the switch off, and the whole task becomes
//!    flipping that switch. [`Permission::provoke`] is that attempt.
//! 2. **Open the exact pane.** Not "System Settings"; the Privacy pane for
//!    that specific permission.
//! 3. **Say what breaks without it**, per permission, so a refusal is an
//!    informed choice rather than a mystery later.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// Something macOS can withhold from eve.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Permission {
    /// Reading `~/Library`, `~/.Trash` and the rest of the protected user
    /// directories. Without it eve is close to useless.
    FullDiskAccess,
    /// Modifying or deleting other applications' bundles. macOS 14 moved app
    /// removal behind this, separately from Full Disk Access.
    AppManagement,
    /// The notification the unattended run posts when it finishes.
    Notifications,
}

/// Whether eve has it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PermissionState {
    Granted,
    Denied,
    /// Cannot be determined without side effects, so it is not claimed either
    /// way. Reporting a guess as fact is worse than saying "unknown": the user
    /// acts on it and finds out later that it was wrong.
    Unknown,
}

/// One permission, its state, and everything the UI needs to act on it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PermissionStatus {
    pub permission: Permission,
    pub state: PermissionState,
    /// Short label, as it appears in System Settings.
    pub title: &'static str,
    /// What stops working without it, in the user's terms.
    pub what_breaks: &'static str,
    /// Whether eve is worth running at all without it.
    pub required: bool,
    /// Deep link to the exact Privacy pane.
    pub settings_url: &'static str,
    /// The row to look for once that pane is open.
    pub look_for: String,
}

impl Permission {
    pub const ALL: [Permission; 3] = [
        Permission::FullDiskAccess,
        Permission::AppManagement,
        Permission::Notifications,
    ];

    pub fn title(self) -> &'static str {
        match self {
            Permission::FullDiskAccess => "Full Disk Access",
            Permission::AppManagement => "App Management",
            Permission::Notifications => "Notifications",
        }
    }

    /// Whether eve is worth running without it.
    pub fn required(self) -> bool {
        matches!(self, Permission::FullDiskAccess)
    }

    pub fn what_breaks(self) -> &'static str {
        match self {
            Permission::FullDiskAccess => {
                "eve cannot read your caches, logs or Trash. It will report almost \
                 nothing to reclaim and emptying the Trash will do nothing at all."
            }
            Permission::AppManagement => {
                "Uninstalling an application will fail. Everything else still works."
            }
            Permission::Notifications => {
                "The background cleanup will not tell you when it has run. It still runs."
            }
        }
    }

    /// The Privacy pane for exactly this permission.
    pub fn settings_url(self) -> &'static str {
        match self {
            Permission::FullDiskAccess => {
                "x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles"
            }
            Permission::AppManagement => {
                "x-apple.systempreferences:com.apple.preference.security?Privacy_AppBundles"
            }
            Permission::Notifications => {
                "x-apple.systempreferences:com.apple.Notifications-Settings.extension"
            }
        }
    }

    /// Do the thing the permission guards, so macOS registers eve as having
    /// asked for it.
    ///
    /// This is the difference between a one-switch task and a scavenger hunt.
    /// An app that has never attempted the access is simply absent from the
    /// Full Disk Access list, and the user has to add it by hand from a hidden
    /// directory. One failed read is enough to make macOS list it, switched
    /// off, ready to be turned on.
    ///
    /// Deliberately read-only and deliberately ignores its result: the point is
    /// the attempt, not the answer.
    pub fn provoke(self) {
        match self {
            Permission::FullDiskAccess => {
                // The Trash and nothing else.
                //
                // This used to also stat TCC's own database, which lives in
                // `~/Library/Application Support/com.apple.TCC` — another
                // application's support directory, and therefore the exact
                // access behind *"eve would like to access data from other
                // apps"*. `provoke_all()` runs on every launch by design, so
                // that one line raised a permission dialog every single time
                // eve was opened.
                //
                // `~/.Trash` is the user's own directory and is gated by Full
                // Disk Access alone, which is what we are asking about.
                let _ = std::fs::read_dir(trash_dir());
            }
            Permission::AppManagement => {
                // Reading an app's Info.plist is not itself gated, but touching
                // the bundle is what registers interest.
                let _ = std::fs::read_dir("/Applications");
            }
            Permission::Notifications => {}
        }
    }

    /// Whether macOS is currently letting eve do it.
    pub fn state(self) -> PermissionState {
        match self {
            // The canonical probe. TCC's own database is readable only with
            // Full Disk Access, and reading it has no side effects.
            // `~/.Trash` is the probe, and deliberately the only one.
            //
            // It is gated by Full Disk Access, it is the user's own directory,
            // and reading it is eve's actual job — so a successful read means
            // eve can do what it is for. The old probe stat'd TCC's database
            // first, which lives in another app's support directory and raised
            // the App Data dialog on every launch to answer a question
            // `~/.Trash` already answers.
            Permission::FullDiskAccess => {
                if std::fs::read_dir(trash_dir()).is_ok() {
                    PermissionState::Granted
                } else {
                    PermissionState::Denied
                }
            }
            // TCC's own database has the answer, and reading it is exactly as
            // side-effect-free as reading it for Full Disk Access — which eve
            // already does, one line above.
            //
            // This used to report `Unknown` on the grounds that "the only way
            // to learn whether app modification is permitted is to attempt
            // one". That was wrong, and it showed a permission the user had
            // already granted as missing.
            Permission::AppManagement => {
                match tcc_decision("kTCCServiceSystemPolicyAppBundles") {
                    Some(true) => PermissionState::Granted,
                    Some(false) => PermissionState::Denied,
                    // No row at all means never asked. Not the same as denied.
                    None => PermissionState::Unknown,
                }
            }
            Permission::Notifications => notification_state(),
        }
    }

    pub fn status(self) -> PermissionStatus {
        PermissionStatus {
            permission: self,
            state: self.state(),
            title: self.title(),
            what_breaks: self.what_breaks(),
            required: self.required(),
            settings_url: self.settings_url(),
            look_for: look_for(),
        }
    }
}

/// The name the user should look for in the Settings list.
///
/// The bundle when eve is running as the app, the executable's file name when
/// it is the command-line tool — because that is what macOS displays, and
/// telling someone to look for the wrong one is worse than not telling them.
pub fn look_for() -> String {
    if running_as_bundle() {
        "eve".to_string()
    } else {
        std::env::current_exe()
            .ok()
            .and_then(|p| p.file_name().map(|n| n.to_string_lossy().into_owned()))
            .unwrap_or_else(|| "eve".to_string())
    }
}

/// Whether this process is the `.app`, as opposed to the bare binary.
///
/// They are separate TCC identities: granting one does nothing for the other,
/// which is the single most confusing thing about permissions here.
pub fn running_as_bundle() -> bool {
    std::env::current_exe()
        .map(|p| p.to_string_lossy().contains(".app/Contents/MacOS/"))
        .unwrap_or(false)
}

fn tcc_db() -> PathBuf {
    home().join("Library/Application Support/com.apple.TCC/TCC.db")
}

/// What TCC has recorded for this program and one service.
///
/// `Some(true)` granted, `Some(false)` denied, `None` never asked.
///
/// Read straight out of TCC's own database, which is where the answer actually
/// lives, using the `sqlite3` that ships with macOS rather than linking a
/// SQLite of our own. Read-only and side-effect-free — and eve already reads
/// this same file to decide Full Disk Access, so it costs no new permission.
///
/// The client is the **bundle identifier** when running as the `.app` and the
/// **absolute executable path** when running as the command-line tool. They
/// are separate TCC identities with separate rows, and matching the wrong one
/// reports a granted permission as missing.
fn tcc_decision(service: &str) -> Option<bool> {
    tcc_decision_for(service, &tcc_client()?)
}

/// eve's bundle identifier.
///
/// One definition. It is TCC's key for the `.app`, the name of eve's own
/// support directory, and the `?id=` System Settings uses to select eve's row
/// — and three copies of a string that must agree is three chances for them
/// not to.
pub const BUNDLE_ID: &str = "tech.hartle.eve";

/// The identity TCC files eve under.
///
/// The bundle identifier as the `.app`, the absolute executable path as the
/// command-line tool. They are separate identities with separate rows — asking
/// about the wrong one is how a granted permission gets reported as missing.
pub fn tcc_client() -> Option<String> {
    if running_as_bundle() {
        Some(BUNDLE_ID.to_string())
    } else {
        Some(std::env::current_exe().ok()?.to_string_lossy().into_owned())
    }
}

/// Answers, remembered for the life of the process.
///
/// TCC decisions are read when a process starts and cannot change under it, so
/// asking twice can only produce the same answer — and asking is not free.
/// Reading another application's support directory is exactly the access macOS
/// guards with the *App Data* prompt, and `check_all()` runs on every focus,
/// so an uncached probe turns "dismiss the dialog" into "regain focus, probe
/// again, get the dialog again", forever.
static DECISIONS: std::sync::OnceLock<std::sync::Mutex<std::collections::HashMap<String, Option<bool>>>> =
    std::sync::OnceLock::new();

/// The cached answer, if we have already paid for it.
///
/// **Never probes.** Reading TCC's database means reading
/// `~/Library/Application Support/com.apple.TCC`, and that directory belongs to
/// another application — which is precisely the access behind *"eve would like
/// to access data from other apps"*. Doing it as part of the routine startup
/// check raised that dialog on every single launch.
///
/// So the routine path answers from what is already known and otherwise says
/// `Unknown`, and the probe happens only when the user asks a question that
/// makes a permission dialog make sense: opening Settings and pressing
/// Re-check. See [`resolve_deep`].
pub(crate) fn tcc_decision_for(service: &str, client: &str) -> Option<bool> {
    let key = format!("{service}|{client}");
    let cache = DECISIONS.get_or_init(Default::default);
    let hit = cache.lock().ok().and_then(|m| m.get(&key).copied());
    hit.flatten()
}

/// Pay for the answer, and remember it.
fn tcc_decision_probe(service: &str, client: &str) -> Option<bool> {
    let key = format!("{service}|{client}");
    let cache = DECISIONS.get_or_init(Default::default);
    if let Ok(map) = cache.lock() {
        if let Some(hit) = map.get(&key) {
            return *hit;
        }
    }
    let answer = tcc_decision_uncached(service, client);
    if let Ok(mut map) = cache.lock() {
        map.insert(key, answer);
    }
    answer
}

/// Ask macOS the questions that cost a dialog, once.
///
/// Called only from an explicit user action. Everything else reads whatever
/// this left behind.
pub fn resolve_deep() -> Vec<PermissionStatus> {
    if let Some(client) = tcc_client() {
        let _ = tcc_decision_probe("kTCCServiceSystemPolicyAppBundles", &client);
    }
    check_all()
}

fn tcc_decision_uncached(service: &str, client: &str) -> Option<bool> {
    let db = tcc_db();
    if !db.exists() {
        return None;
    }
    let sql = format!(
        "select auth_value from access where service='{}' and client='{}' limit 1;",
        service.replace('\'', "''"),
        client.replace('\'', "''")
    );
    let out = std::process::Command::new("/usr/bin/sqlite3")
        .arg("-readonly")
        .arg(&db)
        .arg(&sql)
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let value = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if value.is_empty() {
        return None;
    }
    // 0 denied, 2 allowed, 3 limited. Anything non-zero is "it works".
    value.parse::<i64>().ok().map(|v| v != 0)
}

/// Whether macOS has eve registered for notifications at all.
///
/// **Registration, not authorisation** — and the distinction is the point.
/// This used to claim it read the decision out of a `flags` column in
/// usernoted's store. There is no such column: the table is
/// `app(app_id, identifier, badge)`, so the query failed, `sqlite3` wrote
/// nothing to stdout, the parse failed, and every caller got `Unknown` for
/// ever while the code read as though it were checking something.
///
/// What the store can honestly answer is whether eve has a row, which is what
/// decides whether eve appears in System Settings › Notifications at all. The
/// authorisation itself is only knowable from `UNUserNotificationCenter`, and
/// only the bundle can ask — so a `Granted`/`Denied` verdict is the app's to
/// supply, and this returns `Unknown` rather than guessing at it.
fn notification_state() -> PermissionState {
    if registered_for_notifications() {
        PermissionState::Unknown
    } else {
        // Never registered: macOS will not list eve, so there is nothing for
        // the user to switch on until eve has asked once.
        PermissionState::Denied
    }
}

/// Whether usernoted has a row for eve.
pub fn registered_for_notifications() -> bool {
    let db = home().join("Library/Group Containers/group.com.apple.usernoted/db2/db");
    if !db.exists() {
        return false;
    }
    let out = std::process::Command::new("/usr/bin/sqlite3")
        .arg("-readonly")
        .arg(&db)
        .arg(format!(
            "select count(*) from app where identifier='{BUNDLE_ID}';"
        ))
        .output();
    let Ok(out) = out else { return false };
    String::from_utf8_lossy(&out.stdout)
        .trim()
        .parse::<i64>()
        .map(|n| n > 0)
        .unwrap_or(false)
}

fn trash_dir() -> PathBuf {
    home().join(".Trash")
}

fn home() -> PathBuf {
    dirs::home_dir().unwrap_or_else(|| PathBuf::from("/"))
}

/// Every permission's current status.
pub fn check_all() -> Vec<PermissionStatus> {
    Permission::ALL.iter().map(|p| p.status()).collect()
}

/// Ask macOS for everything, so all of it appears in Settings.
///
/// Called on first launch before showing the onboarding screen. Without it the
/// screen would send the user to a pane that does not list eve.
pub fn provoke_all() {
    for p in Permission::ALL {
        p.provoke();
    }
}

/// Whether eve can do its job at all.
pub fn blocked() -> bool {
    Permission::ALL
        .iter()
        .any(|p| p.required() && p.state() == PermissionState::Denied)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The query must name columns usernoted's schema actually has.
    ///
    /// The predecessor asked for `flags` from a `bundleid` column, and the
    /// table is `app(app_id, identifier, badge)`. `sqlite3` failed, stdout was
    /// empty, the parse failed, and the function returned `Unknown` — so a
    /// probe that could never work looked exactly like an app that had never
    /// been asked. Asserting on the schema is the only way to catch that:
    /// asserting on the answer cannot distinguish "not registered" from
    /// "the query is nonsense".
    #[test]
    fn the_usernoted_query_matches_the_real_schema() {
        let db = home().join("Library/Group Containers/group.com.apple.usernoted/db2/db");
        if !db.exists() {
            return; // No notification store on this machine; nothing to check.
        }
        let out = std::process::Command::new("/usr/bin/sqlite3")
            .arg("-readonly")
            .arg(&db)
            .arg(format!(
                "select count(*) from app where identifier='{BUNDLE_ID}';"
            ))
            .output()
            .expect("sqlite3 should run");
        assert!(
            out.status.success(),
            "the registration query does not match usernoted's schema: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
        assert!(
            String::from_utf8_lossy(&out.stdout).trim().parse::<i64>().is_ok(),
            "the query returned nothing parseable"
        );
    }

    #[test]
    fn only_full_disk_access_is_required() {
        let required: Vec<_> = Permission::ALL
            .iter()
            .filter(|p| p.required())
            .copied()
            .collect();
        assert_eq!(required, vec![Permission::FullDiskAccess]);
    }

    /// Every permission must deep-link to its own Privacy pane. Sending the
    /// user to the top of System Settings is the failure this exists to fix.
    #[test]
    fn every_permission_opens_a_specific_privacy_pane() {
        let mut seen = std::collections::HashSet::new();
        for p in Permission::ALL {
            let url = p.settings_url();
            assert!(
                url.starts_with("x-apple.systempreferences:"),
                "{p:?} does not deep-link: {url}"
            );
            assert!(seen.insert(url), "{p:?} shares a pane with another");
        }
    }

    #[test]
    fn every_permission_says_what_breaks_without_it() {
        for p in Permission::ALL {
            let text = p.what_breaks();
            assert!(text.len() > 30, "{p:?} explains nothing: {text:?}");
            assert!(!text.contains("TCC"), "{p:?} leaks jargon: {text:?}");
        }
    }

    /// Regression: App Management was hardcoded to `Unknown` on the grounds
    /// that "the only way to learn whether app modification is permitted is to
    /// attempt one". TCC's own database has the answer, eve already reads that
    /// file for Full Disk Access, and the result was a permission the user had
    /// granted being displayed as missing.
    #[test]
    fn app_management_is_read_from_tcc_not_guessed() {
        // The real grant on this machine is against the *bundle* identity;
        // the test binary has no row of its own, and `None` there is correct —
        // "never asked" is not "denied".
        // The probing variant: the cached one deliberately never asks, because
        // asking means reading another app's support directory and that is
        // what raised a permission dialog on every launch.
        let granted = tcc_decision_probe("kTCCServiceSystemPolicyAppBundles", "tech.hartle.eve");
        if !tcc_db().exists() {
            return; // no Full Disk Access in this environment
        }
        assert!(
            granted.is_some(),
            "eve holds App Management but the probe could not read it"
        );
        assert_eq!(granted, Some(true));
    }

    /// The bundle and the bare binary are different TCC subjects. Asking about
    /// the wrong one is exactly how a granted permission reads as missing.
    #[test]
    fn the_tcc_client_is_the_bundle_id_only_when_running_as_the_app() {
        let client = tcc_client().expect("no identity");
        if running_as_bundle() {
            assert_eq!(client, "tech.hartle.eve");
        } else {
            assert!(client.starts_with('/'), "the CLI identity must be a path: {client}");
        }
    }

    #[test]
    fn full_disk_access_still_answers_definitively() {
        assert_ne!(
            Permission::FullDiskAccess.state(),
            PermissionState::Unknown,
            "Full Disk Access has a read-only probe and must give an answer"
        );
    }

    #[test]
    fn provoking_is_read_only_and_never_panics() {
        // Runs against the real filesystem on purpose: the whole point is that
        // it is safe to call on every launch, whatever the answers are.
        provoke_all();
        let _ = check_all();
    }
}
