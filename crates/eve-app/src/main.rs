//! The eve desktop application.
//!
//! A thin shell over the same engines the CLI uses. No cleaning logic lives
//! here — the app builds the same `Selection` and calls the same `Cleaner`, so
//! the safety funnel cannot be bypassed by coming in through the window
//! instead of the terminal.

// Do not spawn a console window alongside the app on Windows. Harmless on
// macOS, and keeps the target open.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::time::Duration;

use eve_core::journal::{Journal, JournalEntry};
use eve_core::liveness::Liveness;
use eve_core::policy::Policy;
use eve_core::prefs::{Preferences, TrashExclusions};
use eve_core::privilege::SudoWorker;
use eve_engines::analyze::Analysis;
use eve_engines::clean::{CleanReport, Cleaner, Selection};
use eve_engines::status::Status;
use eve_engines::{analyze, status};
use serde::Deserialize;

mod notify;

/// What the UI sends when the user presses Clean or Rescan.
#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Request {
    #[serde(default)]
    skip: Vec<String>,
    #[serde(default)]
    include: Vec<String>,
    #[serde(default)]
    privileged: bool,
}

impl Request {
    fn selection(&self, prefs: &Preferences) -> Selection {
        Selection {
            // The user's stored choices, plus anything this request skipped.
            // Read from preferences rather than the request so the window and
            // the unattended agent cannot disagree about which categories are
            // off — the 3am run is the one that broke things.
            skip: prefs
                .disabled_categories
                .iter()
                .cloned()
                .chain(self.skip.iter().cloned())
                .collect(),
            include: self.include.clone(),
            allow_privileged: self.privileged,
            // A window on screen means a human is present, so the unattended
            // tier gate does not apply. Destructive tiers still require the
            // user to opt in explicitly.
            unattended: false,
            only: Vec::new(),
            // Read from the stored settings rather than from the request. The
            // window is one of four callers; if it could send its own value,
            // the checkbox and the LaunchAgent would disagree the moment they
            // drifted, and the user would have no way to tell which won.
            empty_trash: prefs.empty_trash,
            empty_trash_at: prefs.empty_trash_at,
            permanent_delete: prefs.permanent_delete,
        }
    }
}

fn policy() -> Policy {
    // Locks are part of the policy, not an afterthought applied by whoever
    // remembered: every caller builds the policy here, so a locked directory
    // is locked for the window, the CLI and the unattended run alike.
    let locks = Preferences::load_default().unwrap_or_default().locked_paths;
    Policy::current().with_default_whitelist().with_locks(locks)
}

/// The stored settings, or defaults if the file will not parse.
///
/// The window reports the problem through [`preferences`], which returns the
/// error; this is the fallback the engine calls use so that a broken file
/// degrades to "do less", never to "delete more".
fn stored_prefs() -> Preferences {
    Preferences::load_default().unwrap_or_default()
}

/// The current settings, or the reason they could not be read.
#[tauri::command]
fn preferences() -> Result<Preferences, String> {
    Preferences::load_default()
}

/// Every exclusion in effect and where it came from, so the window can show
/// the built-ins without pretending the user can remove them.
/// Switch one category on or off, durably.
#[tauri::command]
fn set_category_enabled(key: String, enabled: bool) -> Result<Preferences, String> {
    let mut prefs = Preferences::load_default().unwrap_or_default();
    prefs.set_category(&key, enabled);
    prefs.save_default()?;
    Ok(prefs)
}

/// Every category eve knows about, with whether it is on.
#[derive(serde::Serialize)]
pub struct CategoryInfo {
    pub key: String,
    pub title: String,
    pub description: String,
    pub group: String,
    pub tier: String,
    pub enabled: bool,
    /// On by default for its tier — so the UI can show what "off" is relative to.
    pub default_on: bool,
}

#[tauri::command]
fn categories() -> Vec<CategoryInfo> {
    let prefs = stored_prefs();
    eve_catalog::catalog()
        .into_iter()
        .map(|c| CategoryInfo {
            key: c.key.to_string(),
            title: c.title.to_string(),
            description: c.description.to_string(),
            group: c.group.title().to_string(),
            tier: c.tier.as_str().to_string(),
            enabled: !prefs.is_disabled(c.key) && c.on_by_default(),
            default_on: c.on_by_default(),
        })
        .collect()
}

/// Add an exclusion. Every entry is the user's, including the seeded ones.
#[tauri::command]
fn add_trash_exclusion(pattern: String) -> Result<Vec<(String, String)>, String> {
    let mut prefs = Preferences::load_default().unwrap_or_default();
    prefs.exclude_trash(&pattern)?;
    prefs.save_default()?;
    Ok(prefs
        .effective_trash_exclusions()
        .into_iter()
        .map(|(p, s)| (p, s.to_string()))
        .collect())
}

/// Remove an exclusion — any of them, including one eve suggested or added.
#[tauri::command]
fn remove_trash_exclusion(pattern: String) -> Result<Vec<(String, String)>, String> {
    let mut prefs = Preferences::load_default().unwrap_or_default();
    prefs.unexclude_trash(&pattern);
    prefs.save_default()?;
    Ok(prefs
        .effective_trash_exclusions()
        .into_iter()
        .map(|(p, s)| (p, s.to_string()))
        .collect())
}

/// Directories the user has locked.
#[tauri::command]
fn locked_paths() -> Vec<String> {
    stored_prefs().locked_paths
}

/// Lock or unlock a directory. Nothing inside a locked one is ever removed.
#[tauri::command]
fn set_locked(path: String, locked: bool) -> Result<Vec<String>, String> {
    let mut prefs = Preferences::load_default().unwrap_or_default();
    prefs.set_locked(&path, locked);
    prefs.save_default()?;
    Ok(prefs.locked_paths)
}

/// Empty the history, and say how much went.
#[tauri::command]
async fn clear_history() -> Result<usize, String> {
    off_main(|| {
        Journal::open_default()
            .and_then(|j| j.clear())
            .map_err(|e| e.to_string())
    })
    .await?
}

#[tauri::command]
fn trash_exclusions() -> Vec<(String, String)> {
    stored_prefs()
        .effective_trash_exclusions()
        .into_iter()
        .map(|(pattern, source)| (pattern, source.to_string()))
        .collect()
}

/// Replace the stored settings.
///
/// Takes the fields rather than a whole `Preferences` so every pattern goes
/// through `exclude_trash` and is validated as a glob. A pattern that does not
/// compile is rejected here rather than stored and silently never matched.
#[tauri::command]
#[allow(clippy::too_many_arguments)]
fn set_preferences(
    direct_cleanup: bool,
    threshold_gb: u64,
    cooldown_sec: u64,
    trash_exclusions: Vec<String>,
) -> Result<Preferences, String> {
    if threshold_gb == 0 {
        // Refused here as well as in the CLI. A window is exactly where a
        // stray keystroke produces a 0, and a threshold of 0 never fires —
        // the agent would go quiet and look like it had simply stopped.
        return Err("a 0 GB threshold would never fire".into());
    }
    let mut prefs = Preferences {
        threshold_gb,
        cooldown_sec,
        trash_exclusions: Vec::new(),
        ..Preferences::default()
    };
    // One question, three fields. The window asks it once; the engine keeps
    // the parts, so exclusions, sweep timing and tier scoping stay available
    // without the settings pane turning into a form.
    prefs.set_direct_cleanup(direct_cleanup);
    for pattern in trash_exclusions {
        prefs
            .exclude_trash(&pattern)
            .map_err(|e| format!("{pattern:?} is not a valid pattern: {e}"))?;
    }
    prefs.save_default()?;
    Ok(prefs)
}

/// Run a blocking job off the main thread.
///
/// Tauri runs a *synchronous* command on the main thread, which is the thread
/// driving the webview — so a multi-second filesystem walk does not merely
/// take a few seconds, it freezes the window and queues every click behind
/// it. That is the entire explanation for "toggles take seconds to register":
/// the toggle's own IPC was waiting behind a scan.
///
/// Anything that touches the disk goes through here.
async fn off_main<T, F>(job: F) -> Result<T, String>
where
    F: FnOnce() -> T + Send + 'static,
    T: Send + 'static,
{
    tauri::async_runtime::spawn_blocking(job)
        .await
        .map_err(|e| format!("background task failed: {e}"))
}

#[tauri::command]
async fn scan(request: Request) -> Result<CleanReport, String> {
    off_main(move || scan_blocking(request)).await
}

fn scan_blocking(request: Request) -> CleanReport {
    let policy = policy();
    let liveness = Liveness::snapshot();
    let prefs = stored_prefs();
    let cleaner = Cleaner::new(&policy, &liveness)
        .with_trash_exclusions(TrashExclusions::compile(&prefs));
    cleaner.scan(&eve_catalog::catalog(), &request.selection(&prefs))
}

#[tauri::command]
async fn clean(request: Request) -> Result<CleanReport, String> {
    off_main(move || clean_blocking(request)).await
}

fn clean_blocking(request: Request) -> CleanReport {
    let policy = policy();
    let liveness = Liveness::snapshot();
    let journal = Journal::open_default().ok();
    let prefs = stored_prefs();
    let mut cleaner = Cleaner::new(&policy, &liveness)
        .with_trash_exclusions(TrashExclusions::compile(&prefs));
    if let Some(j) = &journal {
        cleaner = cleaner.with_journal(j);
    }
    let catalog = eve_catalog::catalog();

    // The worker is created per invocation and dropped at the end of it, so
    // root exists only for the duration of the clean the user asked for.
    let mut broker = request.privileged.then(SudoWorker::interactive);
    let sel = request.selection(&prefs);
    let mut report = match broker.as_mut() {
        Some(b) => cleaner.execute(&catalog, &sel, Some(b)),
        None => cleaner.execute(&catalog, &sel, None),
    };
    // Anything this run proved undeletable becomes an exclusion, so the next
    // sweep skips it rather than failing on it for ever. Done here, in the
    // user's own process — the privileged worker has a different home.
    report.newly_excluded = eve_engines::clean::learn_undeletable(&report);
    report
}

#[tauri::command]
async fn system_status() -> Result<Status, String> {
    off_main(status::collect).await
}

/// A page of history, newest first.
///
/// The journal is append-only and already past thirteen thousand entries on a
/// machine that has been running eve for a fortnight. Serialising all of it
/// across IPC to render a list nobody scrolls to the bottom of is a cost paid
/// on every visit to the History view.
#[tauri::command]
async fn history(offset: usize, limit: usize) -> Result<HistoryPage, String> {
    off_main(move || {
        let all = Journal::open_default()
            .and_then(|j| j.read_all())
            .unwrap_or_default();
        let total = all.len();
        // Newest first, which is the only order anybody wants.
        let entries = all
            .into_iter()
            .rev()
            .skip(offset)
            .take(limit.clamp(1, 5_000))
            .collect();
        HistoryPage { entries, total }
    })
    .await
}

#[derive(serde::Serialize)]
pub struct HistoryPage {
    pub entries: Vec<JournalEntry>,
    pub total: usize,
}

#[tauri::command]
async fn disk_analysis(path: Option<String>) -> Result<Analysis, String> {
    off_main(move || {
        let root = path.map(std::path::PathBuf::from).unwrap_or_else(dirs_home);
        analyze::analyze(&root, Duration::from_secs(45))
    })
    .await
}

fn dirs_home() -> std::path::PathBuf {
    std::env::var_os("HOME")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::PathBuf::from("/"))
}

/// The active whitelist, so the UI can show what is protected and why.
#[tauri::command]
fn whitelist() -> Vec<(String, String)> {
    policy()
        .whitelist_patterns()
        .into_iter()
        .map(|(p, s)| (p.to_string(), s.to_string()))
        .collect()
}

/// What macOS is currently allowing, for the onboarding screen and for the
/// warning triangles beside the features each one gates.
#[tauri::command]
fn permissions() -> Vec<eve_core::permissions::PermissionStatus> {
    with_real_notification_state(eve_core::permissions::check_all())
}

/// Replace the notification row with what `UNUserNotificationCenter` says.
///
/// eve-core reads usernoted's store, which only has a row once the app has
/// registered — accurate but useless before the first ask. The app can ask the
/// framework directly, and it is the only caller that can.
fn with_real_notification_state(
    mut all: Vec<eve_core::permissions::PermissionStatus>,
) -> Vec<eve_core::permissions::PermissionStatus> {
    use eve_core::permissions::{Permission, PermissionState};
    let real = match notify::status() {
        notify::Authorization::Granted => Some(PermissionState::Granted),
        notify::Authorization::Denied => Some(PermissionState::Denied),
        notify::Authorization::NotDetermined => Some(PermissionState::Unknown),
        notify::Authorization::Unavailable => None,
    };
    if let Some(state) = real {
        for p in &mut all {
            if p.permission == Permission::Notifications {
                p.state = state;
            }
        }
    }
    all
}

/// Ask macOS for notification permission, and report what it said.
///
/// Goes straight to `UNUserNotificationCenter`. The Tauri plugin answers
/// `Granted` without ever asking and never registers the app, so eve was absent
/// from System Settings › Notifications entirely and the permission could not
/// be granted even deliberately.
///
/// Two shapes, because macOS only shows the dialog once in the lifetime of an
/// installation:
///
/// * never asked — raise the prompt and wait for the answer;
/// * already answered — no dialog will ever appear again, so open System
///   Settings at eve's own row instead. Sitting there waiting for a prompt
///   macOS has no intention of showing is exactly what "Ask me now does not
///   pop the notification permission request" looked like from outside.
#[tauri::command]
async fn request_notifications(
    app: tauri::AppHandle,
) -> Result<eve_core::permissions::PermissionState, String> {
    use eve_core::permissions::PermissionState;

    if !notify::can_still_ask() {
        open_notification_settings();
        return Ok(match notify::status() {
            notify::Authorization::Granted => PermissionState::Granted,
            notify::Authorization::Denied => PermissionState::Denied,
            _ => PermissionState::Unknown,
        });
    }

    let (tx, rx) = std::sync::mpsc::channel();
    // The call goes on the main thread; the wait does not. Doing both there
    // holds the run loop and the dialog never draws.
    app.run_on_main_thread(move || notify::begin_request(tx))
        .map_err(|e| format!("could not reach the main thread: {e}"))?;

    let answer = rx
        .recv_timeout(std::time::Duration::from_secs(65))
        .map_err(|_| "macOS did not answer the permission request".to_string())?;

    Ok(match answer {
        notify::Authorization::Granted => PermissionState::Granted,
        notify::Authorization::Denied => PermissionState::Denied,
        _ => PermissionState::Unknown,
    })
}

/// Open System Settings at eve's own Notifications row.
///
/// The `?id=` query is what selects the app. Without it the pane opens on the
/// full alphabetical list and the user has to go and find eve in it, which is
/// the difference between a link and a hint.
fn open_notification_settings() {
    let url = format!(
        "x-apple.systempreferences:com.apple.Notifications-Settings.extension?id={}",
        eve_core::permissions::BUNDLE_ID
    );
    let _ = std::process::Command::new("/usr/bin/open").arg(url).status();
}

/// Re-ask, then re-check.
///
/// Called when the window regains focus after a trip to System Settings. The
/// re-ask matters on a first run where the user granted the permission before
/// eve had ever requested it.
#[tauri::command]
fn recheck_permissions() -> Vec<eve_core::permissions::PermissionStatus> {
    // The one place that pays for a TCC probe.
    //
    // Reaching TCC's database means reading another app's support directory,
    // which is what raises "eve would like to access data from other apps".
    // Doing it on every startup check asked on every launch; doing it here
    // asks at the only moment a permission dialog makes sense — the user is
    // looking at the permissions list and pressed Re-check.
    //
    // Deliberately does **not** re-provoke.
    //
    // Provoking is a first-run affordance: one attempted access so macOS lists
    // eve in the Privacy pane with the switch off, instead of asking the user
    // to find a binary in a hidden directory. Re-provoking on every re-check is
    // a different thing entirely — this runs whenever the window regains
    // focus, including the moment a TCC dialog is dismissed, so it re-triggers
    // the very access that raised the dialog and raises it again. That is the
    // loop behind "eve keeps forever asking for permission to access other
    // apps; I keep granting it and it never holds".
    with_real_notification_state(eve_core::permissions::resolve_deep())
}

/// Open the Privacy pane for one specific permission.
#[tauri::command]
fn open_privacy_settings(permission: eve_core::permissions::Permission) -> Result<(), String> {
    // Provoked first so eve is definitely listed by the time the pane opens.
    // Opening a pane that does not mention eve is worse than not opening one.
    permission.provoke();
    std::process::Command::new("/usr/bin/open")
        .arg(permission.settings_url())
        .status()
        .map_err(|e| format!("could not open System Settings: {e}"))?;
    Ok(())
}

/// One directory, biggest first.
#[tauri::command]
async fn browse(path: Option<String>) -> Result<eve_engines::browse::BrowseResult, String> {
    off_main(move || {
        let root = path.map(std::path::PathBuf::from).unwrap_or_else(dirs_home);
        eve_engines::browse::browse(&root)
    })
    .await?
}

/// What happened to one path the user picked.
///
/// A purpose-built shape rather than the raw `FunnelReport`, because the
/// window kept getting the same question wrong: a report with no `denial` is
/// one the *funnel* allowed, which is not the same as one that happened. The
/// executor refuses too — an unavailable Trash, a tree holding something macOS
/// will never delete — and those arrive afterwards. Here there is one field
/// for whether it worked and one for why it did not.
#[derive(serde::Serialize)]
pub struct DeleteOutcome {
    pub path: String,
    pub bytes: u64,
    pub ok: bool,
    pub problem: Option<String>,
}

/// Forget the remembered sizes for one directory, so the next listing
/// measures its children again.
#[tauri::command]
fn refresh_sizes(path: String) {
    eve_engines::browse::refresh(std::path::Path::new(&path));
}

/// Delete paths the user picked in the browser.
///
/// Through the funnel, like everything else. A hand-picked path is precisely
/// the case the protection policy, the whitelist and the live-owner check
/// exist for — a browser that deleted directly would be the one entry point in
/// eve where an arbitrary path skipped every gate.
#[tauri::command]
async fn delete_paths(paths: Vec<String>) -> Result<Vec<DeleteOutcome>, String> {
    off_main(move || {
        let targets: Vec<std::path::PathBuf> =
            paths.into_iter().map(std::path::PathBuf::from).collect();
        let ops = eve_engines::browse::to_operations(&targets);
        let policy = policy();
        let liveness = Liveness::snapshot();
        let journal = Journal::open_default().ok();
        let executor = eve_core::executor::Executor::live();
        let mut funnel = eve_core::funnel::Funnel::new(&policy, &liveness, &executor);
        if let Some(j) = &journal {
            funnel = funnel.with_journal(j);
        }
        let reports = funnel.run_all(&ops);
        // The browser remembers sizes so that walking back up is instant. A
        // deletion is the one event that makes a remembered size wrong, and it
        // is wrong for every directory above it as well.
        for r in reports.iter().filter(|r| r.succeeded()) {
            eve_engines::browse::forget(&r.path);
        }
        reports
            .into_iter()
            .map(|r| DeleteOutcome {
                path: r.path.display().to_string(),
                bytes: r.bytes(),
                ok: r.succeeded(),
                problem: r.problem(),
            })
            .collect()
    })
    .await
}

/// Everything installed, classified.
///
/// `include_system` is off by default: the sealed system volume holds nearly
/// two hundred bundles, none of them removable by anyone, and walking 4 GB of
/// it to draw a list nobody can act on is not what the screen should cost to
/// open. The Applications view asks for them when that section is expanded.
#[tauri::command]
async fn list_apps(include_system: Option<bool>) -> Result<Vec<eve_engines::uninstall::App>, String> {
    off_main(move || {
        eve_engines::uninstall::list_apps_with_system(&[], include_system.unwrap_or(false))
    })
    .await
}

#[derive(serde::Serialize)]
pub struct UninstallBatch {
    pub apps: Vec<UninstallSummary>,
    pub reports: Vec<eve_core::FunnelReport>,
    /// What the plan came to. A forecast, not a result.
    pub total_bytes: u64,
    /// What was actually removed.
    ///
    /// The window used to show `total_bytes` under the heading "Removed",
    /// which was true only when nothing had gone wrong. With `/Applications`
    /// refusing every bundle, the screen cheerfully reported the full size of
    /// an app that was still sitting in the Dock — the user's whole reason for
    /// believing the uninstaller did nothing was that it *said* it had.
    pub freed_bytes: u64,
    /// Why anything did not happen, in the user's words rather than a path.
    pub problems: Vec<String>,
    pub executed: bool,
}

#[derive(serde::Serialize)]
pub struct UninstallSummary {
    pub name: String,
    pub path: String,
    pub bytes: u64,
    pub items: usize,
    /// The system owns this bundle. Known before the attempt, so the window
    /// can say so instead of letting the removal appear to fail.
    pub needs_admin: bool,
}

/// Preview or perform a batch removal.
///
/// `execute: false` is the preview and touches nothing, which is what the
/// typed confirmation is shown against — the same contract as `eve clean`.
#[tauri::command]
async fn uninstall_apps(
    paths: Vec<String>,
    execute: bool,
    privileged: bool,
) -> Result<UninstallBatch, String> {
    off_main(move || {
        let home = dirs_home();
        let installed = eve_engines::uninstall::list_apps(&[]);
        let mut summaries = Vec::new();
        let mut ops = Vec::new();
        let mut total = 0u64;

        for p in &paths {
            let Some(app) = installed.iter().find(|a| a.path.to_string_lossy() == *p) else {
                continue;
            };
            let plan = eve_engines::uninstall::plan(app, &home);
            let plan_ops = eve_engines::uninstall::plan_to_operations(&plan);
            total += plan.total_bytes;
            summaries.push(UninstallSummary {
                name: plan.app.name.clone(),
                path: p.clone(),
                bytes: plan.total_bytes,
                items: plan_ops.len(),
                needs_admin: plan.app.needs_admin,
            });
            ops.extend(plan_ops);
        }

        // The system owns some bundles, and POSIX will not let this user move
        // a directory they cannot write into a different parent. Root can, and
        // the macOS administrator dialog is a prompt a window is allowed to
        // raise — so the window offers it instead of telling the user to go
        // and find a terminal.
        let reports = if execute && privileged {
            use eve_core::privilege::PrivilegeBroker;
            let mut broker = eve_core::privilege::AdminPrompt::new(
                "eve needs administrator rights to remove an application the system owns.",
            );
            match broker.execute(&eve_core::privilege::Plan::new(ops.clone()).dry_run(false)) {
                Ok(r) => r,
                // A refusal to authenticate is an answer, not a crash: report
                // it against every operation the user asked for.
                Err(e) => ops
                    .iter()
                    .map(|op| eve_core::FunnelReport {
                        path: op.path.clone(),
                        category: op.category.clone(),
                        tier: op.tier,
                        denial: None,
                        outcome: Some(eve_core::executor::ExecOutcome {
                            path: op.path.clone(),
                            disposition: op.disposition,
                            bytes: 0,
                            files: 0,
                            complete: true,
                            dry_run: false,
                            error: Some(e.to_string()),
                            failures: Vec::new(),
                            permanently_stuck: Vec::new(),
                        }),
                    })
                    .collect(),
            }
        } else {
            let policy = policy();
            let liveness = Liveness::snapshot();
            let journal = Journal::open_default().ok();
            let executor = if execute {
                eve_core::executor::Executor::live()
            } else {
                eve_core::executor::Executor::dry_run()
            };
            let mut funnel = eve_core::funnel::Funnel::new(&policy, &liveness, &executor);
            if let Some(j) = &journal {
                funnel = funnel.with_journal(j);
            }
            funnel.run_all(&ops)
        };
        let freed = reports.iter().filter(|r| r.succeeded()).map(|r| r.bytes()).sum();
        let problems = reports.iter().filter_map(|r| r.problem()).collect();
        // Removing an app changes the size of /Applications and of every
        // directory a leftover lived in.
        for r in reports.iter().filter(|r| r.succeeded()) {
            eve_engines::browse::forget(&r.path);
        }

        UninstallBatch {
            reports,
            apps: summaries,
            total_bytes: total,
            freed_bytes: freed,
            problems,
            executed: execute,
        }
    })
    .await
}

/// Show a path in Finder, selected.
///
/// `open -R` reveals *and* selects, which is the difference between landing in
/// the right folder and landing on the right item.
#[tauri::command]
fn reveal_in_finder(path: String) -> Result<(), String> {
    std::process::Command::new("/usr/bin/open")
        .arg("-R")
        .arg(&path)
        .status()
        .map_err(|e| format!("could not reveal {path}: {e}"))?;
    Ok(())
}

/// Open a terminal at this location.
///
/// A file opens its containing directory — `cd` into a file is not a thing,
/// and silently doing nothing would be worse than picking the obvious parent.
#[tauri::command]
fn reveal_in_terminal(path: String) -> Result<(), String> {
    let p = std::path::PathBuf::from(&path);
    let dir = if p.is_dir() {
        p.clone()
    } else {
        p.parent().map(std::path::Path::to_path_buf).unwrap_or(p)
    };
    // Whichever terminal the user actually uses: `open -a` respects the
    // default handler for the directory only if we name an app, so try iTerm
    // and fall back to Terminal.
    let iterm = std::process::Command::new("/usr/bin/open")
        .args(["-a", "iTerm"])
        .arg(&dir)
        .status();
    if matches!(&iterm, Ok(s) if s.success()) {
        return Ok(());
    }
    std::process::Command::new("/usr/bin/open")
        .args(["-a", "Terminal"])
        .arg(&dir)
        .status()
        .map_err(|e| format!("could not open a terminal at {}: {e}", dir.display()))?;
    Ok(())
}

#[derive(serde::Serialize)]
pub struct Holder {
    pub pid: i32,
    pub name: String,
}

/// Which processes are holding something under this path open.
///
/// This is what turns "owner still running" from a dead end into something the
/// user can act on: eve already refuses to delete a directory somebody has
/// open, and the obvious next question is *who*.
#[tauri::command]
async fn owning_processes(path: String) -> Result<Vec<Holder>, String> {
    off_main(move || {
        // `+D` walks the tree, so it is bounded: a deep directory must not
        // hang the window while lsof enumerates every descendant.
        let out = std::process::Command::new("/usr/sbin/lsof")
            .args(["-nP", "-Fpcn", "+D"])
            .arg(&path)
            .output();
        let Ok(out) = out else {
            return Vec::new();
        };
        let text = String::from_utf8_lossy(&out.stdout);

        let mut holders: Vec<Holder> = Vec::new();
        let mut pid = 0i32;
        for line in text.lines() {
            match line.as_bytes().first() {
                Some(b'p') => pid = line[1..].parse().unwrap_or(0),
                Some(b'c') => {
                    let name = line[1..].to_string();
                    if pid > 0 && !holders.iter().any(|h| h.pid == pid) {
                        holders.push(Holder { pid, name });
                    }
                }
                _ => {}
            }
        }
        holders
    })
    .await
}

/// Ask a process to quit.
///
/// `SIGTERM`, not `SIGKILL`: the point is to let go of the files eve wants to
/// remove, and a process given the chance to exit cleanly closes its databases
/// properly instead of leaving the half-written state this tool then has to
/// reason about.
#[tauri::command]
fn kill_process(pid: i32) -> Result<(), String> {
    if pid <= 1 {
        return Err("refusing to signal that process".into());
    }
    // SAFETY: `kill` with a validated positive pid and a standard signal.
    let rc = unsafe { libc::kill(pid, libc::SIGTERM) };
    if rc != 0 {
        return Err(format!(
            "could not stop process {pid}: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}

/// Which running apps are holding the Trash open, and what it costs.
///
/// Reframed after testing the premise. "macOS will not let you empty the
/// Trash while an app is running" is **not** what happens: POSIX unlinks an
/// open file quite happily — the directory entry goes and the inode survives
/// until the last handle closes. Two things are true instead, and both are
/// worth saying:
///
/// 1. **The space is not returned** until the holder lets go, so a sweep can
///    report bytes the disk does not get back yet.
/// 2. **eve's own liveness gate refuses those entries**, deliberately, because
///    deleting a file out from under a running program is how you corrupt a
///    database that is mid-write.
///
/// So the warning names the apps to quit rather than claiming macOS will
/// refuse — and quitting them is genuinely what makes the sweep complete.
#[tauri::command]
async fn trash_blockers() -> Result<Vec<eve_engines::blockers::Blocker>, String> {
    off_main(|| {
        let trash = dirs_home().join(".Trash");
        eve_engines::blockers::holding(&trash)
    })
    .await
}

/// Containers, VMs and emulators, biggest first.
#[tauri::command]
async fn list_machines() -> Result<Vec<eve_engines::machines::Machine>, String> {
    off_main(|| eve_engines::machines::survey(&dirs_home())).await
}

/// Memory as it is, plus the two things that can change it and what each costs.
#[derive(serde::Serialize)]
pub struct MemoryReport {
    pub snapshot: eve_engines::memory::MemorySnapshot,
    pub boosts: Vec<eve_engines::memory::BoostOption>,
    /// Disk that memory management holds and that nothing can reclaim. Shown
    /// so the space is accounted for, never offered as a deletion.
    pub fixed_costs: Vec<eve_engines::memory::FixedCost>,
}

#[tauri::command]
async fn memory_report() -> Result<MemoryReport, String> {
    off_main(|| MemoryReport {
        snapshot: eve_engines::memory::MemorySnapshot::read(),
        boosts: eve_engines::memory::BOOSTS.to_vec(),
        fixed_costs: eve_engines::memory::fixed_costs(),
    })
    .await
}

/// Run one memory action and report the measured before/after.
///
/// `execute` is false for a look — the same preview contract the cleaning
/// funnel keeps, so the button can say what it would do before it does it.
#[tauri::command]
async fn run_boost(
    key: String,
    execute: bool,
) -> Result<eve_engines::memory::BoostResult, String> {
    use eve_engines::memory::Boost;
    let boost = match key.as_str() {
        "drop_caches" => Boost::DropCaches,
        "force_eviction" => Boost::ForceEviction,
        other => return Err(format!("unknown memory action {other:?}")),
    };
    off_main(move || eve_engines::memory::run(boost, !execute)).await
}

/// Remove selected machine storage, through the funnel like everything else.
#[tauri::command]
async fn remove_machines(paths: Vec<String>, execute: bool) -> Result<Vec<DeleteOutcome>, String> {
    off_main(move || {
        let targets: Vec<std::path::PathBuf> =
            paths.into_iter().map(std::path::PathBuf::from).collect();
        let ops = eve_engines::machines::to_operations(&targets);
        let policy = policy();
        let liveness = Liveness::snapshot();
        let journal = Journal::open_default().ok();
        let executor = if execute {
            eve_core::executor::Executor::live()
        } else {
            eve_core::executor::Executor::dry_run()
        };
        let mut funnel = eve_core::funnel::Funnel::new(&policy, &liveness, &executor);
        if let Some(j) = &journal {
            funnel = funnel.with_journal(j);
        }
        funnel
            .run_all(&ops)
            .into_iter()
            .map(|r| DeleteOutcome {
                path: r.path.display().to_string(),
                bytes: r.bytes(),
                ok: r.succeeded(),
                problem: r.problem(),
            })
            .collect()
    })
    .await
}

#[tauri::command]
fn agent_status() -> eve_core::agent::AgentStatus {
    eve_core::agent::status()
}

/// Install the background agent, pointed at this executable.
#[tauri::command]
fn install_agent() -> Result<eve_core::agent::AgentStatus, String> {
    eve_core::agent::install()?;
    Ok(eve_core::agent::status())
}

#[tauri::command]
fn uninstall_agent() -> Result<eve_core::agent::AgentStatus, String> {
    eve_core::agent::uninstall()?;
    Ok(eve_core::agent::status())
}

/// Restart, so a freshly granted permission is actually in effect.
///
/// TCC decisions are read when a process starts. An app that has just been
/// granted Full Disk Access still cannot use it until it is relaunched, and
/// silently continuing to fail is the single most confusing outcome available
/// at that moment.
#[tauri::command]
fn relaunch(app: tauri::AppHandle) {
    app.restart();
}

fn main() {
    // Before Tauri, before any window.
    //
    // The LaunchAgent's program is this exact executable, not a helper beside
    // it, because macOS grants permissions to a *program* identified by its
    // code signature — a separate helper would need its own Full Disk Access
    // grant, in a second place, which is the experience this whole flow exists
    // to remove. One binary, one signature, one grant.
    //
    // So when launchd invokes it with `autoclean`, it does the unattended run
    // and exits without ever creating a window.
    // The privileged peer, checked before Tauri.
    //
    // `AdminPrompt` elevates *this* executable, so when the window asks macOS
    // for administrator rights the thing that runs as root is this binary with
    // `__worker` on its command line. Without this branch that argument fell
    // straight through to `tauri::Builder::run()` — so authenticating opened a
    // **second eve window** and removed nothing at all. The plan was written,
    // root was granted, and no code ever read it.
    if eve_core::privilege::serve_if_worker(&eve_engines::authorizer::CatalogAuthorizer::build()) {
        return;
    }

    // What *this bundle* is allowed to do, as JSON, without opening a window.
    //
    // The app and the command-line tool are separate TCC identities, so the
    // CLI's answer says nothing about the window's — and "permissions do not
    // show they have been given" is unanswerable without asking the binary
    // that actually holds them.
    // Report the notification permission from the command line, so the
    // registration can be checked without clicking through the window.
    //
    // It reports rather than asks. The dialog is drawn by the main run loop,
    // and this branch runs before Tauri starts one — asking here would return
    // a verdict no user was ever shown, which is precisely the fiction the
    // Tauri plugin was dropped for.
    if std::env::args().nth(1).as_deref() == Some("ask-notifications") {
        println!("status:     {:?}", notify::status());
        println!("can prompt: {}", notify::can_still_ask());
        return;
    }

    if std::env::args().nth(1).as_deref() == Some("permissions") {
        let all = with_real_notification_state(eve_core::permissions::check_all());
        println!("{}", serde_json::to_string_pretty(&all).unwrap_or_default());
        return;
    }

    if std::env::args().nth(1).as_deref() == Some("autoclean") {
        let code = match eve_engines::autoclean::run(&eve_engines::autoclean::Config {
            threshold_gb: None,
            cooldown_sec: None,
            dry_run: false,
        }) {
            Ok(()) => 0,
            Err(e) => {
                eprintln!("eve autoclean: {e}");
                1
            }
        };
        std::process::exit(code);
    }

    // First launch has never asked macOS for anything, so eve is absent from
    // the Privacy lists entirely and "grant Full Disk Access" would mean
    // hunting for a binary in a hidden directory. One attempted read puts it
    // in the list, switched off, ready to be switched on.
    eve_core::permissions::provoke_all();

    tauri::Builder::default()
        .plugin(tauri_plugin_notification::init())
        .setup(|app| {
            // Ask for notifications once, on the first launch that has never
            // asked.
            //
            // The other two permissions can only be *provoked* — eve attempts
            // the access and the user flips a switch in System Settings.
            // Notifications have a real API that raises a real prompt, and
            // until now nothing called it: the request lived behind a button
            // in Settings, so eve had never registered with the notification
            // centre at all and the permission could not be granted even
            // deliberately.
            //
            // `permission_state` answers "already decided?" without asking, so
            // this prompts exactly once and never again — a granted *or*
            // refused answer both count as decided.
            {
                use tauri_plugin_notification::NotificationExt;

                // ⚠ KNOWN NOT TO WORK YET — and left here deliberately,
                // because the next person needs the evidence rather than a
                // clean-looking absence.
                //
                // What was measured, on macOS 15 with tauri-plugin-notification 2:
                //
                // - `permission_state()` answers `Ok(Granted)` without ever
                //   asking anything.
                // - `request_permission()` also answers `Ok(Granted)`
                //   immediately, shows no dialog, and does not register the
                //   app.
                // - Delivering a notification with `.show()`, which is what
                //   normally makes macOS raise the prompt, does not register
                //   it either.
                //
                // The proof is usernoted's own store: 114 applications are
                // registered in
                // `~/Library/Group Containers/group.com.apple.usernoted/db2/db`
                // and eve is not among them, before or after any of the above.
                // So the plugin is not reaching `UNUserNotificationCenter` at
                // all on this platform.
                //
                // The fix is to call `UNUserNotificationCenter` directly
                // through objc2 — `requestAuthorizationWithOptions:` on the
                // main thread — rather than through the plugin. Contained
                // work, but real work, and not worth guessing at.
                //
                // Meanwhile the unattended run still notifies through
                // `osascript`, which works but is attributed to Script Editor
                // rather than to eve. That is why no eve notification
                // permission has ever appeared in System Settings.
                let queued = app.handle().clone();
                let _ = app.handle().run_on_main_thread(move || {
                    if eve_core::permissions::Permission::Notifications.state()
                        != eve_core::permissions::PermissionState::Unknown
                    {
                        return;
                    }
                    let _ = queued
                        .notification()
                        .builder()
                        .title("eve is watching your disk")
                        .body("You will hear from eve only when it reclaims space on its own.")
                        .show();
                });
            }

            // A real NSVisualEffectView behind the window. Painting a flat
            // grey panel and calling it a sidebar is the single clearest
            // giveaway that a Mac app was not written for the Mac: the
            // material has to actually sample and blur what is behind it.
            use tauri::Manager;
            if let Some(window) = app.get_webview_window("main") {
                let _ = window_vibrancy::apply_vibrancy(
                    &window,
                    window_vibrancy::NSVisualEffectMaterial::Sidebar,
                    Some(window_vibrancy::NSVisualEffectState::Active),
                    None,
                );
            }
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            scan,
            clean,
            system_status,
            history,
            disk_analysis,
            whitelist,
            preferences,
            set_preferences,
            trash_exclusions,
            categories,
            set_category_enabled,
            locked_paths,
            set_locked,
            clear_history,
            add_trash_exclusion,
            remove_trash_exclusion,
            permissions,
            open_privacy_settings,
            recheck_permissions,
            agent_status,
            install_agent,
            uninstall_agent,
            relaunch,
            browse,
            refresh_sizes,
            delete_paths,
            list_apps,
            uninstall_apps,
            reveal_in_finder,
            reveal_in_terminal,
            owning_processes,
            kill_process,
            request_notifications,
            trash_blockers,
            list_machines,
            remove_machines,
            memory_report,
            run_boost
        ])
        .run(tauri::generate_context!())
        .expect("failed to start eve");
}
