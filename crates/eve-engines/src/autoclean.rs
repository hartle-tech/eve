//! The unattended low-disk trigger.
//!
//! This replaces the shell wrapper that used to sit between launchd and the
//! cleaner. Folding it into the binary removes the whole reason that wrapper
//! was hard: it existed to split a run into a user pass and a root pass,
//! because `osascript … with administrator privileges` hangs forever under
//! launchd while running everything as root breaks Homebrew and Docker. eve
//! solves both structurally — the privileged worker never draws a dialog, and
//! `RunContext::User` categories are pinned to the user side by the catalog.
//!
//! launchd has no low-disk event, so this polls. The common case is one
//! `statfs` and an immediate exit.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use eve_core::error::Denial;
use eve_core::journal::Journal;
use eve_core::liveness::Liveness;
use eve_core::policy::Policy;
use eve_core::prefs::{state_dir, Preferences, TrashExclusions};
use eve_core::privilege::SudoWorker;
use eve_core::size::{free_space, human_bytes};
use crate::clean::{Cleaner, Selection};

const VOLUME: &str = "/System/Volumes/Data";

pub struct Config {
    /// `None` means "whatever the user stored". A value overrides it for this
    /// run and is deliberately not written back — see the flag's help.
    pub threshold_gb: Option<u64>,
    pub cooldown_sec: Option<u64>,
    pub dry_run: bool,
}

fn log_path() -> PathBuf {
    dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("/tmp"))
        .join("Library/Logs/hartle.tech/eve-autoclean.log")
}

/// Every write here is best-effort. This runs precisely when the disk is full,
/// so it must never die because it could not append to its own log.
fn log(line: &str) {
    let path = log_path();
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let stamp = eve_core::journal::format_epoch(now());
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
    {
        let _ = writeln!(f, "{stamp}  {line}");
    }
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn notify(message: &str) {
    // The message is interpolated into an AppleScript string literal, so it
    // must not contain a double quote.
    let safe = message.replace('"', "'");
    let _ = std::process::Command::new("/usr/bin/osascript")
        .arg("-e")
        .arg(format!(
            "display notification \"{safe}\" with title \"eve\""
        ))
        .output();
}

/// Atomic lock whose staleness is decided by whether the recorded pid is still
/// alive, not by age — a genuinely long run must not have its lock stolen.
struct Lock(PathBuf);

impl Lock {
    fn acquire() -> Option<Lock> {
        let dir = state_dir().join("lock");
        let _ = std::fs::create_dir_all(dir.parent()?);

        if std::fs::create_dir(&dir).is_ok() {
            let _ = std::fs::write(dir.join("pid"), std::process::id().to_string());
            return Some(Lock(dir));
        }

        let pid: Option<i32> = std::fs::read_to_string(dir.join("pid"))
            .ok()
            .and_then(|s| s.trim().parse().ok());
        if let Some(pid) = pid {
            // SAFETY: signal 0 performs the permission/existence check only.
            if unsafe { libc::kill(pid, 0) } == 0 {
                return None; // Genuinely running.
            }
        }

        log(&format!(
            "breaking stale lock (recorded pid {:?} is not alive)",
            pid
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir(&dir).ok()?;
        let _ = std::fs::write(dir.join("pid"), std::process::id().to_string());
        Some(Lock(dir))
    }
}

impl Drop for Lock {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn rotate_log() {
    let path = log_path();
    const MAX: u64 = 1024 * 1024;
    if let Ok(meta) = std::fs::metadata(&path) {
        if meta.len() > MAX {
            let _ = std::fs::rename(&path, path.with_extension("log.1"));
        }
    }
}

pub fn run(cfg: &Config) -> anyhow::Result<()> {
    rotate_log();

    let Some(free) = free_space(Path::new(VOLUME)) else {
        log("ERROR: could not read free space");
        anyhow::bail!("could not read free space on {VOLUME}");
    };

    // Loaded before the threshold check, because the threshold is one of the
    // things it carries. Unreadable settings are logged and treated as
    // defaults: this is the one caller with nobody watching, so it must never
    // quietly do something destructive on the strength of a file it could not
    // parse.
    let prefs = Preferences::load_default().unwrap_or_else(|e| {
        log(&format!("WARNING: stored settings not applied — {e}"));
        Preferences::default()
    });

    // A flag overrides for this run only. Deployed plists still pass the old
    // defaults on the command line, so persisting them here would have every
    // unattended run silently reset whatever the user configured.
    let threshold_gb = cfg.threshold_gb.unwrap_or(prefs.threshold_gb);
    let cooldown_sec = cfg.cooldown_sec.unwrap_or(prefs.cooldown_sec);

    let threshold = threshold_gb * 1024 * 1024 * 1024;
    // The common case, hit every interval. Stay silent so the log records only
    // real events rather than a heartbeat.
    if free >= threshold {
        return Ok(());
    }

    let stamp = state_dir().join("last-run");
    if let Ok(meta) = std::fs::metadata(&stamp) {
        if let Ok(modified) = meta.modified() {
            let age = SystemTime::now()
                .duration_since(modified)
                .unwrap_or(Duration::ZERO)
                .as_secs();
            if age < cooldown_sec {
                log(&format!(
                    "below threshold ({} free) but cooldown active ({}s of {}s)",
                    human_bytes(free),
                    age,
                    cooldown_sec
                ));
                return Ok(());
            }
        }
    }

    let Some(_lock) = Lock::acquire() else {
        log("another run is already in progress");
        return Ok(());
    };

    log(&format!(
        "=== TRIGGER{}: {} free, below {} GB ===",
        if cfg.dry_run { " (DRY RUN)" } else { "" },
        human_bytes(free),
        threshold_gb
    ));

    // Locked directories bind the unattended run as hard as any other.
    let policy = Policy::current()
        .with_default_whitelist()
        .with_locks(prefs.locked_paths.clone());
    let liveness = Liveness::snapshot();
    let journal = Journal::open_default().ok();
    let mut cleaner =
        Cleaner::new(&policy, &liveness).with_trash_exclusions(TrashExclusions::compile(&prefs));
    if let Some(j) = &journal {
        cleaner = cleaner.with_journal(j);
    }
    let catalog = eve_catalog::catalog();

    // `unattended` is what enforces the tier gate. Review, Destructive and
    // NeverAuto categories cannot be reached from here at all — which is why
    // iOS backups are structurally out of reach rather than excluded by a flag
    // someone has to remember.
    //
    // Emptying the Trash is the single exception, and it is the reason the
    // preference had to be durable rather than a flag: this is the run that
    // fills the Trash, so it has to be the run that empties it. The consent
    // was given deliberately and persists; the tier gate exists to stop a
    // caller reaching a tier by accident, which this is the opposite of.
    let sel = Selection {
        unattended: true,
        allow_privileged: true,
        // Categories the user switched off stay off here too. This is the run
        // that came back and broke a working toolchain, so it is the one that
        // most needs to respect the setting.
        skip: prefs.disabled_categories.clone(),
        empty_trash: prefs.empty_trash,
        empty_trash_at: prefs.empty_trash_at,
        permanent_delete: prefs.permanent_delete,
        ..Default::default()
    };
    if prefs.empty_trash {
        log(match prefs.empty_trash_at {
            eve_core::prefs::TrashSweep::Start => "emptying the Trash first (empty-trash is on)",
            eve_core::prefs::TrashSweep::End => "emptying the Trash last (empty-trash-at is end)",
        });
    }
    if prefs.permanent_delete {
        log("permanent-delete is on: regenerable caches are removed outright");
    }
    if !prefs.direct_cleanup() {
        // Stated every run, on purpose. This is the default and it is a real
        // choice — nothing eve does is irreversible — but its consequence is
        // that an unattended run fills the Trash and frees nothing, which is
        // exactly the complaint that started all of this. Better said out
        // loud every time than rediscovered as a bug.
        log("direct-cleanup is off: everything moves to the Trash and no space is freed");
    }

    let mut report = if cfg.dry_run {
        cleaner.scan(&catalog, &sel)
    } else {
        let mut broker = SudoWorker::unattended();
        cleaner.execute(&catalog, &sel, Some(&mut broker))
    };
    report.newly_excluded = crate::clean::learn_undeletable(&report);
    for pattern in &report.newly_excluded {
        log(&format!(
            "recorded {pattern} as undeletable — future sweeps will skip it"
        ));
    }

    // Two refusals go in the log. Nobody is watching this run, so the only way
    // an operator learns that the Trash could not be read, or that an
    // exclusion is holding it open, is if it is written down.
    //
    // Only those two. A live cache is refused on most runs and by design —
    // logging every one buries the two lines that mean "this needs you" under
    // thirty that mean "working as intended".
    for cat in &report.categories {
        for denial in cat.notable_denials() {
            if matches!(
                denial,
                Denial::Unreadable { .. } | Denial::TrashExcluded { .. }
            ) {
                log(&format!("  ⊘ {denial}"));
            }
        }
    }

    for cat in &report.categories {
        if cat.bytes() > 0 {
            log(&format!(
                "  {} — {} ({} items)",
                cat.key,
                human_bytes(cat.bytes()),
                cat.items()
            ));
        }
    }

    let after = free_space(Path::new(VOLUME)).unwrap_or(free);
    let reclaimed = after.saturating_sub(free);
    log(&format!(
        "=== DONE: {} -> {} (reclaimed {}) ===",
        human_bytes(free),
        human_bytes(after),
        human_bytes(reclaimed)
    ));

    if cfg.dry_run {
        notify("Dry run complete. Nothing was deleted.");
    } else if reclaimed < 1024 * 1024 * 1024 && after < threshold {
        // The failure mode that actually matters: cleanup ran, but the real
        // consumer is not cache, so re-running will never help. Say so plainly
        // instead of reporting a cheerful small number.
        notify(&format!(
            "Freed only {} and the disk is still low ({} free). Something other than cache is using the space.",
            human_bytes(reclaimed),
            human_bytes(after)
        ));
    } else {
        notify(&format!(
            "Reclaimed {}. Now {} free.",
            human_bytes(reclaimed),
            human_bytes(after)
        ));
    }

    // Stamped unconditionally, including after a failure. Otherwise a
    // persistently failing run would re-fire every interval forever.
    let _ = std::fs::create_dir_all(state_dir());
    let _ = std::fs::write(&stamp, b"");
    Ok(())
}
