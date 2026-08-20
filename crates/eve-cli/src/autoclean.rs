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

use eve_core::journal::Journal;
use eve_core::liveness::Liveness;
use eve_core::policy::Policy;
use eve_core::privilege::SudoWorker;
use eve_core::size::{free_space, human_bytes};
use eve_engines::clean::{Cleaner, Selection};

const VOLUME: &str = "/System/Volumes/Data";

pub struct Config {
    pub threshold_gb: u64,
    pub cooldown_sec: u64,
    pub dry_run: bool,
}

fn state_dir() -> PathBuf {
    dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("/tmp"))
        .join("Library/Application Support/hartle.tech/eve")
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

    let threshold = cfg.threshold_gb * 1024 * 1024 * 1024;
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
            if age < cfg.cooldown_sec {
                log(&format!(
                    "below threshold ({} free) but cooldown active ({}s of {}s)",
                    human_bytes(free),
                    age,
                    cfg.cooldown_sec
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
        cfg.threshold_gb
    ));

    let policy = Policy::current().with_default_whitelist();
    let liveness = Liveness::snapshot();
    let journal = Journal::open_default().ok();
    let mut cleaner = Cleaner::new(&policy, &liveness);
    if let Some(j) = &journal {
        cleaner = cleaner.with_journal(j);
    }
    let catalog = eve_catalog::catalog();

    // `unattended` is what enforces the tier gate. Review, Destructive and
    // NeverAuto categories cannot be reached from here at all — which is why
    // iOS backups are structurally out of reach rather than excluded by a flag
    // someone has to remember.
    let sel = Selection {
        unattended: true,
        allow_privileged: true,
        ..Default::default()
    };

    let report = if cfg.dry_run {
        cleaner.scan(&catalog, &sel)
    } else {
        let mut broker = SudoWorker::unattended();
        cleaner.execute(&catalog, &sel, Some(&mut broker))
    };

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
