use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::error::{EveError, Result};
use crate::size::{measure, Measurement};

/// How a target should be removed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Disposition {
    /// Move to the Finder Trash. Recoverable, and the default.
    Trash,
    /// Unlink permanently. Only for places where Trash is meaningless —
    /// root-owned system paths that the user's Trash cannot hold.
    Permanent,
    /// Remove the directory's contents but keep the directory itself.
    ///
    /// Many applications assume their cache directory exists and misbehave if
    /// it vanishes underneath them.
    EmptyContents,
}

/// What actually happened to one target.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecOutcome {
    pub path: PathBuf,
    pub disposition: Disposition,
    pub bytes: u64,
    pub files: u64,
    /// False when the measurement was truncated by a timeout or an unreadable
    /// subtree. A partial number must never masquerade as a total.
    pub complete: bool,
    pub dry_run: bool,
    pub error: Option<String>,
}

impl ExecOutcome {
    pub fn succeeded(&self) -> bool {
        self.error.is_none()
    }
}

/// Turn a Trash failure into something the user can act on.
///
/// macOS routes Trash moves through Finder, which needs Automation permission
/// for the calling app, and Full Disk Access to reach much of `~/Library`.
/// When either is missing, Finder returns error -5000 and the underlying
/// message is a wall of AppleScript. Surfacing that verbatim tells the user
/// nothing about what to do, and reads like a crash rather than a permission
/// prompt they can satisfy in about fifteen seconds.
pub fn explain_trash_failure(raw: &str) -> String {
    let permission_denied = raw.contains("-5000")
        || raw.contains("necessary permission")
        || raw.contains("not allowed")
        || raw.contains("Operation not permitted");

    if permission_denied {
        "macOS would not let Finder move this to the Trash. Grant the app \
         Automation access to Finder, and Full Disk Access, in System Settings \
         > Privacy & Security. Nothing was deleted — eve does not fall back to \
         permanent deletion when a recoverable delete is unavailable."
            .to_string()
    } else {
        format!("{raw} — nothing was deleted; eve does not fall back to permanent deletion")
    }
}

/// Stage 4 of the funnel.
pub struct Executor {
    dry_run: bool,
    size_budget: Duration,
}

impl Default for Executor {
    fn default() -> Self {
        Executor {
            dry_run: true,
            size_budget: Duration::from_secs(15),
        }
    }
}

impl Executor {
    /// A dry-run executor. This is the default on purpose: the destructive
    /// mode should be the one you have to ask for.
    pub fn dry_run() -> Self {
        Executor::default()
    }

    pub fn live() -> Self {
        Executor {
            dry_run: false,
            ..Executor::default()
        }
    }

    pub fn with_size_budget(mut self, budget: Duration) -> Self {
        self.size_budget = budget;
        self
    }

    pub fn is_dry_run(&self) -> bool {
        self.dry_run
    }

    /// Remove one target. The path must already have cleared stages 1–3.
    pub fn remove(&self, path: &Path, disposition: Disposition) -> ExecOutcome {
        let m = if path.symlink_metadata().is_ok() {
            measure(path, self.size_budget)
        } else {
            Measurement::EMPTY
        };

        let mut outcome = ExecOutcome {
            path: path.to_path_buf(),
            disposition,
            bytes: m.bytes,
            files: m.files,
            complete: m.complete,
            dry_run: self.dry_run,
            error: None,
        };

        if self.dry_run || m == Measurement::EMPTY && !path.exists() {
            return outcome;
        }

        if let Err(e) = self.perform(path, disposition) {
            outcome.error = Some(e.to_string());
            // The measurement described what *would* have been freed. Since it
            // was not, do not report it as reclaimed.
            outcome.bytes = 0;
            outcome.files = 0;
        }

        outcome
    }

    fn perform(&self, path: &Path, disposition: Disposition) -> Result<()> {
        match disposition {
            Disposition::Trash => Self::to_trash(path),
            Disposition::Permanent => Self::permanent(path),
            Disposition::EmptyContents => {
                let entries = std::fs::read_dir(path)?;
                let mut first_error = None;
                for entry in entries.flatten() {
                    let child = entry.path();
                    // Contents go to the Trash too, preserving the contract.
                    if let Err(e) = Self::to_trash(&child) {
                        first_error.get_or_insert(e);
                    }
                }
                match first_error {
                    Some(e) => Err(e),
                    None => Ok(()),
                }
            }
        }
    }

    /// The recoverable-delete contract.
    ///
    /// If the Trash is unavailable, this **refuses** — it does not quietly
    /// escalate to a permanent unlink. A caller that asked for a recoverable
    /// delete and silently got an irrecoverable one has been lied to.
    /// Move to the Trash without going through Finder.
    ///
    /// The default backend drives Finder over AppleScript, which requires the
    /// calling process to hold **Automation** permission for Finder. A CLI
    /// invoked from a terminal rarely has it, so every delete failed with
    /// Finder error -5000 and the recoverable-delete contract — correctly —
    /// refused rather than escalating to `rm`. The result was a cleaner that
    /// could not clean anything.
    ///
    /// `NsFileManager` calls `trashItemAtURL:` directly: no Finder, no
    /// AppleScript, no Automation prompt. The cost is that macOS does not
    /// record "Put Back" information, so items land in the Trash without their
    /// original location. They are still fully recoverable, which is what the
    /// contract actually promises.
    fn to_trash(path: &Path) -> Result<()> {
        use trash::macos::{DeleteMethod, TrashContextExtMacos};

        let mut ctx = trash::TrashContext::default();
        ctx.set_delete_method(DeleteMethod::NsFileManager);
        ctx.delete(path)
            .map_err(|e| EveError::Trash(explain_trash_failure(&e.to_string())))
    }

    fn permanent(path: &Path) -> Result<()> {
        let meta = std::fs::symlink_metadata(path)?;
        if meta.is_dir() && !meta.is_symlink() {
            std::fs::remove_dir_all(path)?;
        } else {
            std::fs::remove_file(path)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dry_run_measures_but_does_not_delete() {
        let tmp = tempfile::tempdir().unwrap();
        let victim = tmp.path().join("cache");
        std::fs::create_dir_all(&victim).unwrap();
        std::fs::write(victim.join("f"), vec![0u8; 4096]).unwrap();

        let out = Executor::dry_run().remove(&victim, Disposition::Permanent);
        assert!(out.dry_run);
        assert_eq!(out.bytes, 4096);
        assert!(victim.exists(), "dry run deleted something");
    }

    #[test]
    fn permanent_removes_a_tree_and_reports_size() {
        let tmp = tempfile::tempdir().unwrap();
        let victim = tmp.path().join("cache");
        std::fs::create_dir_all(victim.join("nested")).unwrap();
        std::fs::write(victim.join("nested/f"), vec![0u8; 2048]).unwrap();

        let out = Executor::live().remove(&victim, Disposition::Permanent);
        assert!(out.succeeded(), "{:?}", out.error);
        assert_eq!(out.bytes, 2048);
        assert!(!victim.exists());
    }

    #[test]
    fn empty_contents_keeps_the_directory() {
        let tmp = tempfile::tempdir().unwrap();
        let cache = tmp.path().join("cache");
        std::fs::create_dir_all(&cache).unwrap();
        std::fs::write(cache.join("a"), b"aaaa").unwrap();

        // Trash is unavailable for a tempdir on CI-ish setups, so assert the
        // directory survives regardless of whether the children moved.
        let _ = Executor::live().remove(&cache, Disposition::EmptyContents);
        assert!(cache.is_dir(), "EmptyContents removed the directory itself");
    }

    #[test]
    fn missing_path_is_a_clean_no_op() {
        let out = Executor::live().remove(
            Path::new("/nonexistent/eve/target"),
            Disposition::Permanent,
        );
        assert!(out.succeeded());
        assert_eq!(out.bytes, 0);
    }

    /// Proves the Trash backend works without Automation permission.
    ///
    /// Ignored by default because it really does move a file to the Trash and
    /// leaves it there. Run explicitly:
    ///
    ///     cargo test -p eve-core -- --ignored trash_move_works
    #[test]
    #[ignore]
    fn trash_move_works_without_finder_automation() {
        let tmp = tempfile::tempdir().unwrap();
        let victim = tmp.path().join("eve-trash-backend-check");
        std::fs::write(&victim, vec![0u8; 2048]).unwrap();

        let out = Executor::live().remove(&victim, Disposition::Trash);
        assert!(
            out.succeeded(),
            "Trash move failed — the backend still needs Automation: {:?}",
            out.error
        );
        assert!(!victim.exists(), "file survived the Trash move");
        assert_eq!(out.bytes, 2048);
    }

    #[test]
    fn a_denied_trash_move_explains_what_to_grant() {
        let raw = "Error during a `trash` operation: Finder got an error: The operation \
                   can't be completed because you don't have the necessary permission. (-5000)";
        let msg = explain_trash_failure(raw);
        assert!(msg.contains("Full Disk Access"), "no remedy offered: {msg}");
        assert!(msg.contains("Nothing was deleted"), "does not reassure: {msg}");
        assert!(!msg.contains("-5000"), "leaks the raw AppleScript error: {msg}");
    }

    #[test]
    fn an_unrecognised_trash_failure_still_states_the_contract() {
        let msg = explain_trash_failure("disk went away");
        assert!(msg.contains("disk went away"));
        assert!(msg.contains("does not fall back to permanent deletion"));
    }

    #[test]
    fn a_failed_delete_reports_zero_reclaimed() {
        let tmp = tempfile::tempdir().unwrap();
        let f = tmp.path().join("f");
        std::fs::write(&f, vec![0u8; 1000]).unwrap();
        // Removing a file as a directory fails.
        let out = Executor::live().remove(&f, Disposition::EmptyContents);
        assert!(!out.succeeded());
        assert_eq!(out.bytes, 0, "failed delete must not claim reclaimed bytes");
    }
}
