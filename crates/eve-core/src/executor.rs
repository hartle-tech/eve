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
    /// Remove the directory's contents permanently, keeping the directory.
    ///
    /// This exists for exactly one place: the Trash. Its contents are the one
    /// thing that cannot be sent to the Trash, and `~/.Trash` itself must
    /// survive — macOS expects it to be there. Removing the directory instead,
    /// which is what a plain `Permanent` on `~/.Trash` does, also removes the
    /// per-item `.DS_Store` bookkeeping Finder keeps alongside it.
    PermanentContents,
}

impl Disposition {
    /// Whether what this removes can be got back.
    ///
    /// The distinction is not cosmetic: it decides what the journal marks as
    /// undoable, and it is what a frontend must tell the user before a run.
    pub fn is_recoverable(self) -> bool {
        matches!(self, Disposition::Trash | Disposition::EmptyContents)
    }
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
    /// Individual children that could not be removed, when the disposition
    /// works child by child.
    ///
    /// Kept separately from `error` because one stuck item is not a failed
    /// sweep. The old code kept the first error, discarded every success and
    /// reported zero bytes — so a Trash holding one undeletable directory
    /// looked like a total failure on every single run, for ever, while
    /// gigabytes really were being freed underneath it.
    #[serde(default)]
    pub failures: Vec<String>,
    /// Names of children that macOS will *never* let anything delete.
    ///
    /// Narrower than `failures` on purpose. A file a running process is
    /// holding open, or one whose permissions are wrong, is a temporary
    /// condition that quitting an app or a `chflags` fixes — recording those
    /// would quietly turn a fixable failure into a permanent skip. This list
    /// carries only the Data Vault signature: `readdir` names the entry and
    /// `lstat` on it is refused, which nothing, including root, can lift.
    ///
    /// The caller turns these into Trash exclusions so the next sweep skips
    /// them instead of failing on them again for ever.
    #[serde(default)]
    pub permanently_stuck: Vec<String>,
}

impl ExecOutcome {
    /// Nothing went wrong. Partial sweeps are *not* failures — read
    /// [`ExecOutcome::failures`] for those.
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

/// Why a directory cannot leave where it is.
///
/// All three present as "permission denied" on the move and have nothing else
/// in common, so eve has to tell them apart before it says anything: telling
/// somebody to re-run as administrator when the answer is "sign out of that
/// cloud service" is worse than saying nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Unmovable {
    /// Root owns it. An installer package put it there, and admin rights fix it.
    SystemOwned,
    /// A file provider's domain under `~/Library/CloudStorage` — a cloud
    /// service or a connected phone. Nothing can move it, root included.
    FileProvider,
    /// Yours, and marked read-only. The user can fix this themselves.
    NotWritable,
}

/// Stage 4 of the funnel.
pub struct Executor {
    dry_run: bool,
    size_budget: Duration,
    /// How a recoverable delete is actually performed.
    ///
    /// Injectable so the test suite can exercise the Trash path without using
    /// the developer's real Trash — which it did, twice per run, for as long
    /// as these tests have existed. Finding junk in `~/.Trash` after every
    /// `cargo test` is bad enough on its own; on a tool whose reported bug was
    /// "the Trash is never emptied" it actively obstructed the fix.
    trash_with: fn(&Path) -> Result<()>,
    /// Put recoverable deletions in *this* Trash, and hand them to this user.
    ///
    /// Set only on the privileged side. `NSFileManager` trashes into the Trash
    /// of whoever is running, so root would move a removed application to
    /// `/var/root/.Trash` — where the person who asked for it cannot see it,
    /// cannot restore it, and cannot empty it to get the space back. The
    /// recoverable-delete contract would be technically satisfied and
    /// practically void.
    ///
    /// Root instead renames into the invoking user's Trash and gives the tree
    /// back to them, which is what makes it a real undo.
    trash_into: Option<(PathBuf, u32, u32)>,
}

impl Default for Executor {
    fn default() -> Self {
        Executor {
            dry_run: true,
            size_budget: Duration::from_secs(15),
            trash_with: Executor::to_trash,
            trash_into: None,
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

    /// Replace the recoverable-delete backend. Tests only — the real Trash is
    /// a shared resource and a test suite has no business writing to it.
    #[cfg(test)]
    pub(crate) fn with_trash_backend(mut self, f: fn(&Path) -> Result<()>) -> Self {
        self.trash_with = f;
        self
    }

    /// Trash into a named directory and hand the result to a named user.
    ///
    /// For the privileged side only. See [`Executor::trash_into`].
    pub fn trashing_into(mut self, dir: impl Into<PathBuf>, uid: u32, gid: u32) -> Self {
        self.trash_into = Some((dir.into(), uid, gid));
        self
    }

    /// Move into a specific Trash and give the tree to a specific user.
    ///
    /// A plain rename, because root can relocate anything, followed by a
    /// recursive `chown` so the item behaves like something the user deleted:
    /// visible in their Trash, restorable, and emptiable to actually free the
    /// space. Without the chown a root-owned tree in the user's Trash is
    /// exactly the un-emptiable item this tool exists to avoid creating.
    fn to_named_trash(path: &Path, dir: &Path, uid: u32, gid: u32) -> Result<()> {
        std::fs::create_dir_all(dir)?;
        let name = path
            .file_name()
            .ok_or_else(|| EveError::Trash(format!("{} has no name", path.display())))?;

        // Finder's own collision rule: keep the name, add the time.
        let mut dest = dir.join(name);
        if dest.exists() {
            let stamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            dest = dir.join(format!("{} {stamp}", name.to_string_lossy()));
        }

        // The rename IS the deletion. Once it lands, the item is out of the
        // way and the caller's request has been carried out — so nothing after
        // this point may turn a success into a reported failure.
        std::fs::rename(path, &dest)?;

        // Best-effort, and it genuinely does fail: macOS will not let even
        // root chown a signed bundle an installer placed (the same provenance
        // protection that stops the *user* relocating it). Reporting that as a
        // failed removal was wrong twice over — the app was already gone from
        // /Applications, and the run said "Removed: 0 B".
        //
        // What it costs when it fails is real, though: the item sits in the
        // user's Trash still owned by root, so they cannot empty it. That is
        // why `empty_trash` has its own privileged path.
        for entry in walkdir::WalkDir::new(&dest).follow_links(false).into_iter().flatten() {
            let _ = std::os::unix::fs::lchown(entry.path(), Some(uid), Some(gid));
        }
        Ok(())
    }

    /// Whether anything in this Trash needs root to remove.
    ///
    /// A privileged uninstall can leave a root-owned bundle in the user's
    /// Trash, because macOS refuses to let even root give a signed bundle
    /// away. The user then cannot empty their own Trash, which is exactly the
    /// stuck state this tool exists to prevent — so the Trash sweep has to be
    /// able to ask for administrator rights too.
    pub fn trash_needs_admin(trash: &Path) -> Vec<PathBuf> {
        let Ok(entries) = std::fs::read_dir(trash) else {
            return Vec::new();
        };
        entries
            .flatten()
            .map(|e| e.path())
            .filter(|p| {
                std::fs::symlink_metadata(p).is_ok_and(|m| m.is_dir() && !m.is_symlink())
                    && Self::needs_admin_to_relocate(p)
            })
            .collect()
    }

    pub fn is_dry_run(&self) -> bool {
        self.dry_run
    }

    /// Remove one target. The path must already have cleared stages 1–3.
    pub fn remove(&self, path: &Path, disposition: Disposition) -> ExecOutcome {
        let mut outcome = ExecOutcome {
            path: path.to_path_buf(),
            disposition,
            bytes: 0,
            files: 0,
            complete: true,
            dry_run: self.dry_run,
            error: None,
            failures: Vec::new(),
            permanently_stuck: Vec::new(),
        };

        if path.symlink_metadata().is_err() {
            return outcome;
        }

        match disposition {
            Disposition::Trash | Disposition::Permanent => {
                let m = measure(path, self.size_budget);
                outcome.bytes = m.bytes;
                outcome.files = m.files;
                outcome.complete = m.complete;
                if self.dry_run {
                    return outcome;
                }
                if let Err(e) = self.remove_one(path, disposition, &m) {
                    outcome.error = Some(e.to_string());
                    // The measurement described what *would* have been freed.
                    // Since it was not, do not report it as reclaimed.
                    outcome.bytes = 0;
                    outcome.files = 0;
                }
            }
            Disposition::EmptyContents | Disposition::PermanentContents => {
                self.sweep_children(path, disposition, &mut outcome);
            }
        }

        outcome
    }

    /// Remove exactly one target, with the vault gate in front of the Trash.
    fn remove_one(&self, path: &Path, disposition: Disposition, m: &Measurement) -> Result<()> {
        match disposition {
            Disposition::Trash => {
                Self::refuse_if_undeletable(path, m)?;
                match &self.trash_into {
                    // Root: relocate directly. The "needs admin" refusal is
                    // exactly what this side exists to satisfy, so it does not
                    // apply here.
                    Some((dir, uid, gid)) => Self::to_named_trash(path, dir, *uid, *gid),
                    None => {
                        Self::refuse_if_root_owned(path)?;
                        (self.trash_with)(path)
                    }
                }
            }
            _ => Self::permanent(path),
        }
    }

    /// Whether moving this directory anywhere would need administrator rights.
    ///
    /// A directory can only be moved to a **different parent** by someone who
    /// can write to the directory *itself*, because the move rewrites its `..`
    /// entry. Write permission on the parent is not enough. That is ordinary
    /// POSIX and it is the whole reason applications installed by a `.pkg`
    /// cannot be uninstalled: `/Applications` is `drwxrwxr-x root:admin` so an
    /// admin user may add to it freely, but the bundles those installers leave
    /// behind are `root:wheel` and nobody but root can relocate them.
    ///
    /// The tell that this is POSIX and not a permission the user can grant:
    /// renaming such a bundle *within* `/Applications` succeeds, because `..`
    /// does not change. It is also not TCC — a root-owned directory that is not
    /// an app bundle at all fails in exactly the same way, and it fails for a
    /// process that already holds App Management.
    pub fn needs_admin_to_relocate(path: &Path) -> bool {
        matches!(Self::why_unmovable(path), Some(Unmovable::SystemOwned))
    }

    /// Why a directory cannot be moved out of where it is, if it cannot.
    ///
    /// Three different situations that all present as "write permission
    /// denied", and telling them apart is the whole point — the remedies have
    /// nothing in common, and eve was announcing the wrong one. A cloud
    /// provider's mount under `~/Library/CloudStorage` is owned by *you* and
    /// still unwritable, and it was being reported as "put there by an
    /// installer package … re-run with administrator rights", which is untrue
    /// and sends the user to do something that cannot work.
    pub fn why_unmovable(path: &Path) -> Option<Unmovable> {
        use std::os::unix::fs::MetadataExt;

        let meta = std::fs::symlink_metadata(path).ok()?;
        if !meta.is_dir() || meta.is_symlink() {
            return None;
        }
        if Self::writable(path) {
            return None;
        }

        // A file provider's domain: a cloud service or a phone, mounted by an
        // app's extension. Deleting the folder is not how it goes away.
        if path.components().any(|c| c.as_os_str() == "CloudStorage") {
            return Some(Unmovable::FileProvider);
        }
        // SAFETY: getuid cannot fail.
        let me = unsafe { libc::getuid() };
        if meta.uid() != me {
            return Some(Unmovable::SystemOwned);
        }
        Some(Unmovable::NotWritable)
    }

    fn writable(path: &Path) -> bool {
        use std::os::unix::ffi::OsStrExt;
        let Ok(c) = std::ffi::CString::new(path.as_os_str().as_bytes()) else {
            return false;
        };
        // SAFETY: `access` reads a NUL-terminated path and returns a status.
        unsafe { libc::access(c.as_ptr(), libc::W_OK) == 0 }
    }

    /// Refuse a Trash move that POSIX cannot perform, and say what would.
    ///
    /// Attempting it anyway produces `trashItemAtURL failed: "DJI Studio"
    /// couldn't be moved to the trash because you don't have permission to
    /// access it` — which reads like a bug in eve, names no remedy, and sends
    /// people to Privacy settings that have nothing to do with it.
    fn refuse_if_root_owned(path: &Path) -> Result<()> {
        let Some(why) = Self::why_unmovable(path) else {
            return Ok(());
        };
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| path.display().to_string());
        Err(EveError::NeedsAdmin(match why {
            Unmovable::SystemOwned => format!(
                "{name} is owned by the system — it was put there by an installer \
                 package rather than dragged in — and moving it needs administrator \
                 rights. Nothing was deleted. Re-run this with administrator rights \
                 and eve will remove it."
            ),
            Unmovable::FileProvider => format!(
                "{name} is a cloud folder, published by an app rather than stored \
                 here — macOS will not let anything move it, and administrator \
                 rights make no difference. To remove it, sign out of that \
                 service or turn its folder off in the app that provides it."
            ),
            Unmovable::NotWritable => format!(
                "{name} belongs to you but is marked read-only, so it cannot be \
                 moved. Nothing was deleted. Allow writing to it in Finder's Get \
                 Info panel and try again."
            ),
        }))
    }

    /// The vault gate.
    ///
    /// A move to the Trash is a rename, so it *succeeds* on a tree that can
    /// never actually be deleted — and the result is an item that sits in the
    /// Trash for ever and makes every subsequent Empty Trash fail. This
    /// machine collected four of them: `com.apple.siriactionsd`,
    /// `com.apple.WorkflowKit.BackgroundShortcutRunner` and two
    /// `com.apple.quicklook.ThumbnailsAgent` directories, each holding a macOS
    /// **Data Vault** that neither the owner nor root can unlink.
    ///
    /// Leaving such a tree where it is costs nothing — it is scratch space the
    /// OS manages. Stranding it in the Trash is permanent. So the recoverable
    /// disposition refuses, exactly as it refuses when the Trash is
    /// unavailable, rather than creating a mess it cannot clean up.
    ///
    /// Only the Trash is gated. A permanent delete may still try: it fails in
    /// place, which changes nothing and is recoverable by doing nothing.
    fn refuse_if_undeletable(path: &Path, m: &Measurement) -> Result<()> {
        if !m.denied {
            return Ok(());
        }
        Err(EveError::Trash(format!(
            "{} holds something macOS will never let anything delete (a Data \
             Vault), so moving it to the Trash would leave an item there that \
             can never be emptied. Nothing was moved — it has been left where \
             it is, which costs nothing.",
            path.display()
        )))
    }

    /// Remove every child, keeping going after a failure and counting only
    /// what actually went.
    ///
    /// One stuck entry must not stop the rest — that is the difference between
    /// eve and Finder, which abandons the whole Trash when a single item is in
    /// use, and is how a Trash becomes un-emptiable. It must also not erase
    /// the record of the twenty that succeeded.
    fn sweep_children(&self, dir: &Path, disposition: Disposition, out: &mut ExecOutcome) {
        let recoverable = disposition == Disposition::EmptyContents;
        let entries = match std::fs::read_dir(dir) {
            Ok(e) => e,
            Err(e) => {
                out.error = Some(e.to_string());
                return;
            }
        };

        let mut removed = 0usize;
        for entry in entries.flatten() {
            let child = entry.path();
            let m = measure(&child, self.size_budget);
            if !m.complete {
                out.complete = false;
            }
            if self.dry_run {
                out.bytes += m.bytes;
                out.files += m.files;
                continue;
            }

            let attempt = if recoverable {
                Self::refuse_if_undeletable(&child, &m).and_then(|()| match &self.trash_into {
                    Some((dir, uid, gid)) => Self::to_named_trash(&child, dir, *uid, *gid),
                    None => (self.trash_with)(&child),
                })
            } else {
                Self::permanent(&child)
            };
            match attempt {
                Ok(()) => {
                    removed += 1;
                    out.bytes += m.bytes;
                    out.files += m.files;
                }
                Err(e) => {
                    // The vault signature is the one class worth remembering:
                    // it is a property of the entry, not of what is running.
                    if m.denied {
                        if let Some(name) = child.file_name().and_then(|n| n.to_str()) {
                            out.permanently_stuck.push(name.to_string());
                        }
                    }
                    out.failures.push(format!("{}: {e}", child.display()));
                }
            }
        }

        // A sweep that removed nothing at all, and had something to remove,
        // is a failure. A sweep that removed some of it is not — it reports
        // what it freed and names what it could not.
        if removed == 0 && !out.failures.is_empty() {
            out.error = Some(format!(
                "nothing could be removed from {} ({} item(s) refused)",
                dir.display(),
                out.failures.len()
            ));
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
        assert!(out.bytes >= 4096, "reported {}", out.bytes);
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
        // Blocks allocated, which rounds up past the 2048 written.
        assert!(out.bytes >= 2048, "reported {}", out.bytes);
        assert!(!victim.exists());
    }

    /// A stand-in for the Trash that deletes outright.
    ///
    /// Recoverability is not what these tests are about, and using the real
    /// backend meant every `cargo test` left junk in the developer's own
    /// Trash. The genuine backend is covered by
    /// `trash_move_works_without_finder_automation`, which is `#[ignore]`d
    /// precisely because it does touch the real thing.
    fn fake_trash(path: &Path) -> Result<()> {
        Executor::permanent(path)
    }

    #[test]
    fn empty_contents_keeps_the_directory() {
        let tmp = tempfile::tempdir().unwrap();
        let cache = tmp.path().join("cache");
        std::fs::create_dir_all(cache.join("nested")).unwrap();
        std::fs::write(cache.join("a"), b"aaaa").unwrap();

        let out = Executor::live()
            .with_trash_backend(fake_trash)
            .remove(&cache, Disposition::EmptyContents);

        assert!(out.succeeded(), "{:?}", out.error);
        assert!(cache.is_dir(), "EmptyContents removed the directory itself");
        assert_eq!(
            std::fs::read_dir(&cache).unwrap().count(),
            0,
            "the children were left behind"
        );
        assert!(out.bytes >= 4, "the freed bytes were not counted: {}", out.bytes);
    }

    /// The Trash is the one directory whose contents cannot be sent to the
    /// Trash. Emptying it needs a disposition that removes children outright
    /// while leaving the directory — macOS expects `~/.Trash` to exist.
    #[test]
    fn permanent_contents_removes_children_and_keeps_the_directory() {
        let tmp = tempfile::tempdir().unwrap();
        let trash = tmp.path().join(".Trash");
        std::fs::create_dir_all(trash.join("old-app")).unwrap();
        std::fs::write(trash.join("old-app/blob"), vec![0u8; 4096]).unwrap();
        std::fs::write(trash.join("note.txt"), b"bye").unwrap();

        let out = Executor::live().remove(&trash, Disposition::PermanentContents);
        assert!(out.succeeded(), "{:?}", out.error);
        assert!(trash.is_dir(), "the Trash directory itself was removed");
        assert_eq!(
            std::fs::read_dir(&trash).unwrap().count(),
            0,
            "children survived"
        );
    }

    #[test]
    fn permanent_contents_is_not_recoverable_and_says_so() {
        assert!(!Disposition::PermanentContents.is_recoverable());
        assert!(!Disposition::Permanent.is_recoverable());
        assert!(Disposition::Trash.is_recoverable());
        assert!(Disposition::EmptyContents.is_recoverable());
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

    /// The vault gate.
    ///
    /// Moving something to the Trash is a rename, so it succeeds even when
    /// part of the tree can never be deleted. The result is an item that sits
    /// in the Trash for ever and makes every future "Empty Trash" fail — which
    /// is exactly what happened to this machine's `com.apple.siriactionsd` and
    /// friends. Refuse the move instead: leaving it where it is costs nothing,
    /// and stranding it in the Trash is permanent.
    #[test]
    fn a_tree_holding_something_undeletable_is_not_moved_to_the_trash() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let victim = tmp.path().join("scratch");
        let inner = victim.join("vault");
        std::fs::create_dir_all(inner.join("sealed")).unwrap();
        std::fs::set_permissions(&inner, std::fs::Permissions::from_mode(0o400)).unwrap();

        let out = Executor::live().remove(&victim, Disposition::Trash);
        let restore = std::fs::set_permissions(&inner, std::fs::Permissions::from_mode(0o700));

        assert!(!out.succeeded(), "eve stranded an undeletable item in the Trash");
        assert!(victim.exists(), "the tree should have been left where it is");
        assert_eq!(out.bytes, 0, "a refused move must not claim reclaimed bytes");
        let msg = out.error.clone().unwrap_or_default();
        assert!(
            msg.contains("Trash") && msg.contains("never"),
            "the refusal does not explain itself: {msg}"
        );
        restore.unwrap();
    }

    /// The reason `.pkg`-installed applications could not be uninstalled.
    ///
    /// Moving a directory to a **different parent** rewrites its `..` entry, so
    /// POSIX requires write permission on the directory itself. Write access to
    /// `/Applications` is not enough. A read-only directory therefore cannot be
    /// trashed at all, however permissive its parent is — which is exactly the
    /// shape of a `root:wheel` bundle sitting in a `drwxrwxr-x root:admin`
    /// `/Applications`.
    #[test]
    fn a_directory_we_cannot_write_needs_admin_to_reach_the_trash() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let bundle = tmp.path().join("Example.app");
        std::fs::create_dir_all(bundle.join("Contents")).unwrap();
        std::fs::set_permissions(&bundle, std::fs::Permissions::from_mode(0o555)).unwrap();

        let why = Executor::why_unmovable(&bundle);
        let out = Executor::live()
            .with_trash_backend(fake_trash)
            .remove(&bundle, Disposition::Trash);
        let restore = std::fs::set_permissions(&bundle, std::fs::Permissions::from_mode(0o755));

        if std::env::var_os("USER").is_some_and(|u| u == "root") {
            restore.unwrap();
            return; // root can relocate anything; the check is not for it
        }
        // A test cannot create a root-owned directory, so this one is
        // `NotWritable` — the *move* is refused either way, which is the
        // property that matters here. Which of the three reasons applies is
        // pinned by `why_unmovable` and its own tests.
        assert!(why.is_some(), "an unwritable directory was not recognised");
        assert!(!out.succeeded(), "eve tried a move POSIX cannot perform");
        let msg = out.error.clone().unwrap_or_default();
        assert!(
            msg.contains("cannot be moved") || msg.contains("administrator rights"),
            "the failure names no remedy: {msg}"
        );
        assert!(
            !msg.contains("trashItemAtURL"),
            "still leaking the raw API error: {msg}"
        );
        assert!(bundle.exists());
        restore.unwrap();
    }

    /// Regression: a cloud folder was reported as "put there by an installer
    /// package … re-run with administrator rights". It is owned by the user,
    /// admin rights change nothing, and the advice could not have worked.
    #[test]
    fn a_cloud_folder_is_not_reported_as_system_owned() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let cloud = tmp.path().join("Library/CloudStorage/Provider-Phone");
        std::fs::create_dir_all(&cloud).unwrap();
        std::fs::set_permissions(&cloud, std::fs::Permissions::from_mode(0o500)).unwrap();

        let why = Executor::why_unmovable(&cloud);
        let out = Executor::live()
            .with_trash_backend(fake_trash)
            .remove(&cloud, Disposition::Trash);
        let restore = std::fs::set_permissions(&cloud, std::fs::Permissions::from_mode(0o700));

        assert_eq!(why, Some(Unmovable::FileProvider));
        assert!(
            !Executor::needs_admin_to_relocate(&cloud),
            "a cloud folder was offered as fixable with administrator rights"
        );
        let msg = out.error.clone().unwrap_or_default();
        assert!(msg.contains("cloud folder"), "wrong explanation: {msg}");
        assert!(
            !msg.contains("administrator rights and eve will remove it"),
            "still telling the user to do something that cannot work: {msg}"
        );
        restore.unwrap();
    }

    /// Owned by you and read-only is a third thing again, and the remedy is
    /// yours to apply rather than root's.
    #[test]
    fn a_read_only_directory_of_your_own_says_so() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let d = tmp.path().join("locked");
        std::fs::create_dir_all(&d).unwrap();
        std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o500)).unwrap();

        let why = Executor::why_unmovable(&d);
        let restore = std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o700));
        assert_eq!(why, Some(Unmovable::NotWritable));
        assert!(!Executor::needs_admin_to_relocate(&d));
        restore.unwrap();
    }

    /// A file is not affected — only directories carry `..`.
    #[test]
    fn an_unwritable_file_still_reaches_the_trash() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let f = tmp.path().join("locked.txt");
        std::fs::write(&f, vec![0u8; 16]).unwrap();
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o444)).unwrap();

        assert!(!Executor::needs_admin_to_relocate(&f));
        let out = Executor::live()
            .with_trash_backend(fake_trash)
            .remove(&f, Disposition::Trash);
        assert!(out.succeeded(), "{:?}", out.error);
    }

    /// A permanent delete is still allowed to try. It fails in place, which is
    /// recoverable; a Trash move fails *forever*, which is not.
    #[test]
    fn the_vault_gate_does_not_block_deleting_in_place() {
        let tmp = tempfile::tempdir().unwrap();
        let victim = tmp.path().join("scratch");
        std::fs::create_dir_all(&victim).unwrap();
        std::fs::write(victim.join("f"), vec![0u8; 32]).unwrap();

        let out = Executor::live().remove(&victim, Disposition::Permanent);
        assert!(out.succeeded(), "{:?}", out.error);
    }

    /// One stuck child must not erase the record of the twenty that went.
    ///
    /// The old code kept the first error, threw the successes away and
    /// reported zero bytes reclaimed — so emptying a Trash that held one
    /// undeletable item looked like a total failure, every time, for ever.
    #[test]
    fn a_partly_successful_sweep_reports_what_it_actually_freed() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let trash = tmp.path().join(".Trash");
        std::fs::create_dir_all(trash.join("gone")).unwrap();
        std::fs::write(trash.join("gone/blob"), vec![0u8; 4096]).unwrap();

        let stuck = trash.join("stuck");
        std::fs::create_dir_all(&stuck).unwrap();
        std::fs::write(stuck.join("held"), b"x").unwrap();
        std::fs::set_permissions(&stuck, std::fs::Permissions::from_mode(0o500)).unwrap();

        let out = Executor::live().remove(&trash, Disposition::PermanentContents);
        let restore = std::fs::set_permissions(&stuck, std::fs::Permissions::from_mode(0o700));

        assert!(out.bytes >= 4096, "the 4 KB that really went was not counted: {}", out.bytes);
        assert_eq!(out.failures.len(), 1, "the stuck item was not named");
        assert!(out.failures[0].contains("stuck"));
        assert!(
            !trash.join("gone").exists(),
            "one stuck child stopped the rest of the sweep"
        );
        restore.unwrap();
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
