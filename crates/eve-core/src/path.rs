use std::path::{Component, Path, PathBuf};

use crate::error::Denial;
use crate::policy::{Exemptions, Policy};

/// Stage 1 of the funnel: syntactic validation and symlink resolution.
///
/// The validator answers one question — *is this string safe to hand to a
/// delete call?* — and answers it before anything has been touched.
pub struct PathValidator<'a> {
    policy: &'a Policy,
}

/// Collapse repeated separators, drop `.` components, strip a trailing slash.
///
/// Equivalent spellings must not be able to produce different verdicts:
/// `/a//b/` and `/a/b` are the same location and the protection check has to
/// see them as the same string.
pub fn normalize(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for c in path.components() {
        match c {
            Component::RootDir => out.push("/"),
            Component::CurDir => {}
            other => out.push(other.as_os_str()),
        }
    }
    if out.as_os_str().is_empty() {
        PathBuf::from("/")
    } else {
        out
    }
}

/// macOS file flags that mean "you will not be deleting this".
const SF_RESTRICTED: u32 = 0x0008_0000; // SIP-protected
const SF_IMMUTABLE: u32 = 0x0002_0000; // system immutable
const UF_IMMUTABLE: u32 = 0x0000_0002; // user immutable
// The one that actually matters in practice. macOS marks system service
// scratch directories under /var/folders — SandboxHelper,
// com.apple.ThreadCommissionerService — `sunlnk` rather than `restricted`,
// and `ls -lO` is the only place it shows up. Omitting it means eve keeps
// walking into exactly the dialogs this check exists to prevent.
const SF_NOUNLINK: u32 = 0x0010_0000; // system no-unlink
const UF_NOUNLINK: u32 = 0x0000_0010; // user no-unlink

/// Refuse anything macOS has marked restricted or immutable.
///
/// System Integrity Protection flags certain files — `SandboxHelper`,
/// `com.apple.ThreadCommissionerService` and friends — as `restricted`. A
/// delete attempt does not merely fail: on recent macOS it raises a modal
/// dialog saying the item "can't be modified or deleted because it's required
/// by macOS". Firing several of those during a routine clean is both alarming
/// and useless, since the answer will never change.
///
/// Checking the flag turns an unavoidable interruption into a quiet skip. The
/// refusal is deliberately *not* noteworthy: on a stock Mac these are numerous,
/// expected, and say nothing about the user's disk.
fn check_system_restricted(path: &Path) -> Result<(), Denial> {
    #[cfg(target_os = "macos")]
    {
        use std::os::macos::fs::MetadataExt;
        if let Ok(meta) = std::fs::symlink_metadata(path) {
            let flags = meta.st_flags();
            if flags & (SF_RESTRICTED | SF_IMMUTABLE | UF_IMMUTABLE | SF_NOUNLINK | UF_NOUNLINK) != 0 {
                return Err(Denial::SystemRestricted(path.to_path_buf()));
            }
        }
    }
    #[cfg(not(target_os = "macos"))]
    let _ = path;
    Ok(())
}

impl<'a> PathValidator<'a> {
    pub fn new(policy: &'a Policy) -> Self {
        PathValidator { policy }
    }

    /// Validate a deletion candidate, returning its normalized form.
    ///
    /// `exemptions` are the calling category's explicit, declared permissions.
    /// They are needed here because the ancestor-symlink guard re-runs the
    /// protection predicates on the *resolved* path — without them, a category
    /// that legitimately declared access to (say) `MobileSync` would have that
    /// declaration silently overridden whenever an ancestor happened to be a
    /// symlink, which on macOS includes anything under /var or /tmp.
    pub fn validate(&self, raw: &Path, exemptions: &Exemptions) -> Result<PathBuf, Denial> {
        use std::os::unix::ffi::OsStrExt;

        let bytes = raw.as_os_str().as_bytes();
        if bytes.is_empty() {
            return Err(Denial::Empty);
        }
        if bytes.iter().any(|b| b.is_ascii_control()) {
            return Err(Denial::ControlCharacter(raw.to_path_buf()));
        }
        if !raw.is_absolute() {
            return Err(Denial::NotAbsolute(raw.to_path_buf()));
        }
        // `..` only as a *whole* component. A directory legitimately named
        // "name..files" (Firefox does this) must not trip the check.
        if raw.components().any(|c| matches!(c, Component::ParentDir)) {
            return Err(Denial::Traversal(raw.to_path_buf()));
        }

        let path = normalize(raw);

        check_system_restricted(&path)?;
        self.check_leaf_symlink(&path)?;
        self.check_ancestor_symlinks(&path, exemptions)?;

        Ok(path)
    }

    /// If the target itself is a symlink, judge where it points.
    ///
    /// Validating the target rather than skipping symlinks outright matters:
    /// skipping means a link is never cleaned, but *following* one blindly
    /// means a link can be aimed at anything.
    fn check_leaf_symlink(&self, path: &Path) -> Result<(), Denial> {
        let Ok(meta) = std::fs::symlink_metadata(path) else {
            return Ok(()); // Missing path: nothing to delete, nothing to judge.
        };
        if !meta.is_symlink() {
            return Ok(());
        }

        let target = std::fs::read_link(path)
            .map_err(|_| Denial::UnreadableSymlink(path.to_path_buf()))?;

        let resolved = if target.is_absolute() {
            normalize(&target)
        } else {
            let parent = path.parent().unwrap_or(Path::new("/"));
            normalize(&parent.join(&target))
        };

        if self.policy.critical_rule(&resolved).is_some() {
            return Err(Denial::SymlinkToProtected {
                link: path.to_path_buf(),
                target: resolved,
            });
        }
        Ok(())
    }

    /// The ancestor-symlink guard.
    ///
    /// Every check above matches on the *literal* path string, and the leaf
    /// test only inspects the final component. If an ancestor is a symlink the
    /// literal string matches nothing dangerous while the actual `rm` follows
    /// the link into the real target — a redirected `~/Library/Caches` would
    /// let a cache sweep walk into `~/Documents`.
    ///
    /// So: canonicalize the parent (which physically resolves every ancestor
    /// link) and re-run the deny predicates on the resolved leaf. This is
    /// deny-only — a resolved path never *grants* permission the literal path
    /// lacked, so legitimate targets keep their existing verdict.
    ///
    /// This sits on the hot path, so the common case stays fork-free: walk the
    /// ancestors with a cheap `is_symlink` test and only pay for canonicalize
    /// when one of them really is a link.
    fn check_ancestor_symlinks(
        &self,
        path: &Path,
        exemptions: &Exemptions,
    ) -> Result<(), Denial> {
        let Some(parent) = path.parent() else {
            return Ok(());
        };

        let mut probe = Some(parent);
        let mut ancestor_is_link = false;
        while let Some(p) = probe {
            if p == Path::new("/") {
                break;
            }
            if p.is_symlink() {
                ancestor_is_link = true;
                break;
            }
            probe = p.parent();
        }
        if !ancestor_is_link {
            return Ok(());
        }

        let Ok(resolved_parent) = std::fs::canonicalize(parent) else {
            return Ok(()); // Cannot resolve: the delete will fail anyway.
        };
        if resolved_parent == parent {
            return Ok(());
        }

        let leaf = path.file_name().unwrap_or_default();
        let resolved = normalize(&resolved_parent.join(leaf));

        if self.policy.critical_rule(&resolved).is_some()
            || self.policy.check(&resolved, exemptions).is_err()
        {
            return Err(Denial::ResolvesIntoProtected {
                literal: path.to_path_buf(),
                resolved,
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy_for(home: &Path) -> Policy {
        Policy::for_home(home)
    }

    #[test]
    fn rejects_the_obvious_shapes() {
        let p = Policy::for_home("/Users/tester");
        let v = PathValidator::new(&p);

        assert_eq!(v.validate(Path::new(""), &Exemptions::none()).unwrap_err(), Denial::Empty);
        assert!(matches!(
            v.validate(Path::new("relative/path"), &Exemptions::none()).unwrap_err(),
            Denial::NotAbsolute(_)
        ));
        assert!(matches!(
            v.validate(Path::new("/a/../../etc"), &Exemptions::none()).unwrap_err(),
            Denial::Traversal(_)
        ));
        assert!(matches!(
            v.validate(Path::new("/tmp/bad\nname"), &Exemptions::none()).unwrap_err(),
            Denial::ControlCharacter(_)
        ));
    }

    #[test]
    fn allows_dots_inside_a_component() {
        // Firefox really does create directories like "name..files".
        let p = Policy::for_home("/Users/tester");
        let v = PathValidator::new(&p);
        assert!(v.validate(Path::new("/Users/tester/Library/Caches/name..files"), &Exemptions::none()).is_ok());
    }

    #[test]
    fn normalizes_equivalent_spellings() {
        assert_eq!(normalize(Path::new("/a//b/")), PathBuf::from("/a/b"));
        assert_eq!(normalize(Path::new("/a/./b")), PathBuf::from("/a/b"));
        assert_eq!(normalize(Path::new("/")), PathBuf::from("/"));
    }

    #[test]
    fn refuses_a_symlink_aimed_at_a_protected_path() {
        let tmp = tempfile::tempdir().unwrap();
        let link = tmp.path().join("innocent-cache");
        std::os::unix::fs::symlink("/System/Library", &link).unwrap();

        let p = policy_for(tmp.path());
        let v = PathValidator::new(&p);
        assert!(matches!(
            v.validate(&link, &Exemptions::none()).unwrap_err(),
            Denial::SymlinkToProtected { .. }
        ));
    }

    /// The case the guard exists for: a cache directory redirected at documents.
    #[test]
    fn refuses_when_an_ancestor_symlink_redirects_into_protected_data() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().to_path_buf();
        let docs = home.join("Documents");
        std::fs::create_dir_all(docs.join("subdir")).unwrap();

        // ~/Library/Caches is a symlink to ~/Documents.
        let library = home.join("Library");
        std::fs::create_dir_all(&library).unwrap();
        std::os::unix::fs::symlink(&docs, library.join("Caches")).unwrap();

        let p = policy_for(&home);
        let v = PathValidator::new(&p);

        // The literal string looks like a perfectly ordinary cache sweep.
        let target = library.join("Caches").join("subdir");
        assert!(
            matches!(
                v.validate(&target, &Exemptions::none()).unwrap_err(),
                Denial::ResolvesIntoProtected { .. }
            ),
            "ancestor-symlink guard failed to catch the redirect"
        );
    }

    #[test]
    fn ordinary_paths_with_no_symlinks_pass() {
        let tmp = tempfile::tempdir().unwrap();
        let cache = tmp.path().join("Library/Caches/com.example.app");
        std::fs::create_dir_all(&cache).unwrap();

        let p = policy_for(tmp.path());
        let v = PathValidator::new(&p);
        assert_eq!(v.validate(&cache, &Exemptions::none()).unwrap(), normalize(&cache));
    }

    /// macOS raises a modal dialog when you try to delete a restricted item,
    /// so eve must decline before attempting it rather than after.
    #[test]
    fn refuses_items_macos_marks_immutable() {
        let tmp = tempfile::tempdir().unwrap();
        let locked = tmp.path().join("SandboxHelper");
        std::fs::write(&locked, b"x").unwrap();

        // uchg is the user-immutable flag; SIP's restricted flag cannot be set
        // in a test, but it travels the same code path.
        let set = std::process::Command::new("/usr/bin/chflags")
            .arg("uchg")
            .arg(&locked)
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if !set {
            return; // chflags unavailable; nothing to assert.
        }

        let p = Policy::for_home(tmp.path());
        let v = PathValidator::new(&p);
        let verdict = v.validate(&locked, &Exemptions::none());

        let _ = std::process::Command::new("/usr/bin/chflags")
            .arg("nouchg")
            .arg(&locked)
            .status();

        assert!(
            matches!(verdict, Err(Denial::SystemRestricted(_))),
            "immutable item was not refused: {verdict:?}"
        );
    }

    /// These are numerous and expected on a stock Mac; listing them would bury
    /// the refusals that actually tell the user something.
    #[test]
    fn restricted_refusals_are_not_reported_as_noteworthy() {
        let d = Denial::SystemRestricted(PathBuf::from("/x"));
        assert!(!d.is_noteworthy());
    }

    #[test]
    fn missing_paths_validate_fine() {
        // Nothing to delete is not an error at this stage; the executor
        // reports it as a no-op.
        let p = Policy::for_home("/Users/tester");
        let v = PathValidator::new(&p);
        assert!(v.validate(Path::new("/Users/tester/Library/Caches/gone"), &Exemptions::none()).is_ok());
    }
}
