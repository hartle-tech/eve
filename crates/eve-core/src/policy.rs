use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::Denial;

/// A protected location, matched as an exact path or as an ancestor.
///
/// Prefix matching rather than globbing is deliberate here: these rules guard
/// system integrity, and a glob that silently fails to match is a hole. User
/// whitelist entries, which fail safe in the other direction, do use globs.
#[derive(Debug, Clone)]
struct PrefixRule {
    path: PathBuf,
    name: &'static str,
}

impl PrefixRule {
    fn matches(&self, candidate: &Path) -> bool {
        let c = depriv(candidate);
        let r = depriv(&self.path);
        c == r || c.starts_with(&r)
    }
}

/// Collapse macOS's `/private` aliases so equivalent paths compare equal.
///
/// `/var`, `/tmp` and `/etc` are symlinks to `/private/var`, `/private/tmp` and
/// `/private/etc`. Anything that has been through `canonicalize()` comes back
/// wearing the `/private` prefix, while rules built from an uncanonicalized
/// home directory do not — so without this, a protection rule and the very
/// path it is meant to guard fail to match. That is not cosmetic: it is
/// exactly how the ancestor-symlink guard silently stops firing.
pub fn depriv(p: &Path) -> PathBuf {
    let Ok(rest) = p.strip_prefix("/private") else {
        return p.to_path_buf();
    };
    match rest.components().next() {
        Some(std::path::Component::Normal(first))
            if matches!(first.to_str(), Some("var") | Some("tmp") | Some("etc")) =>
        {
            Path::new("/").join(rest)
        }
        _ => p.to_path_buf(),
    }
}

/// The protection policy: what may never be deleted, what needs an explicit
/// exemption, and what the user has whitelisted.
#[derive(Debug, Clone)]
pub struct Policy {
    home: PathBuf,
    critical: Vec<PrefixRule>,
    protected: Vec<PrefixRule>,
    whitelist: Vec<WhitelistEntry>,
}

#[derive(Debug, Clone)]
struct WhitelistEntry {
    pattern: glob::Pattern,
    source: String,
}

/// A category's declared permission to touch a normally-`protected` path.
///
/// Exemptions are explicit, per-category, and never apply to `critical` rules.
/// They exist so that (for example) the `ios_backups` category can name
/// `MobileSync` rather than the policy having a hole in it for everyone.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Exemptions(pub Vec<PathBuf>);

impl Exemptions {
    pub fn none() -> Self {
        Exemptions(Vec::new())
    }

    fn covers(&self, path: &Path) -> bool {
        let c = depriv(path);
        self.0.iter().any(|e| {
            let e = depriv(e);
            c == e || c.starts_with(&e)
        })
    }
}

impl Policy {
    /// Build the policy for a given home directory.
    pub fn for_home(home: impl Into<PathBuf>) -> Self {
        let home: PathBuf = home.into();
        let h = |rel: &str| home.join(rel);

        // Never deletable under any circumstances, by anyone, with no exemption
        // available. System integrity, other users, and anything mounted.
        let critical = vec![
            PrefixRule { path: PathBuf::from("/"), name: "filesystem root" },
            PrefixRule { path: PathBuf::from("/System"), name: "system volume" },
            PrefixRule { path: PathBuf::from("/bin"), name: "system binaries" },
            PrefixRule { path: PathBuf::from("/sbin"), name: "system binaries" },
            PrefixRule { path: PathBuf::from("/usr/bin"), name: "system binaries" },
            PrefixRule { path: PathBuf::from("/usr/sbin"), name: "system binaries" },
            PrefixRule { path: PathBuf::from("/usr/lib"), name: "system libraries" },
            PrefixRule { path: PathBuf::from("/usr/share"), name: "system data" },
            PrefixRule { path: PathBuf::from("/Library/Frameworks"), name: "frameworks" },
            PrefixRule { path: PathBuf::from("/Library/Keychains"), name: "keychains" },
            // Root-launched services and privileged helpers. Deleting these is
            // an escalation primitive — it is how you disable security tooling
            // without ever needing to write a file — so they are critical even
            // though they are not part of the OS proper.
            PrefixRule { path: PathBuf::from("/Library/LaunchDaemons"), name: "system launch daemons" },
            PrefixRule { path: PathBuf::from("/Library/LaunchAgents"), name: "system launch agents" },
            PrefixRule { path: PathBuf::from("/Library/PrivilegedHelperTools"), name: "privileged helpers" },
            PrefixRule { path: PathBuf::from("/Library/Preferences"), name: "system preferences" },
            PrefixRule { path: PathBuf::from("/Library/Security"), name: "security configuration" },
            PrefixRule { path: PathBuf::from("/private/etc"), name: "system config" },
            PrefixRule { path: PathBuf::from("/private/var/db/dslocal"), name: "directory services" },
            // External and network volumes. eve is a cleaner for *this* Mac;
            // a mounted backup drive is exactly the thing it must never touch.
            PrefixRule { path: PathBuf::from("/Volumes"), name: "mounted volume" },
            PrefixRule { path: PathBuf::from("/Network"), name: "network mount" },
            PrefixRule { path: PathBuf::from("/Applications"), name: "applications directory" },
            // NOTE: other users' homes are handled dynamically in
            // `critical_rule`, not here. A static `/Users` prefix rule would
            // also match *our own* home and make the entire tool a no-op.
        ];

        // User data. A category may exempt a specific subtree, and must say so.
        let protected = vec![
            PrefixRule { path: h("Documents"), name: "documents" },
            PrefixRule { path: h("Desktop"), name: "desktop" },
            PrefixRule { path: h("Pictures"), name: "pictures" },
            PrefixRule { path: h("Movies"), name: "movies" },
            PrefixRule { path: h("Music"), name: "music" },
            PrefixRule { path: h("Library/Mobile Documents"), name: "iCloud Drive" },
            PrefixRule { path: h("Library/Keychains"), name: "keychains" },
            PrefixRule { path: h("Library/Messages"), name: "messages" },
            PrefixRule { path: h("Library/Photos"), name: "photos library" },
            PrefixRule { path: h("Library/Application Support/AddressBook"), name: "contacts" },
            PrefixRule { path: h("Library/Calendars"), name: "calendars" },
            PrefixRule { path: h("Library/Mail"), name: "mail store" },
            // iPhone backups. Photos and videos, not cache — and TCC-protected,
            // so they size as 0 bytes and a deletion would not even be visible
            // in the log. Reachable only by a category that names it explicitly.
            PrefixRule {
                path: h("Library/Application Support/MobileSync"),
                name: "iOS device backups",
            },
            PrefixRule { path: h(".ssh"), name: "ssh keys" },
            PrefixRule { path: h(".gnupg"), name: "gpg keys" },
            PrefixRule { path: h(".password-store"), name: "password store" },
            PrefixRule { path: h("Projects"), name: "source code" },
        ];

        Policy {
            home,
            critical,
            protected,
            whitelist: Vec::new(),
        }
    }

    /// Build the policy for the current user's home.
    pub fn current() -> Self {
        Policy::for_home(dirs::home_dir().unwrap_or_else(|| PathBuf::from("/")))
    }

    pub fn home(&self) -> &Path {
        &self.home
    }

    /// Add a user whitelist pattern. Invalid globs are rejected, not ignored.
    pub fn whitelist(&mut self, pattern: &str, source: impl Into<String>) -> Result<(), String> {
        let compiled = glob::Pattern::new(pattern).map_err(|e| e.to_string())?;
        self.whitelist.push(WhitelistEntry {
            pattern: compiled,
            source: source.into(),
        });
        Ok(())
    }

    /// Every active whitelist pattern with the source that contributed it, so
    /// the UI can distinguish built-in protection from the user's own rules.
    pub fn whitelist_patterns(&self) -> Vec<(&str, &str)> {
        self.whitelist
            .iter()
            .map(|w| (w.pattern.as_str(), w.source.as_str()))
            .collect()
    }

    /// The default whitelist: caches that are expensive to rebuild and that a
    /// user almost never wants reclaimed silently. Model weights, package
    /// registries and IDE indexes cost hours of redownload for a few GB.
    pub fn with_default_whitelist(mut self) -> Self {
        let h = self.home.display().to_string();
        for p in [
            format!("{h}/.ollama/models/**"),
            format!("{h}/.cache/huggingface/**"),
            format!("{h}/.m2/repository/**"),
            format!("{h}/.gradle/caches/**"),
            format!("{h}/Library/Caches/ms-playwright*/**"),
            format!("{h}/Library/Caches/JetBrains*/**"),
            format!("{h}/Library/Application Support/JetBrains*/**"),
            format!("{h}/Library/Caches/pypoetry/virtualenvs/**"),
            format!("{h}/Library/Caches/com.apple.FontRegistry*/**"),
            format!("{h}/Library/Caches/CloudKit*/**"),
        ] {
            let _ = self.whitelist(&p, "default");
        }
        self
    }

    /// Does this path match a critical rule? Used both as a direct check and as
    /// the deny predicate for the ancestor-symlink guard.
    pub fn critical_rule(&self, path: &Path) -> Option<&'static str> {
        // The filesystem root matches everything by prefix, so it is only a
        // violation when it *is* the target.
        for rule in &self.critical {
            if rule.path == Path::new("/") {
                if path == Path::new("/") {
                    return Some(rule.name);
                }
                continue;
            }
            if rule.matches(path) {
                return Some(rule.name);
            }
        }

        // `/Users` itself, and any home directory that is not ours. Handled
        // here rather than as a prefix rule so that our own home stays
        // reachable — see the note in the critical list.
        let candidate = depriv(path);
        let users_root = Path::new("/Users");
        if candidate == users_root {
            return Some("user home root");
        }
        if candidate.starts_with(users_root) && !candidate.starts_with(depriv(&self.home)) {
            return Some("another user's home");
        }

        None
    }

    /// Full policy check for a candidate deletion.
    pub fn check(&self, path: &Path, exemptions: &Exemptions) -> Result<(), Denial> {
        if let Some(rule) = self.critical_rule(path) {
            return Err(Denial::Protected {
                path: path.to_path_buf(),
                rule: rule.to_string(),
            });
        }

        // The home directory itself.
        if depriv(path) == depriv(&self.home) {
            return Err(Denial::Protected {
                path: path.to_path_buf(),
                rule: "home directory".into(),
            });
        }

        for rule in &self.protected {
            if rule.matches(path) && !exemptions.covers(path) {
                return Err(Denial::Protected {
                    path: path.to_path_buf(),
                    rule: rule.name.to_string(),
                });
            }
        }

        let deprived = depriv(path);
        for entry in &self.whitelist {
            if entry.pattern.matches_path(path) || entry.pattern.matches_path(&deprived) {
                return Err(Denial::Whitelisted {
                    path: path.to_path_buf(),
                    pattern: entry.pattern.as_str().to_string(),
                });
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> Policy {
        Policy::for_home("/Users/tester")
    }

    #[test]
    fn refuses_the_filesystem_root_but_not_everything_under_it() {
        let p = policy();
        assert!(p.critical_rule(Path::new("/")).is_some());
        assert!(p.critical_rule(Path::new("/Users/tester/Library/Caches/x")).is_none());
    }

    #[test]
    fn refuses_system_and_mounted_volumes() {
        let p = policy();
        for path in [
            "/System",
            "/System/Library/CoreServices",
            "/bin",
            "/usr/bin/env",
            "/Volumes",
            "/Volumes/Backup Drive/photos",
            "/Users",
            "/Users/someone-else",
        ] {
            assert!(
                p.critical_rule(Path::new(path)).is_some(),
                "should be critical: {path}"
            );
        }
    }

    #[test]
    fn refuses_user_data_without_an_exemption() {
        let p = policy();
        let e = Exemptions::none();
        for path in [
            "/Users/tester/Documents/taxes.pdf",
            "/Users/tester/.ssh/id_ed25519",
            "/Users/tester/Library/Mobile Documents/x",
            "/Users/tester/Library/Application Support/MobileSync/Backup",
        ] {
            assert!(
                p.check(Path::new(path), &e).is_err(),
                "should be protected: {path}"
            );
        }
    }

    #[test]
    fn an_exemption_unlocks_protected_but_never_critical() {
        let p = policy();
        let backups = PathBuf::from("/Users/tester/Library/Application Support/MobileSync");
        let exempt = Exemptions(vec![backups.clone()]);

        assert!(p.check(&backups.join("Backup"), &exempt).is_ok());

        // Critical rules ignore exemptions entirely.
        let sys = Exemptions(vec![PathBuf::from("/System")]);
        assert!(p.check(Path::new("/System/Library"), &sys).is_err());
    }

    #[test]
    fn home_itself_is_refused() {
        let p = policy();
        assert!(p.check(Path::new("/Users/tester"), &Exemptions::none()).is_err());
    }

    #[test]
    fn whitelist_blocks_an_otherwise_allowed_path() {
        let mut p = policy();
        p.whitelist("/Users/tester/.ollama/models/**", "test").unwrap();
        let e = Exemptions::none();
        assert!(p.check(Path::new("/Users/tester/.ollama/models/llama"), &e).is_err());
        assert!(p.check(Path::new("/Users/tester/.ollama/junk"), &e).is_ok());
    }

    /// Regression: `/private` aliasing made protection rules and the paths
    /// they guard fail to compare equal, which silently disabled the
    /// ancestor-symlink guard for anything under /var or /tmp.
    #[test]
    fn private_aliases_compare_equal() {
        assert_eq!(depriv(Path::new("/private/var/folders/x")), PathBuf::from("/var/folders/x"));
        assert_eq!(depriv(Path::new("/private/tmp/y")), PathBuf::from("/tmp/y"));
        // Not an alias: /private/whatever stays put.
        assert_eq!(depriv(Path::new("/private/other")), PathBuf::from("/private/other"));
        assert_eq!(depriv(Path::new("/Users/tester")), PathBuf::from("/Users/tester"));

        let p = Policy::for_home("/var/folders/tmpdir");
        let e = Exemptions::none();
        // Same location, two spellings, one verdict.
        assert!(p.check(Path::new("/var/folders/tmpdir/Documents/a"), &e).is_err());
        assert!(p
            .check(Path::new("/private/var/folders/tmpdir/Documents/a"), &e)
            .is_err());
    }

    #[test]
    fn our_own_home_is_reachable_but_other_homes_are_not() {
        let p = Policy::for_home("/Users/tester");
        assert!(p.critical_rule(Path::new("/Users/tester/Library/Caches/x")).is_none());
        assert!(p.critical_rule(Path::new("/Users/someone-else/Library")).is_some());
        assert!(p.critical_rule(Path::new("/Users")).is_some());
    }

    #[test]
    fn invalid_whitelist_glob_is_rejected_not_ignored() {
        let mut p = policy();
        assert!(p.whitelist("[unclosed", "test").is_err());
    }
}
