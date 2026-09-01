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
    /// Directories the user has locked. See [`Policy::lock`].
    locked: Vec<PathBuf>,
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
            // NOTE: `/Applications` is *protected*, not critical — see below.
            // NOTE: other users' homes are handled dynamically in
            // `critical_rule`, not here. A static `/Users` prefix rule would
            // also match *our own* home and make the entire tool a no-op.
        ];

        // User data. A category may exempt a specific subtree, and must say so.
        let protected = vec![
            // Installed applications.
            //
            // `protected` rather than `critical`, which is the difference
            // between "needs an explicit exemption" and "no exemption exists".
            // As a critical rule this silently discarded the uninstall
            // engine's per-bundle exemption and refused every app removal,
            // while the leftovers in ~/Library — not critical — were deleted
            // normally. eve gutted applications instead of uninstalling them.
            //
            // Nothing is loosened by the move: no catalog category names
            // /Applications, so the only callers that can reach it are the
            // uninstaller (which exempts one bundle) and the disk browser
            // (which exempts one hand-picked path). The directory itself is
            // covered by the protected-root guard in `check`.
            PrefixRule { path: PathBuf::from("/Applications"), name: "applications directory" },
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
            locked: Vec::new(),
        }
    }

    /// Build the policy for the current user's home.
    pub fn current() -> Self {
        Policy::for_home(dirs::home_dir().unwrap_or_else(|| PathBuf::from("/")))
    }

    pub fn home(&self) -> &Path {
        &self.home
    }

    /// Lock a directory: nothing inside it is ever removed.
    ///
    /// Stronger than the whitelist, which is a glob and reports itself as a
    /// routine skip. A lock is the user naming a place and eve agreeing never
    /// to touch it — by any category, at any tier, from any engine — so it is
    /// enforced as a prefix rule beside the protected ones and refuses the
    /// directory itself as well as everything under it.
    pub fn lock(&mut self, path: impl Into<PathBuf>) {
        self.locked.push(path.into());
    }

    pub fn with_locks<I, P>(mut self, paths: I) -> Self
    where
        I: IntoIterator<Item = P>,
        P: Into<PathBuf>,
    {
        for p in paths {
            self.lock(p);
        }
        self
    }

    pub fn locked_paths(&self) -> &[PathBuf] {
        &self.locked
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
            // eve's own log directory. `user_logs` empties `~/Library/Logs`,
            // which is where the autoclean log lives — so an unattended run
            // was deleting its own audit trail halfway through writing it, and
            // the one record of what happened at 3am ended up truncated in the
            // Trash. Two patterns because the directory itself is what the
            // category enumerates, and a `/**` glob only matches its contents.
            format!("{h}/Library/Logs/hartle.tech"),
            format!("{h}/Library/Logs/hartle.tech/**"),
            // PlugInKit's registry of installed app extensions, which lives in
            // the per-user scratch space that `darwin_scratch` empties.
            //
            // It is not a cache. Every System Settings pane — General,
            // Displays, Privacy & Security — is an ExtensionKit extension
            // discovered through this registry, and deleting it leaves System
            // Settings with an empty sidebar and no way back short of a new
            // login session, because pkd only re-enumerates the system
            // extension directories when a session starts.
            //
            // The liveness gate did not catch it: the directory is named
            // `com.apple.pluginkit` while the process holding it is `pkd`, so
            // the owner lookup found nothing running. Directory names in
            // /var/folders are not reliably a process's identity, which is
            // why this is a named exception rather than a smarter heuristic.
            "/var/folders/*/*/*/com.apple.pluginkit".to_string(),
            "/var/folders/*/*/*/com.apple.pluginkit/**".to_string(),
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
        // Locks come first, before even the critical rules, because they are
        // the one rule the user set personally. Nothing lifts them: not an
        // exemption, not a tier, not root.
        let candidate = depriv(path);
        for locked in &self.locked {
            let l = depriv(locked);
            if candidate == l || candidate.starts_with(&l) {
                return Err(Denial::Locked {
                    path: path.to_path_buf(),
                    locked: locked.clone(),
                });
            }
        }

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
            if !rule.matches(path) {
                continue;
            }
            // The root of a protected tree is never a target, however loudly
            // the caller asks. An exemption grants *reach inside* a protected
            // area — it is not, and must never be readable as, permission to
            // remove the area itself. Without this, the disk browser's
            // "exempt whatever the user ticked" would let a single checkbox
            // take `/Applications`, `~/Documents` or `~/.ssh` entire.
            let is_the_root_itself = depriv(path) == depriv(&rule.path);
            if is_the_root_itself || !exemptions.covers(path) {
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

    /// Regression, and the worst thing eve has ever done to this machine.
    ///
    /// `darwin_scratch` treats `/var/folders/…/C` and `/var/folders/…/T` as
    /// pure scratch. PlugInKit keeps its *registry* of installed app
    /// extensions in there — including every System Settings pane — so
    /// emptying it left macOS System Settings with no General, no Displays,
    /// no Privacy & Security, and no way to get them back short of a new
    /// login session.
    #[test]
    fn the_extension_registry_in_var_folders_is_never_cleaned() {
        let p = Policy::for_home("/Users/tester").with_default_whitelist();
        let e = Exemptions::none();
        for path in [
            "/var/folders/my/abc123/T/com.apple.pluginkit",
            "/var/folders/my/abc123/T/com.apple.pluginkit/Annotations",
            "/var/folders/my/abc123/C/com.apple.pluginkit",
            "/var/folders/my/abc123/0/com.apple.pluginkit/Annotations",
        ] {
            assert!(
                p.check(Path::new(path), &e).is_err(),
                "eve would break System Settings again: {path}"
            );
        }
        // Ordinary scratch is still fair game — this is a hole for one thing.
        assert!(p
            .check(Path::new("/var/folders/my/abc123/C/com.apple.Safari"), &e)
            .is_ok());
    }

    /// Regression: `user_logs` empties `~/Library/Logs`, and eve's own
    /// autoclean log lives in there. An unattended run was destroying its own
    /// audit trail halfway through writing it — every trigger left a truncated
    /// copy in the Trash and nothing in place.
    #[test]
    fn eves_own_log_directory_is_never_cleaned() {
        let p = Policy::for_home("/Users/tester").with_default_whitelist();
        let e = Exemptions::none();
        for path in [
            "/Users/tester/Library/Logs/hartle.tech",
            "/Users/tester/Library/Logs/hartle.tech/eve-autoclean.log",
        ] {
            assert!(
                p.check(Path::new(path), &e).is_err(),
                "eve would delete its own log: {path}"
            );
        }
        // Everything else in ~/Library/Logs is still fair game.
        assert!(p
            .check(Path::new("/Users/tester/Library/Logs/SomeApp"), &e)
            .is_ok());
    }

    /// Regression, and the reason eve could never uninstall anything.
    ///
    /// `/Applications` was `critical`, and critical rules ignore exemptions by
    /// design. So the uninstall engine's carefully-scoped "exempt exactly this
    /// bundle" was discarded before it was ever consulted, and every app
    /// removal was refused — while the *leftovers*, which live in `~/Library`
    /// and are not critical, were deleted normally. The journal shows the
    /// result: 27 `uninstall:leftover` deletions, and not one `uninstall`.
    /// Apps were being gutted instead of removed.
    #[test]
    fn an_app_bundle_can_be_removed_with_an_exemption() {
        let p = policy();
        let bundle = PathBuf::from("/Applications/Example.app");
        let exempt = Exemptions(vec![bundle.clone()]);

        assert!(
            p.check(&bundle, &exempt).is_ok(),
            "an uninstall that exempted exactly this bundle was still refused"
        );
        assert!(
            p.check(&bundle.join("Contents/MacOS/Example"), &exempt).is_ok(),
            "the exemption must cover what is inside the bundle too"
        );
        // Without the exemption it stays protected: no category gets to walk
        // into /Applications by accident.
        assert!(p.check(&bundle, &Exemptions::none()).is_err());
    }

    /// The hole that opening `/Applications` would otherwise create.
    ///
    /// An exemption says "this caller may reach *inside* here". It must never
    /// be readable as "this caller may delete the whole tree" — otherwise the
    /// disk browser, which exempts whatever the user ticked, would happily
    /// remove `/Applications` or `~/Documents` entire.
    #[test]
    fn a_protected_root_is_never_deletable_even_when_exempted() {
        let p = policy();
        for root in [
            "/Applications",
            "/Users/tester/Documents",
            "/Users/tester/Projects",
            "/Users/tester/.ssh",
        ] {
            let path = PathBuf::from(root);
            let exempt = Exemptions(vec![path.clone()]);
            assert!(
                p.check(&path, &exempt).is_err(),
                "an exemption deleted a protected root outright: {root}"
            );
            // A strict descendant, on the other hand, is exactly what the
            // exemption is for.
            assert!(
                p.check(&path.join("something"), &exempt).is_ok(),
                "the exemption did not reach inside {root}"
            );
        }
    }

    /// A lock is the one rule the user set personally, so nothing lifts it —
    /// not an exemption, not a category's tier, not the privileged worker.
    #[test]
    fn a_locked_directory_refuses_everything_including_exemptions() {
        let mut p = policy();
        p.lock("/Users/tester/work");

        let inside = PathBuf::from("/Users/tester/work/project/target");
        // An exemption is exactly the thing that unlocks a *protected* path,
        // so it is the strongest case to refuse.
        let exempt = Exemptions(vec![inside.clone()]);

        assert!(matches!(
            p.check(&inside, &exempt),
            Err(Denial::Locked { .. })
        ));
        assert!(matches!(
            p.check(Path::new("/Users/tester/work"), &exempt),
            Err(Denial::Locked { .. })
        ));
        // A sibling that merely shares a prefix string is not inside it.
        assert!(p
            .check(Path::new("/Users/tester/workspace/cache"), &Exemptions::none())
            .is_ok());
    }

    #[test]
    fn invalid_whitelist_glob_is_rejected_not_ignored() {
        let mut p = policy();
        assert!(p.whitelist("[unclosed", "test").is_err());
    }
}
