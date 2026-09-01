//! Persisted user preferences.
//!
//! eve has three frontends — the CLI, the TUI and the desktop app — and a
//! fourth, unattended caller in the LaunchAgent. A setting that lived in only
//! one of them would not be a setting; it would be a flag the user has to
//! remember. Everything here is read by all four and written by whichever one
//! the user happened to be looking at.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// Trash entries that are never permanently deleted.
///
/// These are the caches of Apple daemons that are running while eve runs.
/// macOS refuses to remove them — Finder gives up on the *whole* Trash rather
/// than skipping the offending item, which is why a user's Trash can sit at
/// tens of gigabytes with no way to empty it from the UI.
///
/// Every pattern ends in `*` on purpose. When a name already exists in the
/// Trash, macOS appends a timestamp (`com.apple.siriactionsd 22.14.31`), so an
/// exact-name pattern matches the first copy and silently stops matching every
/// copy after it.
/// The list eve *starts* with, seeded once into the user's own settings.
///
/// Deliberately not enforced. These were hardcoded and unremovable, which is
/// the wrong shape for a list of "things that cannot be deleted": the set is
/// machine-specific and changes with macOS, so a fixed list is both incomplete
/// on one Mac and wrong on another. They are seeded on first run and then
/// belong to the user, who can remove any of them.
pub const SEED_TRASH_EXCLUSIONS: &[&str] = &[
    "com.apple.siriactionsd*",
    "com.apple.WorkflowKit.BackgroundShortcutRunner*",
    "com.apple.quicklook.ThumbnailsAgent*",
];

/// eve's per-user state directory.
///
/// One definition, shared by the preferences file, the autoclean cooldown
/// stamp and its lock. Two copies of this path is how a setting written by the
/// app ends up invisible to the LaunchAgent.
/// Where eve keeps its settings, journal and run state.
///
/// **Named for the bundle identifier, and that is load-bearing.** macOS
/// decides whether `~/Library/Application Support/<X>` is *your* data or
/// *another app's* by comparing `<X>` to your bundle id. eve's state used to
/// live under `hartle.tech/eve`, which matches nothing, so every launch —
/// loading preferences, opening the journal — was an access to another app's
/// data, and macOS asked *"eve would like to access data from other apps"*
/// every single time. The grant is session-scoped, so allowing it never made
/// the question go away.
///
/// eve's own bundle id is `tech.hartle.eve`. Reading its own directory asks
/// nobody's permission.
pub fn state_dir() -> PathBuf {
    let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("/tmp"));
    let dir = home.join("Library/Application Support/tech.hartle.eve");
    migrate_state(&home, &dir);
    dir
}

/// Move state out of the old, misnamed directory, once.
///
/// Best-effort and idempotent: if the new directory already exists this does
/// nothing, and a failure to migrate leaves the old copy exactly where it is
/// rather than losing a journal that records everything eve has ever deleted.
fn migrate_state(home: &Path, new: &Path) {
    if new.exists() {
        return;
    }
    let old = home.join("Library/Application Support/hartle.tech/eve");
    if !old.is_dir() {
        return;
    }
    if let Some(parent) = new.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    // A rename keeps the journal's history intact and is atomic. If it fails,
    // the old directory is still there and still readable.
    let _ = std::fs::rename(&old, new);
}

/// When the Trash sweep happens relative to the rest of a run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TrashSweep {
    /// Before anything else. What this run deletes then lands in an emptied
    /// Trash and stays recoverable until the next run — a grace period, at the
    /// cost of the space not being freed until that next run.
    Start,
    /// After everything else, so a single run actually frees the space it
    /// reports. Nothing this run deleted is recoverable afterwards.
    End,
}

/// Settings the user has chosen, and that survive the process.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, rename_all = "kebab-case")]
pub struct Preferences {
    /// Permanently delete what is in the Trash as part of a clean.
    ///
    /// Off by default: emptying the Trash is the one thing eve does that
    /// cannot be undone.
    pub empty_trash: bool,
    /// Whether that sweep runs before or after the rest of the clean.
    pub empty_trash_at: TrashSweep,
    /// Delete outright instead of moving to the Trash.
    ///
    /// Off by default, and deliberately narrower than it sounds: it applies
    /// only where the worst case is something regenerable — the same doctrine
    /// as [`crate::risk::RiskTier::unlockable_by_consent`]. Categories that
    /// sit next to real user data keep the recoverable delete however this is
    /// set, and app removal never goes through here at all.
    pub permanent_delete: bool,
    /// Trash entries never permanently deleted. Entirely the user's list.
    ///
    /// Seeded from [`SEED_TRASH_EXCLUSIONS`] on first run and editable in full
    /// afterwards — including removing a seeded one. eve also adds to it
    /// itself: when a sweep hits something macOS will *never* let anything
    /// delete, that entry is recorded here so the next sweep skips it instead
    /// of failing on it again for ever.
    pub trash_exclusions: Vec<String>,
    /// Whether the seed list has been written into `trash_exclusions` already.
    ///
    /// Without this, removing a seeded entry would be undone on the next
    /// launch — the user would delete it, eve would put it back, and the list
    /// would be unremovable in a new way.
    pub trash_exclusions_seeded: bool,
    /// Directories the user has locked. Nothing inside is ever removed.
    ///
    /// Stronger than a category switch and stronger than the protection
    /// policy's own rules: this is the user naming a place and eve agreeing
    /// never to touch it, whatever category, tier or engine asks.
    pub locked_paths: Vec<String>,
    /// Categories the user has switched off, by key.
    ///
    /// The missing control behind "everytime eve runs, it breaks them". eve
    /// cleans developer caches by default and several of those are not caches
    /// in any useful sense — `pyenv_old` removes every Python except the
    /// pinned one, `gradle_wrappers` removes every wrapper except the newest —
    /// so a machine that builds against an older toolchain came back broken
    /// and there was no switch anywhere to stop it.
    ///
    /// Stored here rather than passed per run so that the window, the CLI and
    /// the unattended agent cannot disagree: a category switched off in the UI
    /// is off at 3am too, which is the run that mattered.
    pub disabled_categories: Vec<String>,
    /// The unattended run fires below this much free space.
    pub threshold_gb: u64,
    /// Minimum seconds between real unattended runs.
    pub cooldown_sec: u64,
}

impl Preferences {
    /// Put the starting exclusions into the user's own list, once.
    pub fn seed_trash_exclusions(&mut self) -> bool {
        if self.trash_exclusions_seeded {
            return false;
        }
        for p in SEED_TRASH_EXCLUSIONS {
            if !self.trash_exclusions.iter().any(|x| x == p) {
                self.trash_exclusions.push((*p).to_string());
            }
        }
        self.trash_exclusions_seeded = true;
        true
    }

    /// Record something that could not be removed from the Trash, so the next
    /// sweep skips it rather than failing on it again.
    ///
    /// Only for the permanent kind. A file held open by a running process is a
    /// temporary condition and belongs nowhere near this list — quitting the
    /// app fixes that, and recording it would silently make the entry
    /// un-emptiable for ever.
    pub fn remember_undeletable(&mut self, name: &str) -> bool {
        let pattern = format!("{name}*");
        if self.trash_exclusions.iter().any(|x| x == &pattern) {
            return false;
        }
        self.trash_exclusions.push(pattern);
        true
    }

    pub fn is_locked(&self, path: &std::path::Path) -> bool {
        self.locked_paths.iter().any(|l| {
            let l = std::path::Path::new(l);
            path == l || path.starts_with(l)
        })
    }

    pub fn set_locked(&mut self, path: &str, locked: bool) {
        self.locked_paths.retain(|p| p != path);
        if locked {
            self.locked_paths.push(path.to_string());
        }
        self.locked_paths.sort();
        self.locked_paths.dedup();
    }

    pub fn is_disabled(&self, key: &str) -> bool {
        self.disabled_categories.iter().any(|k| k == key)
    }

    /// Switch a category on or off. Idempotent.
    pub fn set_category(&mut self, key: &str, enabled: bool) {
        self.disabled_categories.retain(|k| k != key);
        if !enabled {
            self.disabled_categories.push(key.to_string());
        }
        self.disabled_categories.sort();
        self.disabled_categories.dedup();
    }
}

impl Default for Preferences {
    /// Written by hand rather than derived. `derive(Default)` would give a
    /// 0 GB threshold, which never fires, and a 0 s cooldown, which fires
    /// every interval forever. The numbers below are what the LaunchAgent has
    /// always passed on its command line, so moving them into preferences
    /// changes nothing until the user changes them.
    fn default() -> Self {
        Preferences {
            empty_trash: false,
            empty_trash_at: TrashSweep::Start,
            permanent_delete: false,
            trash_exclusions: Vec::new(),
            trash_exclusions_seeded: false,
            locked_paths: Vec::new(),
            disabled_categories: Vec::new(),
            threshold_gb: 5,
            cooldown_sec: 10800,
        }
    }
}

impl Preferences {
    /// The one question the user is actually asked: does a cleanup free space,
    /// or does it only move things to the Trash?
    ///
    /// The three fields underneath it are an implementation of that answer,
    /// not three questions. "Empty the Trash", "when to empty it" and "delete
    /// outright" are the same decision asked three ways, and asking it three
    /// ways is how a settings pane becomes a form.
    ///
    /// Off is the default and the safe reading: everything goes to the Trash
    /// and eve never empties it, so nothing eve does is irreversible.
    pub fn direct_cleanup(&self) -> bool {
        self.permanent_delete || self.empty_trash
    }

    /// Set that one question, deriving the three.
    ///
    /// On means both halves, because either alone leaves the complaint this
    /// setting exists to answer: deleting outright still leaves whatever is
    /// already in the Trash, and emptying the Trash at the start still leaves
    /// this run's own deletions sitting in it.
    pub fn set_direct_cleanup(&mut self, on: bool) {
        self.permanent_delete = on;
        self.empty_trash = on;
        self.empty_trash_at = TrashSweep::End;
    }

    /// The file backing the current user's preferences.
    pub fn default_path() -> PathBuf {
        state_dir().join("preferences.json")
    }

    /// Load from `path`.
    ///
    /// A missing file is not an error — it means "no preferences yet". A file
    /// that exists but cannot be read or parsed *is* one: silently reverting
    /// to defaults would turn the user's `empty-trash` back off without ever
    /// saying so, which is the precise failure this whole module exists to
    /// avoid.
    pub fn load(path: &Path) -> Result<Preferences, String> {
        let raw = match std::fs::read_to_string(path) {
            Ok(raw) => raw,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Preferences::default())
            }
            Err(e) => return Err(format!("{}: {e}", path.display())),
        };
        serde_json::from_str(&raw).map_err(|e| format!("{}: {e}", path.display()))
    }

    pub fn load_default() -> Result<Preferences, String> {
        let path = Preferences::default_path();
        let mut prefs = Preferences::load(&path)?;
        // Seed the starting exclusions into the user's own list, once, and
        // persist that so removing one sticks. Doing it here rather than in
        // `default()` is what makes them the user's rather than eve's.
        if prefs.seed_trash_exclusions() {
            let _ = prefs.save(&path);
        }
        Ok(prefs)
    }

    /// Write to `path`, creating the directory if needed.
    ///
    /// Written to a sibling temporary file and renamed into place. The
    /// LaunchAgent can be mid-run while the user is in the app, and a torn
    /// half-written file would fail to parse — which, per [`Preferences::load`],
    /// is a hard error the user then has to clear by hand.
    pub fn save(&self, path: &Path) -> Result<(), String> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| format!("{}: {e}", parent.display()))?;
        }
        let body = serde_json::to_string_pretty(self).map_err(|e| e.to_string())?;
        let tmp = path.with_extension(format!("tmp.{}", std::process::id()));
        std::fs::write(&tmp, body.as_bytes()).map_err(|e| format!("{}: {e}", tmp.display()))?;
        std::fs::rename(&tmp, path).map_err(|e| {
            let _ = std::fs::remove_file(&tmp);
            format!("{}: {e}", path.display())
        })
    }

    pub fn save_default(&self) -> Result<(), String> {
        self.save(&Preferences::default_path())
    }

    /// Every exclusion in effect. All of them are the user's, and all of them
    /// can be removed — including the ones eve seeded or added itself.
    pub fn effective_trash_exclusions(&self) -> Vec<(String, &'static str)> {
        self.trash_exclusions
            .iter()
            .map(|p| {
                let source = if SEED_TRASH_EXCLUSIONS.contains(&p.as_str()) {
                    "suggested by eve"
                } else {
                    "yours"
                };
                (p.clone(), source)
            })
            .collect()
    }

    /// Add a user exclusion. Returns false if it was already present.
    pub fn exclude_trash(&mut self, pattern: &str) -> Result<bool, String> {
        glob::Pattern::new(pattern).map_err(|e| e.to_string())?;
        if self.trash_exclusions.iter().any(|p| p == pattern) {
            return Ok(false);
        }
        self.trash_exclusions.push(pattern.to_string());
        Ok(true)
    }

    /// Remove a user exclusion. Returns false if it was not there.
    ///
    /// The built-ins are not removable: they exist because macOS itself
    /// refuses those entries, and "let me delete it anyway" is not an outcome
    /// eve can deliver.
    pub fn unexclude_trash(&mut self, pattern: &str) -> bool {
        match self.trash_exclusions.iter().position(|p| p == pattern) {
            Some(i) => {
                self.trash_exclusions.remove(i);
                true
            }
            None => false,
        }
    }
}

/// Compiled exclusion patterns, ready to match Trash entries.
#[derive(Debug, Clone, Default)]
pub struct TrashExclusions {
    patterns: Vec<(glob::Pattern, String)>,
}

impl TrashExclusions {
    /// Compile the built-ins plus the user's own. Patterns that do not compile
    /// are dropped here rather than at match time — they were rejected on the
    /// way in, so one can only appear if the file was hand-edited.
    pub fn compile(prefs: &Preferences) -> Self {
        let patterns = prefs
            .effective_trash_exclusions()
            .into_iter()
            .filter_map(|(p, _)| glob::Pattern::new(&p).ok().map(|c| (c, p)))
            .collect();
        TrashExclusions { patterns }
    }

    /// The pattern that excludes this entry, if any.
    ///
    /// A pattern containing `/` is matched against the whole path; anything
    /// else against the entry's file name. Trash entries are one level deep,
    /// so the name is what a user actually knows.
    pub fn excludes(&self, path: &Path) -> Option<&str> {
        let name = path.file_name().map(Path::new);
        self.patterns
            .iter()
            .find(|(compiled, raw)| {
                if raw.contains('/') {
                    compiled.matches_path(path)
                } else {
                    name.is_some_and(|n| compiled.matches_path(n))
                }
            })
            .map(|(_, raw)| raw.as_str())
    }

    pub fn is_empty(&self) -> bool {
        self.patterns.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp() -> tempfile::TempDir {
        tempfile::tempdir().unwrap()
    }

    #[test]
    fn a_missing_file_yields_defaults_and_empty_trash_is_off() {
        let dir = tmp();
        let prefs = Preferences::load(&dir.path().join("nothing-here.json")).unwrap();
        assert_eq!(prefs, Preferences::default());
        assert!(
            !prefs.empty_trash,
            "emptying the Trash must never be on until the user says so"
        );
    }

    /// The whole point: set it once, in any frontend, and it stays set.
    #[test]
    fn a_saved_preference_survives_a_reload() {
        let dir = tmp();
        let path = dir.path().join("nested/preferences.json");

        let mut prefs = Preferences {
            empty_trash: true,
            ..Preferences::default()
        };
        prefs.exclude_trash("Xcode*").unwrap();
        prefs.save(&path).unwrap();

        let reloaded = Preferences::load(&path).unwrap();
        assert!(reloaded.empty_trash);
        assert_eq!(reloaded.trash_exclusions, vec!["Xcode*".to_string()]);
    }

    /// A file that exists but cannot be parsed must not quietly become
    /// "defaults". The caller has to be able to tell the user their settings
    /// were not applied.
    /// `derive(Default)` would give 0 GB and 0 s — a threshold that never
    /// fires and a cooldown that fires constantly. The defaults have to be the
    /// values the shipped LaunchAgent has always passed on the command line,
    /// or moving them into preferences silently changes behaviour.
    #[test]
    fn schedule_defaults_match_what_the_launchagent_has_always_used() {
        let p = Preferences::default();
        assert_eq!(p.threshold_gb, 5);
        assert_eq!(p.cooldown_sec, 10800);
        assert_eq!(p.empty_trash_at, TrashSweep::Start);
        assert!(!p.permanent_delete, "permanent deletion must be opt-in");
    }

    /// A preferences file written before these fields existed must keep
    /// working, and must not acquire a 0 GB threshold on the way.
    #[test]
    fn an_older_file_gains_the_new_defaults_rather_than_zeroes() {
        let dir = tmp();
        let path = dir.path().join("preferences.json");
        std::fs::write(&path, br#"{"empty-trash":true,"trash-exclusions":["a*"]}"#).unwrap();

        let p = Preferences::load(&path).unwrap();
        assert!(p.empty_trash);
        assert_eq!(p.trash_exclusions, vec!["a*".to_string()]);
        assert_eq!(p.threshold_gb, 5);
        assert_eq!(p.cooldown_sec, 10800);
        assert_eq!(p.empty_trash_at, TrashSweep::Start);
        assert!(!p.permanent_delete);
    }

    #[test]
    fn the_new_settings_survive_a_round_trip() {
        let dir = tmp();
        let path = dir.path().join("preferences.json");
        let written = Preferences {
            empty_trash: true,
            empty_trash_at: TrashSweep::End,
            permanent_delete: true,
            threshold_gb: 12,
            cooldown_sec: 3600,
            ..Preferences::default()
        };
        written.save(&path).unwrap();
        assert_eq!(Preferences::load(&path).unwrap(), written);
    }

    /// Off is the default, and off must mean nothing eve does is irreversible.
    #[test]
    fn direct_cleanup_is_off_by_default_and_nothing_is_permanent() {
        let p = Preferences::default();
        assert!(!p.direct_cleanup());
        assert!(!p.permanent_delete);
        assert!(!p.empty_trash);
    }

    /// On has to mean both halves. Either alone leaves the exact complaint the
    /// setting exists to answer.
    #[test]
    fn direct_cleanup_on_both_deletes_outright_and_empties_the_trash() {
        let mut p = Preferences::default();
        p.set_direct_cleanup(true);

        assert!(p.direct_cleanup());
        assert!(p.permanent_delete, "would still fill the Trash");
        assert!(p.empty_trash, "would leave what is already in the Trash");
        assert_eq!(
            p.empty_trash_at,
            TrashSweep::End,
            "a start sweep leaves this run's own deletions behind"
        );
    }

    #[test]
    fn turning_it_off_makes_everything_recoverable_again() {
        let mut p = Preferences::default();
        p.set_direct_cleanup(true);
        p.set_direct_cleanup(false);

        assert!(!p.direct_cleanup());
        assert!(!p.permanent_delete);
        assert!(!p.empty_trash);
    }

    /// A file written before the collapse — with only the Trash half on —
    /// still reads as "on", rather than showing a switch that says off while
    /// eve empties the Trash.
    #[test]
    fn an_older_file_with_only_one_half_set_still_reads_as_on() {
        let mut p = Preferences::default();
        p.empty_trash = true;
        assert!(p.direct_cleanup());
    }

    #[test]
    fn an_unparseable_file_is_an_error_not_a_silent_default() {
        let dir = tmp();
        let path = dir.path().join("preferences.json");
        std::fs::write(&path, b"{ this is not json").unwrap();

        assert!(Preferences::load(&path).is_err());
    }

    #[test]
    fn saving_leaves_no_temporary_file_behind() {
        let dir = tmp();
        let path = dir.path().join("preferences.json");
        Preferences::default().save(&path).unwrap();

        let leftovers: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n != "preferences.json")
            .collect();
        assert!(leftovers.is_empty(), "stray files: {leftovers:?}");
    }

    #[test]
    fn the_apple_daemons_that_block_finder_are_excluded_out_of_the_box() {
        let mut prefs = Preferences::default();
        prefs.seed_trash_exclusions();
        let x = TrashExclusions::compile(&prefs);
        for name in [
            "com.apple.siriactionsd",
            "com.apple.WorkflowKit.BackgroundShortcutRunner",
            "com.apple.quicklook.ThumbnailsAgent",
        ] {
            assert!(
                x.excludes(&PathBuf::from("/Users/t/.Trash").join(name)).is_some(),
                "{name} should be excluded by default"
            );
        }
    }

    /// macOS renames colliding Trash entries by appending a timestamp. An
    /// exclusion that only matched the bare name would stop working the second
    /// time the same cache was trashed.
    #[test]
    fn an_exclusion_still_matches_a_collision_renamed_copy() {
        let mut prefs = Preferences::default();
        prefs.seed_trash_exclusions();
        let x = TrashExclusions::compile(&prefs);
        let renamed = PathBuf::from("/Users/t/.Trash/com.apple.siriactionsd 22.14.31");
        assert!(x.excludes(&renamed).is_some());
    }

    #[test]
    fn an_unrelated_entry_is_not_excluded() {
        let x = TrashExclusions::compile(&Preferences::default());
        assert!(x
            .excludes(&PathBuf::from("/Users/t/.Trash/holiday-photos"))
            .is_none());
    }

    #[test]
    fn a_user_pattern_adds_to_the_builtins_rather_than_replacing_them() {
        let mut prefs = Preferences::default();
        prefs.seed_trash_exclusions();
        prefs.exclude_trash("MyBigFolder*").unwrap();
        let x = TrashExclusions::compile(&prefs);

        assert!(x
            .excludes(&PathBuf::from("/Users/t/.Trash/MyBigFolder"))
            .is_some());
        assert!(
            x.excludes(&PathBuf::from("/Users/t/.Trash/com.apple.siriactionsd"))
                .is_some(),
            "a user pattern wiped out the built-ins"
        );
    }

    /// Same rule as the policy whitelist: a glob that does not compile is
    /// rejected on the way in, because a pattern that silently never matches
    /// is a hole the user believes is plugged.
    #[test]
    fn an_invalid_glob_is_rejected_not_ignored() {
        let mut prefs = Preferences::default();
        assert!(prefs.exclude_trash("[unclosed").is_err());
        assert!(prefs.trash_exclusions.is_empty());
    }

    #[test]
    fn adding_the_same_pattern_twice_is_a_no_op() {
        let mut prefs = Preferences::default();
        assert!(prefs.exclude_trash("a*").unwrap());
        assert!(!prefs.exclude_trash("a*").unwrap());
        assert_eq!(prefs.trash_exclusions.len(), 1);
    }

    /// **Every** entry is removable, including the ones eve suggested.
    ///
    /// They used to be hardcoded and permanent, which is the wrong shape for a
    /// list of "things that cannot be deleted": the set is machine-specific
    /// and changes with macOS, so a fixed list is incomplete on one Mac and
    /// wrong on another. Seeded once, then the user's.
    #[test]
    fn every_exclusion_can_be_removed_including_the_seeded_ones() {
        let mut prefs = Preferences::default();
        assert!(prefs.seed_trash_exclusions(), "first seed should apply");
        assert!(!prefs.seed_trash_exclusions(), "seeding twice would undo a removal");

        let seeded = SEED_TRASH_EXCLUSIONS[0];
        assert!(prefs.unexclude_trash(seeded), "a seeded entry must be removable");
        assert!(!prefs.trash_exclusions.iter().any(|p| p == seeded));

        // And it stays removed — this is the property that makes it the
        // user's list rather than eve's.
        assert!(!prefs.seed_trash_exclusions());
        assert!(!prefs.trash_exclusions.iter().any(|p| p == seeded));
    }

    /// A sweep that meets something nothing can delete records it, so the next
    /// sweep skips it instead of failing on it again for ever.
    #[test]
    fn an_undeletable_entry_is_remembered() {
        let mut prefs = Preferences::default();
        assert!(prefs.remember_undeletable("com.apple.somethingd"));
        assert!(!prefs.remember_undeletable("com.apple.somethingd"), "no duplicates");

        let x = TrashExclusions::compile(&prefs);
        assert!(x
            .excludes(&PathBuf::from("/Users/t/.Trash/com.apple.somethingd 22-14-31"))
            .is_some(), "the timestamped copy macOS makes must match too");
    }

    #[test]
    fn effective_exclusions_name_their_source() {
        let mut prefs = Preferences::default();
        prefs.seed_trash_exclusions();
        prefs.exclude_trash("mine*").unwrap();

        let all = prefs.effective_trash_exclusions();
        assert_eq!(all.len(), SEED_TRASH_EXCLUSIONS.len() + 1);
        assert!(all.iter().any(|(p, s)| p == "mine*" && *s == "yours"));
        assert!(all
            .iter()
            .any(|(p, s)| p == SEED_TRASH_EXCLUSIONS[0] && *s == "suggested by eve"));
    }

    /// A pattern with a slash is about a location, not a name.
    #[test]
    fn a_pattern_containing_a_slash_matches_the_whole_path() {
        let mut prefs = Preferences::default();
        prefs.exclude_trash("/Users/t/.Trash/keep/**").unwrap();
        let x = TrashExclusions::compile(&prefs);

        assert!(x
            .excludes(&PathBuf::from("/Users/t/.Trash/keep/thing"))
            .is_some());
        assert!(x
            .excludes(&PathBuf::from("/Users/t/.Trash/other/thing"))
            .is_none());
    }
}
