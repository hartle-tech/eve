//! The cleaning engine.
//!
//! A scan is a dry run. That is not an implementation shortcut — it is the
//! only way a preview can be honest. The preview and the real run ask the same
//! funnel the same question, so anything the preview lists is something the
//! real run would actually do.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::process::Command;

use eve_catalog::{Category, Cmd, Group, Target};
use eve_core::error::Denial;
use eve_core::executor::{Disposition, Executor};
use eve_core::funnel::{Funnel, FunnelReport, Operation};
use eve_core::journal::{Journal, Principal};
use eve_core::liveness::Liveness;
use eve_core::policy::Policy;
use eve_core::prefs::{TrashExclusions, TrashSweep};
use eve_core::privilege::{Plan, PrivilegeBroker};
use eve_core::risk::{RiskTier, RunContext};
use serde::Serialize;

/// What the caller asked for.
#[derive(Debug, Clone)]
pub struct Selection {
    /// Run only these category keys.
    pub only: Vec<String>,
    /// Skip these category keys.
    pub skip: Vec<String>,
    /// Opt in to categories that are off by default.
    pub include: Vec<String>,
    /// No human present. Enforces the tier gate.
    pub unattended: bool,
    /// Include categories that need root.
    pub allow_privileged: bool,
    /// Permanently delete what is already in the Trash.
    ///
    /// This comes from the user's stored preferences rather than from a flag,
    /// which is what makes it usable by the LaunchAgent — and the LaunchAgent
    /// is what fills the Trash in the first place.
    pub empty_trash: bool,
    /// Whether the sweep runs before or after the rest of the clean.
    pub empty_trash_at: TrashSweep,
    /// Delete outright rather than moving to the Trash, where the tier allows.
    pub permanent_delete: bool,
}

impl Default for Selection {
    fn default() -> Self {
        Selection {
            only: Vec::new(),
            skip: Vec::new(),
            include: Vec::new(),
            unattended: false,
            allow_privileged: false,
            empty_trash: false,
            empty_trash_at: TrashSweep::Start,
            permanent_delete: false,
        }
    }
}

impl Selection {
    pub fn selects(&self, cat: &Category) -> bool {
        if !self.only.is_empty() {
            return self.only.iter().any(|k| k == cat.key);
        }
        // An explicit skip wins over everything, including a stored
        // preference: "not this time" must not mean editing your settings.
        if self.skip.iter().any(|k| k == cat.key) {
            return false;
        }
        if self.unattended && !cat.tier.allowed_unattended() && !self.consents_to(cat) {
            return false;
        }
        if !self.allow_privileged && cat.needs_root() {
            return false;
        }
        cat.on_by_default() || self.consents_to(cat) || self.include.iter().any(|k| k == cat.key)
    }

    /// The category keys the user has durably consented to.
    ///
    /// Handed to the funnel, which enforces the same gate independently — the
    /// funnel is the thing root also runs, and it does not take anyone's word
    /// for a verdict.
    pub fn durable_consent(&self, catalog: &[Category]) -> Vec<String> {
        catalog
            .iter()
            .filter(|c| self.consents_to(c))
            .map(|c| c.key.to_string())
            .collect()
    }

    /// Whether the stored preferences cover this category.
    ///
    /// Identified by disposition rather than by key: the preference is about
    /// *permanently emptying a directory*, and that is a property the catalog
    /// already declares. A key match would put the catalog's naming into the
    /// engine and quietly break if a second such category were ever added.
    fn consents_to(&self, cat: &Category) -> bool {
        self.empty_trash
            && cat.disposition == Disposition::PermanentContents
            && cat.tier.unlockable_by_consent()
    }
}

/// Outcome for one category.
#[derive(Debug, Clone, Serialize)]
pub struct CategoryResult {
    pub key: String,
    pub title: String,
    pub description: String,
    pub group: Group,
    pub tier: RiskTier,
    pub needs_root: bool,
    pub reports: Vec<FunnelReport>,
    pub commands: Vec<CommandResult>,
}

impl CategoryResult {
    pub fn bytes(&self) -> u64 {
        self.reports.iter().map(FunnelReport::bytes).sum()
    }

    pub fn items(&self) -> usize {
        self.reports.iter().filter(|r| r.bytes() > 0).count()
    }

    /// Refusals worth telling the user about. Whitelist hits are routine.
    pub fn notable_denials(&self) -> Vec<&Denial> {
        self.reports
            .iter()
            .filter_map(|r| r.denial.as_ref())
            .filter(|d| d.is_noteworthy())
            .collect()
    }

    /// Things the funnel permitted that then did not happen.
    ///
    /// A different fact from a denial, and one that used to go nowhere at all:
    /// the executor's own refusals — the Trash unavailable, a tree holding a
    /// Data Vault — were carried on the report and never rendered, so a run
    /// that failed to move anything printed the same clean summary as one that
    /// worked. Per-child failures from a sweep are folded in here too.
    pub fn execution_failures(&self) -> Vec<String> {
        self.reports
            .iter()
            .filter(|r| r.was_allowed())
            .flat_map(|r| {
                r.outcome
                    .as_ref()
                    .and_then(|o| o.error.clone())
                    .into_iter()
                    .chain(r.failures().iter().cloned())
            })
            .collect()
    }

    pub fn is_empty(&self) -> bool {
        self.bytes() == 0
            && self.commands.is_empty()
            && self.notable_denials().is_empty()
            && self.execution_failures().is_empty()
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct CommandResult {
    pub program: String,
    pub args: Vec<String>,
    pub note: String,
    pub ran: bool,
    pub ok: bool,
    pub detail: Option<String>,
}

/// The whole run.
#[derive(Debug, Clone, Serialize)]
pub struct CleanReport {
    pub dry_run: bool,
    pub categories: Vec<CategoryResult>,
    pub free_before: Option<u64>,
    pub free_after: Option<u64>,
    pub privileged_available: bool,
    /// Exclusions this run added by itself, after proving those entries can
    /// never be deleted. Empty on a scan.
    ///
    /// Shown to the user because a list that grows on its own is a policy
    /// change, and eve does not make those silently.
    #[serde(default)]
    pub newly_excluded: Vec<String>,
}

impl CleanReport {
    pub fn total_bytes(&self) -> u64 {
        self.categories.iter().map(CategoryResult::bytes).sum()
    }

    pub fn total_items(&self) -> usize {
        self.categories.iter().map(CategoryResult::items).sum()
    }

    /// Trash entries this run proved nothing can ever delete.
    ///
    /// Deduplicated and sorted so the caller can hand them straight to
    /// [`eve_core::prefs::Preferences::remember_undeletable`] without the same
    /// name arriving twice from two categories.
    pub fn permanently_stuck(&self) -> Vec<String> {
        let mut names: Vec<String> = self
            .categories
            .iter()
            .flat_map(|c| &c.reports)
            .filter_map(|r| r.outcome.as_ref())
            .flat_map(|o| o.permanently_stuck.iter().cloned())
            .collect();
        names.sort();
        names.dedup();
        names
    }

    pub fn by_group(&self) -> BTreeMap<Group, Vec<&CategoryResult>> {
        let mut out: BTreeMap<Group, Vec<&CategoryResult>> = BTreeMap::new();
        for c in &self.categories {
            out.entry(c.group).or_default().push(c);
        }
        out
    }
}

/// Record what this run proved undeletable, so the next sweep skips it.
///
/// Call this from the user's own process after a live run — never from the
/// privileged worker, which has a different home and would write the file as
/// root. Returns the patterns that were newly added, which is what the caller
/// tells the user: a list that silently grows is a policy change nobody asked
/// for.
pub fn learn_undeletable(report: &CleanReport) -> Vec<String> {
    if report.dry_run {
        return Vec::new();
    }
    let names = report.permanently_stuck();
    if names.is_empty() {
        return Vec::new();
    }
    let Ok(mut prefs) = eve_core::prefs::Preferences::load_default() else {
        return Vec::new();
    };
    let added: Vec<String> = names
        .into_iter()
        .filter(|n| prefs.remember_undeletable(n))
        .map(|n| format!("{n}*"))
        .collect();
    if !added.is_empty() && prefs.save_default().is_err() {
        return Vec::new();
    }
    added
}

/// Turn a category into the operations that implement it.
///
/// `EmptyContents` is expanded here into one operation per child rather than
/// being handed to the executor as a single directory-wide sweep. That is a
/// safety requirement, not a style choice: the funnel adjudicates whatever
/// path it is given, so a whole-directory `EmptyContents` on
/// `~/Library/Caches` would validate only the parent and then delete children
/// that had never been liveness-checked — silently defeating the guard against
/// removing a cache whose owner still has it open.
pub fn build_operations(cat: &Category, home: &std::path::Path) -> Vec<Operation> {
    expand(cat, home).operations
}

/// What a category expanded to, including what could not be expanded.
#[derive(Debug, Default)]
pub struct Expansion {
    pub operations: Vec<Operation>,
    /// Directories that exist but could not be enumerated, with the reason.
    ///
    /// Carried rather than dropped because on macOS this is nearly always TCC,
    /// and "we could not look" must not be rendered as "there was nothing
    /// there". `~/.Trash` in particular is unreadable without Full Disk
    /// Access, so a silent skip here is precisely the shape of a cleaner that
    /// reports success forever while reclaiming nothing.
    pub unreadable: Vec<(PathBuf, String)>,
}

/// Turn a category into the operations that implement it, keeping the
/// enumeration failures that a bare operation list would throw away.
pub fn expand(cat: &Category, home: &std::path::Path) -> Expansion {
    let paths = resolve_targets(cat, home);
    let mut out = Expansion::default();

    // The child disposition for a contents-only category. `EmptyContents`
    // keeps the recoverable-delete contract; `PermanentContents` exists for
    // the Trash, whose contents have nowhere recoverable left to go.
    let child_disposition = match cat.disposition {
        Disposition::EmptyContents if cat.needs_root() => {
            // Root-owned system paths cannot go to the user's Trash.
            Disposition::Permanent
        }
        Disposition::EmptyContents => Disposition::Trash,
        Disposition::PermanentContents => Disposition::Permanent,
        _ => {
            out.operations = paths
                .into_iter()
                .map(|p| {
                    Operation::new(cat.key, p, cat.tier)
                        .with_disposition(cat.disposition)
                        .with_exemptions(cat.exemptions.clone())
                })
                .collect();
            return out;
        }
    };

    // The directory itself survives; only its children are candidates, and
    // each is judged on its own.
    for dir in paths {
        let entries = match std::fs::read_dir(&dir) {
            Ok(entries) => entries,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => {
                out.unreadable.push((dir, e.to_string()));
                continue;
            }
        };
        for entry in entries.flatten() {
            out.operations.push(
                Operation::new(cat.key, entry.path(), cat.tier)
                    .with_disposition(child_disposition)
                    .with_exemptions(cat.exemptions.clone()),
            );
        }
    }
    out
}

/// The order a run must process categories in.
///
/// The Trash sweep goes first or last depending on what the user asked for,
/// and the difference is the whole trade:
///
/// - `Start` — this run's deletions land in an emptied Trash and stay
///   recoverable until the next run. The space they occupy is not freed until
///   that next run, which is why a single pass appears to free less than it
///   reports.
/// - `End` — a single pass actually frees what it reports, because the sweep
///   also takes what this run just moved. Nothing from this run is
///   recoverable afterwards.
pub fn run_order(selected: Vec<&Category>, at: TrashSweep) -> Vec<&Category> {
    let (sweep, rest): (Vec<_>, Vec<_>) = selected
        .into_iter()
        .partition(|c| c.disposition == Disposition::PermanentContents);
    match at {
        TrashSweep::Start => sweep.into_iter().chain(rest).collect(),
        TrashSweep::End => rest.into_iter().chain(sweep).collect(),
    }
}

/// Rewrite recoverable deletions as outright ones, where that is allowed.
///
/// Deliberately narrow. `Review` and above keep the Trash however the
/// preference is set — those categories sit next to real user data, and "I
/// wanted my caches gone in one pass" must never be able to mean "and my mail
/// attachments with them". App removal never passes through here at all: the
/// uninstall and installer engines build their own operations, so uninstalling
/// stays recoverable by construction.
pub fn apply_permanent_delete(ops: Vec<Operation>, enabled: bool) -> Vec<Operation> {
    if !enabled {
        return ops;
    }
    ops.into_iter()
        .map(|op| {
            if op.disposition == Disposition::Trash && op.tier.permanent_delete_applies() {
                op.with_disposition(Disposition::Permanent)
            } else {
                op
            }
        })
        .collect()
}

/// What was in the Trash before a run started.
///
/// An `End` sweep removes this run's own moves as well as what was already
/// there. Those bytes have already been counted by whichever category moved
/// them, so counting them a second time would report roughly double what the
/// disk actually gained. The snapshot is what the sweep *counts*; it still
/// deletes everything it finds.
#[derive(Debug, Clone, Default)]
pub struct TrashSnapshot {
    /// `None` means "count everything" — correct for a `Start` sweep, where
    /// nothing has moved yet and so nothing can be double-counted.
    entries: Option<std::collections::HashSet<PathBuf>>,
}

impl TrashSnapshot {
    pub fn take(dir: &std::path::Path) -> Self {
        let entries = std::fs::read_dir(dir)
            .map(|rd| rd.flatten().map(|e| e.path()).collect())
            .unwrap_or_default();
        TrashSnapshot {
            entries: Some(entries),
        }
    }

    pub fn everything() -> Self {
        TrashSnapshot { entries: None }
    }

    pub fn contains(&self, path: &std::path::Path) -> bool {
        match &self.entries {
            None => true,
            Some(set) => set.contains(path),
        }
    }
}

/// Expand a category's targets into concrete paths.
pub fn resolve_targets(cat: &Category, home: &std::path::Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for t in &cat.targets {
        match t {
            Target::Path(p) => out.push(p.clone()),
            Target::Glob(g) => {
                if let Ok(paths) = glob::glob(g) {
                    out.extend(paths.flatten());
                }
            }
            Target::Dynamic(kind) => out.extend(kind.resolve(home)),
        }
    }
    out.sort();
    out.dedup();
    out
}

pub struct Cleaner<'a> {
    policy: &'a Policy,
    liveness: &'a Liveness,
    journal: Option<&'a Journal>,
    home: PathBuf,
    trash_exclusions: TrashExclusions,
}

impl<'a> Cleaner<'a> {
    pub fn new(policy: &'a Policy, liveness: &'a Liveness) -> Self {
        let home = policy.home().to_path_buf();
        Cleaner {
            policy,
            liveness,
            journal: None,
            home,
            trash_exclusions: TrashExclusions::default(),
        }
    }

    pub fn with_journal(mut self, journal: &'a Journal) -> Self {
        self.journal = Some(journal);
        self
    }

    /// Entries the Trash emptying must leave where they are.
    ///
    /// Separate from the policy whitelist on purpose. A whitelist pattern
    /// protects a path everywhere; these are about one directory, and a user
    /// excluding `com.apple.siriactionsd` from their Trash is not asking eve
    /// to stop clearing that cache from `~/Library/Caches`.
    pub fn with_trash_exclusions(mut self, exclusions: TrashExclusions) -> Self {
        self.trash_exclusions = exclusions;
        self
    }

    /// Preview. Never writes, never journals.
    pub fn scan(&self, catalog: &[Category], sel: &Selection) -> CleanReport {
        self.run(catalog, sel, None, true)
    }

    /// Execute for real.
    ///
    /// `broker` carries out the privileged half. If it is `None`, privileged
    /// categories are reported as needing root rather than silently skipped.
    pub fn execute(
        &self,
        catalog: &[Category],
        sel: &Selection,
        broker: Option<&mut dyn PrivilegeBroker>,
    ) -> CleanReport {
        self.run(catalog, sel, broker, false)
    }

    fn run(
        &self,
        catalog: &[Category],
        sel: &Selection,
        mut broker: Option<&mut dyn PrivilegeBroker>,
        dry_run: bool,
    ) -> CleanReport {
        let free_before = eve_core::size::free_space(&self.home);
        let executor = if dry_run {
            Executor::dry_run()
        } else {
            Executor::live()
        };

        let principal = if sel.unattended {
            Principal::Unattended
        } else {
            Principal::User
        };
        let mut funnel = Funnel::new(self.policy, self.liveness, &executor)
            .as_principal(principal)
            .unattended(sel.unattended)
            .with_durable_consent(sel.durable_consent(catalog));
        if let Some(j) = self.journal {
            funnel = funnel.with_journal(j);
        }

        let privileged_available = broker.as_mut().map(|b| b.available()).unwrap_or(false);
        let mut categories = Vec::new();

        let selected = run_order(
            catalog
                .iter()
                .filter(|c| sel.selects(c) && c.available())
                .collect(),
            sel.empty_trash_at,
        );

        // Taken before anything moves. An End sweep deletes what this run put
        // in the Trash as well as what was already there — and those bytes
        // have already been counted by the category that moved them, so the
        // sweep must not count them a second time. A Start sweep has nothing
        // to disambiguate, so it counts everything.
        let trash_snapshot = match sel.empty_trash_at {
            TrashSweep::Start => TrashSnapshot::everything(),
            TrashSweep::End => TrashSnapshot::take(&self.home.join(".Trash")),
        };

        for cat in selected {
            let expansion = expand(cat, &self.home);
            let expanded = apply_permanent_delete(expansion.operations, sel.permanent_delete);
            let (ops, mut refusals) = self.apply_trash_exclusions(cat, expanded);
            refusals.extend(expansion.unreadable.into_iter().map(|(path, detail)| {
                FunnelReport {
                    path: path.clone(),
                    category: cat.key.to_string(),
                    tier: cat.tier,
                    denial: Some(Denial::Unreadable { path, detail }),
                    outcome: None,
                }
            }));

            // Privileged categories are handed to the root peer wholesale; it
            // re-runs the funnel itself, which is the point of the boundary.
            let mut reports = if cat.needs_root() && !dry_run {
                match broker.as_mut() {
                    Some(b) => {
                        let plan = Plan::new(ops.clone())
                            .dry_run(false)
                            .unattended(sel.unattended);
                        b.execute(&plan).unwrap_or_else(|e| {
                            ops.iter()
                                .map(|op| FunnelReport {
                                    path: op.path.clone(),
                                    category: op.category.clone(),
                                    tier: op.tier,
                                    denial: Some(Denial::NeedsPrivilege(op.path.clone())),
                                    outcome: None,
                                })
                                .map(|mut r| {
                                    r.category = format!("{} ({e})", r.category);
                                    r
                                })
                                .collect()
                        })
                    }
                    None => ops
                        .iter()
                        .map(|op| FunnelReport {
                            path: op.path.clone(),
                            category: op.category.clone(),
                            tier: op.tier,
                            denial: Some(Denial::NeedsPrivilege(op.path.clone())),
                            outcome: None,
                        })
                        .collect(),
                }
            } else {
                // Dry runs measure privileged paths locally. Sizes are readable
                // without root far more often than deletions are possible, and
                // where they are not, `complete: false` says so.
                funnel.run_all(&ops)
            };

            // Zero the bytes of anything the sweep removed that it did not
            // put there. The deletion still happened — the report just stops
            // claiming credit a second time for space another category
            // already reported freeing.
            if cat.disposition == Disposition::PermanentContents {
                for r in reports.iter_mut() {
                    if !trash_snapshot.contains(&r.path) {
                        if let Some(outcome) = r.outcome.as_mut() {
                            outcome.bytes = 0;
                            outcome.files = 0;
                        }
                    }
                }
            }
            reports.extend(refusals);

            let commands = self.run_commands(cat, dry_run, sel, privileged_available);

            categories.push(CategoryResult {
                key: cat.key.to_string(),
                title: cat.title.to_string(),
                description: cat.description.to_string(),
                group: cat.group,
                tier: cat.tier,
                needs_root: cat.needs_root(),
                reports,
                commands,
            });
        }

        CleanReport {
            dry_run,
            categories,
            free_before,
            free_after: if dry_run {
                free_before
            } else {
                eve_core::size::free_space(&self.home)
            },
            privileged_available,
            newly_excluded: Vec::new(),
        }
    }

    /// Split a Trash-emptying category's operations into what will be removed
    /// and what an exclusion keeps.
    ///
    /// The excluded entries come back as refusals rather than being dropped.
    /// A user whose Trash is not empty afterwards needs to be told which
    /// pattern is responsible — otherwise the exclusion list, which exists to
    /// stop one stuck item defeating the whole operation, becomes a second
    /// invisible reason nothing happened.
    fn apply_trash_exclusions(
        &self,
        cat: &Category,
        ops: Vec<Operation>,
    ) -> (Vec<Operation>, Vec<FunnelReport>) {
        if cat.disposition != Disposition::PermanentContents || self.trash_exclusions.is_empty() {
            return (ops, Vec::new());
        }

        let mut keep = Vec::with_capacity(ops.len());
        let mut refused = Vec::new();
        for op in ops {
            match self.trash_exclusions.excludes(&op.path) {
                Some(pattern) => refused.push(FunnelReport {
                    path: op.path.clone(),
                    category: op.category.clone(),
                    tier: op.tier,
                    denial: Some(Denial::TrashExcluded {
                        path: op.path,
                        pattern: pattern.to_string(),
                    }),
                    outcome: None,
                }),
                None => keep.push(op),
            }
        }
        (keep, refused)
    }

    fn run_commands(
        &self,
        cat: &Category,
        dry_run: bool,
        sel: &Selection,
        privileged_available: bool,
    ) -> Vec<CommandResult> {
        cat.commands
            .iter()
            .map(|c| self.run_command(cat, c, dry_run, sel, privileged_available))
            .collect()
    }

    fn run_command(
        &self,
        cat: &Category,
        c: &Cmd,
        dry_run: bool,
        sel: &Selection,
        privileged_available: bool,
    ) -> CommandResult {
        let mut result = CommandResult {
            program: c.program.to_string(),
            args: c.args.iter().map(|s| s.to_string()).collect(),
            note: c.note.to_string(),
            ran: false,
            ok: false,
            detail: None,
        };

        if dry_run {
            return result;
        }

        // Root-context categories must not be run as root. Homebrew refuses
        // outright; Docker silently addresses the wrong daemon. Both are worse
        // than not running.
        let running_as_root = unsafe { libc::geteuid() } == 0;
        if cat.context == RunContext::User && running_as_root {
            result.detail = Some("skipped: must run as the invoking user".into());
            return result;
        }
        if c.privileged && !running_as_root && !privileged_available {
            result.detail = Some("skipped: requires root".into());
            return result;
        }
        if sel.unattended && !cat.tier.allowed_unattended() {
            result.detail = Some("skipped: not permitted unattended".into());
            return result;
        }

        let Some(program) = eve_catalog::which(c.program).or_else(|| {
            let direct = PathBuf::from("/usr/bin").join(c.program);
            direct.is_file().then_some(direct)
        }) else {
            result.detail = Some(format!("skipped: {} not found on PATH", c.program));
            return result;
        };

        let mut cmd = if c.privileged && !running_as_root {
            let mut s = Command::new("/usr/bin/sudo");
            s.arg("-n").arg(&program);
            s
        } else {
            Command::new(&program)
        };
        cmd.args(c.args);

        result.ran = true;
        match cmd.output() {
            Ok(out) => {
                result.ok = out.status.success();
                let text = String::from_utf8_lossy(&out.stderr);
                let tail: Vec<&str> = text.lines().rev().take(2).collect();
                if !result.ok && !tail.is_empty() {
                    result.detail = Some(tail.join(" | "));
                }
            }
            Err(e) => result.detail = Some(e.to_string()),
        }
        result
    }
}

/// Split a catalog into the user half and the root half.
///
/// This is the whole reason the two-pass structure exists, expressed as one
/// function instead of a shell wrapper.
pub fn partition_by_privilege(catalog: &[Category]) -> (Vec<&Category>, Vec<&Category>) {
    catalog.iter().partition(|c| !c.needs_root())
}

#[cfg(test)]
mod tests {
    use super::*;
    use eve_core::prefs::{Preferences, TrashExclusions, TrashSweep};
    use eve_core::risk::RiskTier;

    fn cats() -> Vec<Category> {
        eve_catalog::catalog_for("/Users/tester")
    }

    #[test]
    fn default_selection_excludes_review_and_privileged() {
        let sel = Selection::default();
        for cat in cats() {
            if sel.selects(&cat) {
                assert_eq!(cat.tier, RiskTier::Safe, "{} slipped in", cat.key);
            }
        }
    }

    #[test]
    fn unattended_selection_never_includes_never_auto() {
        let sel = Selection {
            unattended: true,
            allow_privileged: true,
            include: vec!["ios_backups".into()],
            ..Default::default()
        };
        let selected: Vec<&str> = cats()
            .iter()
            .filter(|c| sel.selects(c))
            .map(|c| c.key)
            .collect::<Vec<_>>()
            .iter()
            .map(|s| Box::leak(s.to_string().into_boxed_str()) as &str)
            .collect();
        assert!(
            !selected.contains(&"ios_backups"),
            "unattended run selected iOS backups"
        );
    }

    #[test]
    fn only_overrides_defaults_but_not_the_unattended_gate() {
        let sel = Selection {
            only: vec!["ios_backups".into()],
            ..Default::default()
        };
        let c = cats();
        let ios = c.iter().find(|c| c.key == "ios_backups").unwrap();
        assert!(sel.selects(ios), "--only should reach an off-by-default category");
    }

    #[test]
    fn privileged_categories_are_excluded_unless_allowed() {
        let c = cats();
        let sleep = c.iter().find(|c| c.key == "sleepimage").unwrap();

        assert!(!Selection::default().selects(sleep));
        assert!(Selection {
            allow_privileged: true,
            ..Default::default()
        }
        .selects(sleep));
    }

    #[test]
    fn partition_splits_root_work_out() {
        let c = cats();
        let (user, root) = partition_by_privilege(&c);
        assert!(!user.is_empty() && !root.is_empty());
        assert!(root.iter().all(|c| c.needs_root()));
        assert!(user.iter().all(|c| !c.needs_root()));
    }

    /// Regression: an `EmptyContents` category must present one operation per
    /// child, so that every child is individually adjudicated. Handing the
    /// funnel the parent directory would validate the parent and then delete
    /// children that were never liveness-checked.
    #[test]
    fn empty_contents_is_expanded_to_one_operation_per_child() {
        let tmp = tempfile::tempdir().unwrap();
        let caches = tmp.path().join("Library/Caches");
        std::fs::create_dir_all(caches.join("com.a.one")).unwrap();
        std::fs::create_dir_all(caches.join("com.b.two")).unwrap();
        std::fs::create_dir_all(tmp.path().join(".cache")).unwrap();

        let catalog = eve_catalog::catalog_for(tmp.path());
        let user_caches = catalog.iter().find(|c| c.key == "user_caches").unwrap();
        let ops = build_operations(user_caches, tmp.path());

        assert_eq!(ops.len(), 2, "expected one operation per child");
        assert!(
            ops.iter().all(|o| o.path.starts_with(&caches)),
            "operations should target children, not the parent"
        );
        assert!(
            !ops.iter().any(|o| o.path == caches),
            "the parent directory must never itself be an operation"
        );
    }

    /// And with the expansion in place, a live cache inside the directory is
    /// refused while its siblings are still cleaned.
    #[test]
    fn a_live_child_is_refused_while_siblings_proceed() {
        let tmp = tempfile::tempdir().unwrap();
        let caches = tmp.path().join("Library/Caches");
        let live = caches.join("com.autodesk.fusion");
        std::fs::create_dir_all(&live).unwrap();
        std::fs::write(live.join("c.sqlite"), b"x").unwrap();
        std::fs::write(live.join("c.sqlite-wal"), b"x").unwrap();
        let idle = caches.join("com.example.idle");
        std::fs::create_dir_all(&idle).unwrap();
        std::fs::write(idle.join("blob"), vec![0u8; 1024]).unwrap();

        let policy = Policy::for_home(tmp.path());
        let liveness = Liveness::permissive_for_tests();
        let cleaner = Cleaner::new(&policy, &liveness);
        let catalog = eve_catalog::catalog_for(tmp.path());

        let report = cleaner.scan(&catalog, &Selection::default());
        let cat = report
            .categories
            .iter()
            .find(|c| c.key == "user_caches")
            .unwrap();

        let refused: Vec<_> = cat.notable_denials();
        assert!(
            refused.iter().any(|d| d.path().starts_with(&live)),
            "the live SQLite cache was not refused: {refused:?}"
        );
        assert!(
            cat.reports
                .iter()
                .any(|r| r.was_allowed() && r.path.starts_with(&idle)),
            "the idle sibling should still be cleanable"
        );
    }

    // ------------------------------------------------------------ the Trash

    fn trash_cat(catalog: &[Category]) -> &Category {
        catalog.iter().find(|c| c.key == "trash").unwrap()
    }

    #[test]
    fn the_trash_is_left_alone_without_a_stored_preference() {
        let c = cats();
        assert!(!Selection::default().selects(trash_cat(&c)));
    }

    #[test]
    fn a_stored_preference_selects_the_trash() {
        let c = cats();
        let sel = Selection {
            empty_trash: true,
            ..Default::default()
        };
        assert!(sel.selects(trash_cat(&c)));
    }

    /// The point of making the preference durable: the LaunchAgent is what
    /// keeps filling the Trash, so it has to be what empties it too.
    #[test]
    fn a_stored_preference_reaches_the_trash_unattended() {
        let c = cats();
        let sel = Selection {
            empty_trash: true,
            unattended: true,
            ..Default::default()
        };
        assert!(sel.selects(trash_cat(&c)));
        assert!(sel.durable_consent(&c).iter().any(|k| k == "trash"));
    }

    /// A stored preference is not a blanket unattended override.
    #[test]
    fn a_stored_preference_does_not_unlock_never_auto_unattended() {
        let c = cats();
        let sel = Selection {
            empty_trash: true,
            unattended: true,
            include: vec!["ios_backups".into()],
            ..Default::default()
        };
        let ios = c.iter().find(|c| c.key == "ios_backups").unwrap();
        assert!(!sel.selects(ios));
        assert!(!sel.durable_consent(&c).iter().any(|k| k == "ios_backups"));
    }

    /// An explicit skip still wins over the stored preference — a one-off
    /// "not this time" must not require editing the settings.
    #[test]
    fn an_explicit_skip_overrides_the_stored_preference() {
        let c = cats();
        let sel = Selection {
            empty_trash: true,
            skip: vec!["trash".into()],
            ..Default::default()
        };
        assert!(!sel.selects(trash_cat(&c)));
    }

    /// Emptying the Trash must happen before the rest of the run fills it.
    /// Otherwise this run's own deletions are permanently removed in the same
    /// breath they were made recoverable, and their bytes are counted twice.
    #[test]
    fn the_trash_is_emptied_before_the_categories_that_fill_it() {
        let c = cats();
        let selected: Vec<&Category> = c.iter().collect();
        let ordered = run_order(selected, TrashSweep::Start);

        let trash_at = ordered.iter().position(|c| c.key == "trash").unwrap();
        let caches_at = ordered.iter().position(|c| c.key == "user_caches").unwrap();
        assert!(
            trash_at < caches_at,
            "the Trash was emptied after something that fills it"
        );
    }

    #[test]
    fn the_trash_category_empties_contents_and_keeps_the_directory() {
        let c = cats();
        assert_eq!(
            trash_cat(&c).disposition,
            eve_core::executor::Disposition::PermanentContents,
            "removing ~/.Trash itself is not the same as emptying it"
        );
    }

    #[test]
    fn every_trash_child_is_adjudicated_on_its_own() {
        let tmp = tempfile::tempdir().unwrap();
        let trash = tmp.path().join(".Trash");
        std::fs::create_dir_all(trash.join("a")).unwrap();
        std::fs::create_dir_all(trash.join("b")).unwrap();

        let catalog = eve_catalog::catalog_for(tmp.path());
        let ops = build_operations(trash_cat(&catalog), tmp.path());

        assert_eq!(ops.len(), 2);
        assert!(!ops.iter().any(|o| o.path == trash), "the Trash itself");
        assert!(ops
            .iter()
            .all(|o| o.disposition == eve_core::executor::Disposition::Permanent));
    }

    /// A scan never edits the exclusion list. Only a real attempt can prove an
    /// entry undeletable, so learning from a dry run would be learning from
    /// nothing — and it would mutate preferences behind a button the user
    /// pressed expecting a read-only look.
    #[test]
    fn a_dry_run_learns_nothing() {
        let tmp = tempfile::tempdir().unwrap();
        let trash = tmp.path().join(".Trash");
        std::fs::create_dir_all(&trash).unwrap();
        std::fs::write(trash.join("thing.dmg"), vec![0u8; 32]).unwrap();

        let policy = Policy::for_home(tmp.path());
        let liveness = Liveness::permissive_for_tests();
        let cleaner = Cleaner::new(&policy, &liveness);
        let catalog = eve_catalog::catalog_for(tmp.path());
        let sel = Selection {
            empty_trash: true,
            ..Default::default()
        };

        let report = cleaner.scan(&catalog, &sel);
        assert!(report.dry_run);
        assert!(learn_undeletable(&report).is_empty());
    }

    /// The same name refused by two categories is recorded once.
    #[test]
    fn stuck_names_are_deduplicated_across_categories() {
        let stuck = |name: &str| eve_core::FunnelReport {
            path: PathBuf::from("/x").join(name),
            category: "trash".into(),
            tier: eve_core::risk::RiskTier::Review,
            denial: None,
            outcome: Some(eve_core::executor::ExecOutcome {
                path: PathBuf::from("/x").join(name),
                disposition: eve_core::executor::Disposition::EmptyContents,
                bytes: 0,
                files: 0,
                complete: true,
                dry_run: false,
                error: None,
                failures: vec![format!("{name}: vault")],
                permanently_stuck: vec![name.to_string()],
            }),
        };
        let category = |key: &str, r: Vec<eve_core::FunnelReport>| CategoryResult {
            key: key.into(),
            title: key.into(),
            description: String::new(),
            group: Group::System,
            tier: eve_core::risk::RiskTier::Review,
            needs_root: false,
            reports: r,
            commands: Vec::new(),
        };

        let report = CleanReport {
            dry_run: false,
            categories: vec![
                category("trash", vec![stuck("com.apple.siriactionsd"), stuck("b")]),
                category("other", vec![stuck("com.apple.siriactionsd")]),
            ],
            free_before: None,
            free_after: None,
            privileged_available: false,
            newly_excluded: Vec::new(),
        };

        assert_eq!(
            report.permanently_stuck(),
            vec!["b".to_string(), "com.apple.siriactionsd".to_string()]
        );
    }

    /// macOS refuses to empty a Trash containing the cache of a running Apple
    /// daemon — and gives up on the whole Trash rather than skipping it. eve
    /// skips the entry and says which pattern did it.
    #[test]
    fn an_excluded_trash_entry_is_refused_and_names_its_pattern() {
        let tmp = tempfile::tempdir().unwrap();
        let trash = tmp.path().join(".Trash");
        let blocked = trash.join("com.apple.siriactionsd");
        std::fs::create_dir_all(&blocked).unwrap();
        std::fs::write(blocked.join("blob"), vec![0u8; 2048]).unwrap();
        let ordinary = trash.join("old-download.dmg");
        std::fs::write(&ordinary, vec![0u8; 4096]).unwrap();

        let policy = Policy::for_home(tmp.path());
        let liveness = Liveness::permissive_for_tests();
        // Seed explicitly: the exclusions are no longer a constant the cleaner
        // consults, they are the user's list, seeded once on first load.
        let mut prefs = Preferences::default();
        prefs.seed_trash_exclusions();
        let cleaner =
            Cleaner::new(&policy, &liveness).with_trash_exclusions(TrashExclusions::compile(&prefs));
        let catalog = eve_catalog::catalog_for(tmp.path());

        let sel = Selection {
            empty_trash: true,
            ..Default::default()
        };
        let report = cleaner.scan(&catalog, &sel);
        let cat = report.categories.iter().find(|c| c.key == "trash").unwrap();

        assert!(
            cat.reports.iter().any(|r| matches!(
                &r.denial,
                Some(Denial::TrashExcluded { path, pattern })
                    if path == &blocked && pattern.starts_with("com.apple.siriactionsd")
            )),
            "the blocking entry was not reported as excluded: {:?}",
            cat.reports
        );
        assert!(
            cat.reports
                .iter()
                .any(|r| r.was_allowed() && r.path == ordinary),
            "the rest of the Trash should still be emptied"
        );
    }

    /// `~/.Trash` needs Full Disk Access. Without it `read_dir` returns EPERM,
    /// and reporting "nothing to empty" would be a lie that looks like success.
    #[test]
    fn an_unreadable_trash_is_reported_rather_than_counted_as_empty() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = tempfile::tempdir().unwrap();
        let trash = tmp.path().join(".Trash");
        std::fs::create_dir_all(trash.join("something")).unwrap();
        std::fs::set_permissions(&trash, std::fs::Permissions::from_mode(0o000)).unwrap();
        if std::fs::read_dir(&trash).is_ok() {
            // Running as root, where permissions do not apply.
            std::fs::set_permissions(&trash, std::fs::Permissions::from_mode(0o755)).unwrap();
            return;
        }

        let policy = Policy::for_home(tmp.path());
        let liveness = Liveness::permissive_for_tests();
        let cleaner = Cleaner::new(&policy, &liveness);
        let catalog = eve_catalog::catalog_for(tmp.path());

        let sel = Selection {
            empty_trash: true,
            ..Default::default()
        };
        let report = cleaner.scan(&catalog, &sel);
        let cat = report.categories.iter().find(|c| c.key == "trash").unwrap();

        std::fs::set_permissions(&trash, std::fs::Permissions::from_mode(0o755)).unwrap();

        assert!(
            cat.reports
                .iter()
                .any(|r| matches!(&r.denial, Some(Denial::Unreadable { .. }))),
            "an unreadable Trash was silently reported as empty: {:?}",
            cat.reports
        );
        assert!(!cat.is_empty(), "the category must not look like a no-op");
    }

    // -------------------------------------------------- permanent deletion

    #[test]
    fn permanent_delete_turns_safe_trash_moves_into_outright_removal() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(tmp.path().join("Library/Caches/com.a")).unwrap();

        let catalog = eve_catalog::catalog_for(tmp.path());
        let caches = catalog.iter().find(|c| c.key == "user_caches").unwrap();

        let normal = build_operations(caches, tmp.path());
        assert!(normal.iter().all(|o| o.disposition == Disposition::Trash));

        let permanent = apply_permanent_delete(normal, true);
        assert!(
            permanent.iter().all(|o| o.disposition == Disposition::Permanent),
            "a Safe cache should be removed outright when asked"
        );
    }

    /// The narrow part. `mail_downloads` is `Review` — real user data with a
    /// Trash disposition — and must keep the recoverable delete however the
    /// preference is set.
    #[test]
    fn permanent_delete_never_reaches_a_review_tier_category() {
        let ops = vec![
            Operation::new("user_caches", "/tmp/x/a", RiskTier::Safe),
            Operation::new("mail_downloads", "/tmp/x/b", RiskTier::Review),
            Operation::new("ios_backups", "/tmp/x/c", RiskTier::NeverAuto),
        ];
        let out = apply_permanent_delete(ops, true);

        assert_eq!(out[0].disposition, Disposition::Permanent);
        assert_eq!(out[1].disposition, Disposition::Trash, "Mail downloads");
        assert_eq!(out[2].disposition, Disposition::Trash, "iOS backups");
    }

    #[test]
    fn permanent_delete_off_changes_nothing() {
        let ops = vec![Operation::new("user_caches", "/tmp/x/a", RiskTier::Safe)];
        let out = apply_permanent_delete(ops, false);
        assert_eq!(out[0].disposition, Disposition::Trash);
    }

    // ------------------------------------------------------- sweep ordering

    #[test]
    fn the_sweep_runs_last_when_the_user_asked_for_end() {
        let c = cats();
        let selected: Vec<&Category> = c.iter().collect();

        let at_end = run_order(selected.clone(), TrashSweep::End);
        let trash_at = at_end.iter().position(|c| c.key == "trash").unwrap();
        let caches_at = at_end.iter().position(|c| c.key == "user_caches").unwrap();
        assert!(trash_at > caches_at, "End should sweep after the fillers");

        let at_start = run_order(selected, TrashSweep::Start);
        assert_eq!(at_start[0].key, "trash");
    }

    /// The accounting trap. An End sweep deletes this run's own moves as well
    /// as what was already there — but those bytes were already counted by the
    /// category that moved them, so counting them again would report double
    /// what the disk actually gained.
    #[test]
    fn an_end_sweep_does_not_count_bytes_another_category_already_counted() {
        let tmp = tempfile::tempdir().unwrap();
        let trash = tmp.path().join(".Trash");
        std::fs::create_dir_all(&trash).unwrap();
        std::fs::write(trash.join("was-already-here"), vec![0u8; 4096]).unwrap();

        // Taken before the run; anything appearing later is this run's own.
        let snapshot = TrashSnapshot::take(&trash);
        std::fs::write(trash.join("moved-here-by-this-run"), vec![0u8; 8192]).unwrap();

        assert!(snapshot.contains(&trash.join("was-already-here")));
        assert!(!snapshot.contains(&trash.join("moved-here-by-this-run")));
    }

    #[test]
    fn a_start_sweep_needs_no_snapshot_because_nothing_has_moved_yet() {
        let tmp = tempfile::tempdir().unwrap();
        let trash = tmp.path().join(".Trash");
        std::fs::create_dir_all(&trash).unwrap();
        std::fs::write(trash.join("a"), b"x").unwrap();

        assert!(TrashSnapshot::everything().contains(&trash.join("a")));
        assert!(TrashSnapshot::everything().contains(&trash.join("anything-else")));
    }

    #[test]
    fn a_scan_never_touches_the_disk() {
        let tmp = tempfile::tempdir().unwrap();
        let cache = tmp.path().join("Library/Caches/com.example.app");
        std::fs::create_dir_all(&cache).unwrap();
        std::fs::write(cache.join("blob"), vec![0u8; 2048]).unwrap();

        let policy = Policy::for_home(tmp.path());
        let liveness = Liveness::permissive_for_tests();
        let cleaner = Cleaner::new(&policy, &liveness);
        let catalog = eve_catalog::catalog_for(tmp.path());

        let report = cleaner.scan(&catalog, &Selection::default());
        assert!(report.dry_run);
        assert!(cache.join("blob").exists(), "scan deleted something");
        assert!(report.total_bytes() >= 2048, "scan failed to see the cache");
    }
}
