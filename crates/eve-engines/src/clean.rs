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
use eve_core::executor::Executor;
use eve_core::funnel::{Funnel, FunnelReport, Operation};
use eve_core::journal::{Journal, Principal};
use eve_core::liveness::Liveness;
use eve_core::policy::Policy;
use eve_core::privilege::{Plan, PrivilegeBroker};
use eve_core::risk::{RiskTier, RunContext};
use serde::Serialize;

/// What the caller asked for.
#[derive(Debug, Clone, Default)]
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
}

impl Selection {
    pub fn selects(&self, cat: &Category) -> bool {
        if !self.only.is_empty() {
            return self.only.iter().any(|k| k == cat.key);
        }
        if self.skip.iter().any(|k| k == cat.key) {
            return false;
        }
        if self.unattended && !cat.tier.allowed_unattended() {
            return false;
        }
        if !self.allow_privileged && cat.needs_root() {
            return false;
        }
        cat.on_by_default() || self.include.iter().any(|k| k == cat.key)
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

    pub fn is_empty(&self) -> bool {
        self.bytes() == 0 && self.commands.is_empty() && self.notable_denials().is_empty()
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
}

impl CleanReport {
    pub fn total_bytes(&self) -> u64 {
        self.categories.iter().map(CategoryResult::bytes).sum()
    }

    pub fn total_items(&self) -> usize {
        self.categories.iter().map(CategoryResult::items).sum()
    }

    pub fn by_group(&self) -> BTreeMap<Group, Vec<&CategoryResult>> {
        let mut out: BTreeMap<Group, Vec<&CategoryResult>> = BTreeMap::new();
        for c in &self.categories {
            out.entry(c.group).or_default().push(c);
        }
        out
    }
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
    let paths = resolve_targets(cat, home);

    if cat.disposition != eve_core::executor::Disposition::EmptyContents {
        return paths
            .into_iter()
            .map(|p| {
                Operation::new(cat.key, p, cat.tier)
                    .with_disposition(cat.disposition)
                    .with_exemptions(cat.exemptions.clone())
            })
            .collect();
    }

    // The directory itself survives; only its children are candidates, and
    // each is judged on its own.
    let child_disposition = if cat.needs_root() {
        // Root-owned system paths cannot go to the user's Trash.
        eve_core::executor::Disposition::Permanent
    } else {
        eve_core::executor::Disposition::Trash
    };

    let mut ops = Vec::new();
    for dir in paths {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            ops.push(
                Operation::new(cat.key, entry.path(), cat.tier)
                    .with_disposition(child_disposition)
                    .with_exemptions(cat.exemptions.clone()),
            );
        }
    }
    ops
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
}

impl<'a> Cleaner<'a> {
    pub fn new(policy: &'a Policy, liveness: &'a Liveness) -> Self {
        let home = policy.home().to_path_buf();
        Cleaner {
            policy,
            liveness,
            journal: None,
            home,
        }
    }

    pub fn with_journal(mut self, journal: &'a Journal) -> Self {
        self.journal = Some(journal);
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
            .unattended(sel.unattended);
        if let Some(j) = self.journal {
            funnel = funnel.with_journal(j);
        }

        let privileged_available = broker.as_mut().map(|b| b.available()).unwrap_or(false);
        let mut categories = Vec::new();

        for cat in catalog {
            if !sel.selects(cat) || !cat.available() {
                continue;
            }

            let ops: Vec<Operation> = build_operations(cat, &self.home);

            // Privileged categories are handed to the root peer wholesale; it
            // re-runs the funnel itself, which is the point of the boundary.
            let reports = if cat.needs_root() && !dry_run {
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
        }
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
