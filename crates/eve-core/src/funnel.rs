use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::error::Denial;
use crate::executor::{Disposition, ExecOutcome, Executor};
use crate::journal::{Journal, Principal};
use crate::liveness::Liveness;
use crate::path::PathValidator;
use crate::policy::{Exemptions, Policy};
use crate::risk::RiskTier;

/// One requested deletion, fully described.
///
/// Operations are *data*. They cross the privilege boundary as typed values
/// and are re-validated on the far side — at no point does eve hand a shell
/// string to root.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Operation {
    pub category: String,
    pub path: PathBuf,
    pub disposition: Disposition,
    pub tier: RiskTier,
    #[serde(default)]
    pub exemptions: Exemptions,
}

impl Operation {
    pub fn new(category: impl Into<String>, path: impl Into<PathBuf>, tier: RiskTier) -> Self {
        Operation {
            category: category.into(),
            path: path.into(),
            disposition: Disposition::Trash,
            tier,
            exemptions: Exemptions::none(),
        }
    }

    pub fn with_disposition(mut self, d: Disposition) -> Self {
        self.disposition = d;
        self
    }

    pub fn with_exemptions(mut self, e: Vec<PathBuf>) -> Self {
        self.exemptions = Exemptions(e);
        self
    }
}

/// The verdict and, if it got that far, the result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunnelReport {
    pub path: PathBuf,
    pub category: String,
    pub tier: RiskTier,
    pub denial: Option<Denial>,
    pub outcome: Option<ExecOutcome>,
}

impl FunnelReport {
    pub fn was_allowed(&self) -> bool {
        self.denial.is_none()
    }

    pub fn bytes(&self) -> u64 {
        self.outcome.as_ref().map(|o| o.bytes).unwrap_or(0)
    }
}

/// The five-stage funnel. Every deletion in eve goes through exactly this.
pub struct Funnel<'a> {
    policy: &'a Policy,
    liveness: &'a Liveness,
    executor: &'a Executor,
    journal: Option<&'a Journal>,
    principal: Principal,
    unattended: bool,
}

impl<'a> Funnel<'a> {
    pub fn new(policy: &'a Policy, liveness: &'a Liveness, executor: &'a Executor) -> Self {
        Funnel {
            policy,
            liveness,
            executor,
            journal: None,
            principal: Principal::User,
            unattended: false,
        }
    }

    pub fn with_journal(mut self, journal: &'a Journal) -> Self {
        self.journal = Some(journal);
        self
    }

    pub fn as_principal(mut self, principal: Principal) -> Self {
        self.principal = principal;
        self
    }

    /// Mark this run as having no human present.
    ///
    /// This is not advisory. Tiers that are not `allowed_unattended` are
    /// refused outright, which is what stops an unattended low-disk run from
    /// reaching iPhone backups because someone forgot a flag.
    pub fn unattended(mut self, yes: bool) -> Self {
        self.unattended = yes;
        self
    }

    pub fn run(&self, op: &Operation) -> FunnelReport {
        let mut report = FunnelReport {
            path: op.path.clone(),
            category: op.category.clone(),
            tier: op.tier,
            denial: None,
            outcome: None,
        };

        match self.adjudicate(op) {
            Err(denial) => {
                report.denial = Some(denial);
                report
            }
            Ok(normalized) => {
                let outcome = self.executor.remove(&normalized, op.disposition);
                // Dry runs are not history. Every preview would otherwise
                // append hundreds of lines to the journal — and since the CLI
                // scans before every real run, the record of what was actually
                // deleted would be buried in what merely could have been.
                if let (Some(journal), false) = (self.journal, outcome.dry_run) {
                    // A journal write failure must not abort the run; the
                    // deletion already happened and losing the audit line is
                    // strictly better than losing the caller's work.
                    let _ = journal.record(
                        &op.category,
                        op.tier.as_str(),
                        self.principal,
                        &outcome,
                    );
                }
                report.outcome = Some(outcome);
                report
            }
        }
    }

    pub fn run_all(&self, ops: &[Operation]) -> Vec<FunnelReport> {
        ops.iter().map(|op| self.run(op)).collect()
    }

    /// Stages 1–3. Returns the normalized path if every gate passes.
    ///
    /// Public so a preview can show exactly what a real run would do: a
    /// preview that lists paths the funnel would refuse is a lie, and the
    /// only way to avoid telling it is to ask the same code the same question.
    pub fn adjudicate(&self, op: &Operation) -> Result<PathBuf, Denial> {
        // Stage 0: tier gate. Cheapest check, and the one with the worst
        // consequences if skipped.
        if self.unattended && !op.tier.allowed_unattended() {
            return Err(Denial::UnattendedRefused {
                path: op.path.clone(),
                tier: op.tier.as_str().to_string(),
            });
        }

        // Stage 1: syntax, symlinks, ancestor-symlink guard.
        let normalized = PathValidator::new(self.policy).validate(&op.path, &op.exemptions)?;

        // Stage 2: protection lists and whitelist.
        self.policy.check(&normalized, &op.exemptions)?;

        // Stage 3: is anything still using it?
        self.liveness.gate(&normalized)?;

        Ok(normalized)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn setup() -> (tempfile::TempDir, Policy) {
        let tmp = tempfile::tempdir().unwrap();
        let policy = Policy::for_home(tmp.path());
        (tmp, policy)
    }

    #[test]
    fn a_clean_cache_passes_every_gate() {
        let (tmp, policy) = setup();
        let cache = tmp.path().join("Library/Caches/com.example.app");
        std::fs::create_dir_all(&cache).unwrap();
        std::fs::write(cache.join("blob"), vec![0u8; 512]).unwrap();

        let liveness = Liveness::permissive_for_tests();
        let exec = Executor::dry_run();
        let funnel = Funnel::new(&policy, &liveness, &exec);

        let report = funnel.run(&Operation::new("caches", &cache, RiskTier::Safe));
        assert!(report.was_allowed(), "{:?}", report.denial);
        assert_eq!(report.bytes(), 512);
    }

    #[test]
    fn protected_user_data_is_refused_before_measurement() {
        let (tmp, policy) = setup();
        let docs = tmp.path().join("Documents");
        std::fs::create_dir_all(&docs).unwrap();

        let liveness = Liveness::permissive_for_tests();
        let exec = Executor::live();
        let funnel = Funnel::new(&policy, &liveness, &exec);

        let report = funnel.run(&Operation::new("oops", &docs, RiskTier::Safe));
        assert!(!report.was_allowed());
        assert!(docs.exists(), "refused path was deleted anyway");
    }

    /// The tier gate: an unattended run must not reach `NeverAuto`, even when
    /// the caller explicitly asked for it.
    #[test]
    fn unattended_runs_refuse_never_auto_tiers() {
        let (tmp, policy) = setup();
        let backups = tmp.path().join("Library/Application Support/MobileSync/Backup");
        std::fs::create_dir_all(&backups).unwrap();

        let liveness = Liveness::permissive_for_tests();
        let exec = Executor::live();

        let op = Operation::new("ios_backups", &backups, RiskTier::NeverAuto)
            .with_exemptions(vec![tmp.path().join("Library/Application Support/MobileSync")]);

        let unattended = Funnel::new(&policy, &liveness, &exec).unattended(true);
        let report = unattended.run(&op);
        assert!(matches!(
            report.denial,
            Some(Denial::UnattendedRefused { .. })
        ));
        assert!(backups.exists());

        // With a human present and an explicit exemption, it is permitted.
        let dry = Executor::dry_run();
        let interactive = Funnel::new(&policy, &liveness, &dry);
        assert!(interactive.run(&op).was_allowed());
    }

    #[test]
    fn a_live_sqlite_cache_is_refused_and_journalled_nowhere() {
        let (tmp, policy) = setup();
        let cache = tmp.path().join("Library/Caches/com.autodesk.fusion");
        std::fs::create_dir_all(&cache).unwrap();
        std::fs::write(cache.join("c.sqlite"), b"x").unwrap();
        std::fs::write(cache.join("c.sqlite-wal"), b"x").unwrap();

        let liveness = Liveness::permissive_for_tests();
        let exec = Executor::live();
        let funnel = Funnel::new(&policy, &liveness, &exec);

        let report = funnel.run(&Operation::new("caches", &cache, RiskTier::Safe));
        assert!(matches!(report.denial, Some(Denial::LiveOwner { .. })));
        assert!(cache.join("c.sqlite").exists());
    }

    #[test]
    fn allowed_deletions_are_journalled() {
        let (tmp, policy) = setup();
        let cache = tmp.path().join("Library/Caches/com.example.app");
        std::fs::create_dir_all(&cache).unwrap();

        let journal = Journal::open(tmp.path().join("j.jsonl")).unwrap();
        let liveness = Liveness::permissive_for_tests();
        let exec = Executor::live();
        let funnel = Funnel::new(&policy, &liveness, &exec).with_journal(&journal);

        funnel.run(&Operation::new("caches", &cache, RiskTier::Safe));
        assert_eq!(journal.read_all().unwrap().len(), 1);
    }

    /// A preview is not history. The CLI scans before every real run, so
    /// journalling dry runs would bury what was actually deleted under what
    /// merely could have been.
    #[test]
    fn dry_runs_are_not_journalled() {
        let (tmp, policy) = setup();
        let cache = tmp.path().join("Library/Caches/com.example.app");
        std::fs::create_dir_all(&cache).unwrap();
        std::fs::write(cache.join("blob"), vec![0u8; 64]).unwrap();

        let journal = Journal::open(tmp.path().join("j.jsonl")).unwrap();
        let liveness = Liveness::permissive_for_tests();
        let exec = Executor::dry_run();
        let funnel = Funnel::new(&policy, &liveness, &exec).with_journal(&journal);

        let report = funnel.run(&Operation::new("caches", &cache, RiskTier::Safe));
        assert!(report.was_allowed());
        assert!(report.bytes() > 0, "the preview should still report a size");
        assert!(
            journal.read_all().unwrap().is_empty(),
            "a dry run wrote to the journal"
        );
    }
}
