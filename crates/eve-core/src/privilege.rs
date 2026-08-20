//! The privilege boundary.
//!
//! # Two eras
//!
//! **Now — [`SudoWorker`].** The parent spawns one worker via `sudo`, holds it
//! for the session, and speaks a typed protocol to it over the child's own
//! stdin/stdout. Those are inherited file descriptors: no unrelated process can
//! connect to them, which is the same property a socketpair would give. The
//! worker dies when the pipe closes, so root exists only while eve is running.
//!
//! **Later — an `SMAppService` daemon.** Blocked on a Developer ID signature,
//! which is why the [`PrivilegeBroker`] trait exists rather than the sudo path
//! being hardcoded.
//!
//! # The invariant
//!
//! The worker **re-runs the entire funnel as root**. It does not trust the
//! parent's verdict, only its request. A compromised or merely buggy parent
//! therefore cannot talk root into deleting something policy forbids.

use std::io::{BufRead, BufReader, Write};
use std::process::{Child, Command, Stdio};

use serde::{Deserialize, Serialize};

use crate::error::{EveError, Result};
use crate::executor::Executor;
use crate::funnel::{Funnel, FunnelReport, Operation};
use crate::journal::{Journal, Principal};
use crate::liveness::Liveness;
use crate::policy::Policy;

/// A batch of operations to be carried out at one privilege level.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Plan {
    pub operations: Vec<Operation>,
    pub dry_run: bool,
    pub unattended: bool,
}

impl Plan {
    pub fn new(operations: Vec<Operation>) -> Self {
        Plan {
            operations,
            dry_run: true,
            unattended: false,
        }
    }

    pub fn dry_run(mut self, yes: bool) -> Self {
        self.dry_run = yes;
        self
    }

    pub fn unattended(mut self, yes: bool) -> Self {
        self.unattended = yes;
        self
    }

    pub fn is_empty(&self) -> bool {
        self.operations.is_empty()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct WorkerResponse {
    reports: Vec<FunnelReport>,
}

/// How privileged work gets done.
pub trait PrivilegeBroker {
    /// Whether this broker can actually escalate right now.
    fn available(&mut self) -> bool;

    /// Carry out a plan at root.
    fn execute(&mut self, plan: &Plan) -> Result<Vec<FunnelReport>>;

    fn describe(&self) -> &'static str;
}

/// The transitional broker: one persistent `sudo` child per session.
pub struct SudoWorker {
    child: Option<Child>,
    /// `sudo -n`. Required for unattended runs, where there is no one to
    /// answer a prompt and a blocking `sudo` would hang forever.
    non_interactive: bool,
}

impl SudoWorker {
    pub fn interactive() -> Self {
        SudoWorker {
            child: None,
            non_interactive: false,
        }
    }

    pub fn unattended() -> Self {
        SudoWorker {
            child: None,
            non_interactive: true,
        }
    }

    fn spawn(&mut self) -> Result<()> {
        if self.child.is_some() {
            return Ok(());
        }
        let exe = worker_binary()?;

        let mut cmd = Command::new("/usr/bin/sudo");
        if self.non_interactive {
            cmd.arg("-n");
        }
        // Keep the sudo timestamp alive for the life of the worker rather than
        // re-prompting: one authentication per session is the contract.
        cmd.arg(&exe)
            .arg(WORKER_ARG)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit());

        let child = cmd
            .spawn()
            .map_err(|e| EveError::Privilege(format!("could not start privileged worker: {e}")))?;
        self.child = Some(child);
        Ok(())
    }
}

/// The hidden subcommand that turns the binary into its own privileged peer.
pub const WORKER_ARG: &str = "__worker";

/// Where the root-owned copy of eve lives.
///
/// A NOPASSWD sudoers rule is only a real security boundary if the binary it
/// names cannot be rewritten by the user it grants root to. Pointing the rule
/// at a user-writable path makes the scoping organisational rather than
/// enforceable — anything able to write that file gains passwordless root.
pub const PRIVILEGED_HELPER: &str = "/usr/local/libexec/eve";

/// Choose which binary to run as root.
///
/// Prefers the root-owned helper, and *verifies* the ownership rather than
/// assuming it: a helper at the expected path that is writable by the invoking
/// user would be worse than not having one, because it looks like a boundary
/// while providing none.
pub fn worker_binary() -> Result<std::path::PathBuf> {
    let helper = std::path::PathBuf::from(PRIVILEGED_HELPER);
    if let Ok(meta) = std::fs::metadata(&helper) {
        use std::os::unix::fs::MetadataExt;
        use std::os::unix::fs::PermissionsExt;
        let root_owned = meta.uid() == 0;
        let group_or_world_writable = meta.permissions().mode() & 0o022 != 0;
        if root_owned && !group_or_world_writable {
            return Ok(helper);
        }
    }
    std::env::current_exe()
        .map_err(|e| EveError::Privilege(format!("cannot locate own binary: {e}")))
}

impl PrivilegeBroker for SudoWorker {
    fn available(&mut self) -> bool {
        // Already root: no escalation needed or possible.
        // SAFETY: `geteuid` is always safe; it reads a process property.
        if unsafe { libc::geteuid() } == 0 {
            return true;
        }
        std::path::Path::new("/usr/bin/sudo").exists()
    }

    fn execute(&mut self, plan: &Plan) -> Result<Vec<FunnelReport>> {
        if plan.is_empty() {
            return Ok(Vec::new());
        }

        // Already root — run in-process, no child needed.
        // SAFETY: see above.
        if unsafe { libc::geteuid() } == 0 {
            return Ok(run_plan_as_root(plan, &TrustLocalPlans));
        }

        self.spawn()?;
        let child = self
            .child
            .as_mut()
            .ok_or_else(|| EveError::Privilege("worker vanished".into()))?;

        let stdin = child
            .stdin
            .as_mut()
            .ok_or_else(|| EveError::Privilege("worker stdin closed".into()))?;
        let line = serde_json::to_string(plan)?;
        writeln!(stdin, "{line}")
            .map_err(|e| EveError::Privilege(format!("worker write failed: {e}")))?;
        stdin.flush().ok();

        let stdout = child
            .stdout
            .as_mut()
            .ok_or_else(|| EveError::Privilege("worker stdout closed".into()))?;
        let mut reader = BufReader::new(stdout);
        let mut response = String::new();
        reader
            .read_line(&mut response)
            .map_err(|e| EveError::Privilege(format!("worker read failed: {e}")))?;

        if response.trim().is_empty() {
            return Err(EveError::Privilege(
                "privileged worker produced no response (authentication refused?)".into(),
            ));
        }

        let parsed: WorkerResponse = serde_json::from_str(response.trim())?;
        Ok(parsed.reports)
    }

    fn describe(&self) -> &'static str {
        "sudo worker (session-scoped)"
    }
}

impl Drop for SudoWorker {
    fn drop(&mut self) {
        // Closing stdin is the shutdown signal; the worker exits on EOF, and
        // root goes away with it.
        if let Some(mut child) = self.child.take() {
            drop(child.stdin.take());
            let _ = child.wait();
        }
    }
}

/// Decides whether root will even consider an operation.
///
/// The sudoers grant authorises *eve's categories*, not "delete anything eve's
/// protection rules happen not to cover". Without this, a caller holding the
/// grant could hand root a hand-written plan pointing anywhere the funnel does
/// not explicitly protect — which is an arbitrary-root-deletion primitive
/// dressed up as a narrowly scoped grant.
///
/// The authorizer is supplied by the binary rather than living here, because
/// the catalog is built on top of this crate and cannot be referenced from it.
pub trait PlanAuthorizer {
    /// True only if the catalog genuinely produces this operation.
    fn authorizes(&self, op: &Operation) -> bool;
}

/// Authorizes everything. For in-process use where the plan was built locally
/// and never crossed a privilege boundary.
pub struct TrustLocalPlans;

impl PlanAuthorizer for TrustLocalPlans {
    fn authorizes(&self, _op: &Operation) -> bool {
        true
    }
}

/// Execute a plan with root's own copy of the full funnel.
pub fn run_plan_as_root(plan: &Plan, authorizer: &dyn PlanAuthorizer) -> Vec<FunnelReport> {
    // The policy is rebuilt here from the *invoking* user's home, not root's.
    // Under `sudo`, `dirs::home_dir()` would return /var/root and every
    // home-relative protection rule would silently stop matching.
    let home = invoking_user_home();
    let policy = Policy::for_home(home).with_default_whitelist();
    let liveness = Liveness::snapshot();
    let executor = if plan.dry_run {
        Executor::dry_run()
    } else {
        Executor::live()
    };

    let journal = Journal::open_default().ok();
    let mut funnel = Funnel::new(&policy, &liveness, &executor)
        .as_principal(Principal::Root)
        .unattended(plan.unattended);
    if let Some(j) = &journal {
        funnel = funnel.with_journal(j);
    }

    // Gate 0, before the funnel sees anything: is this an operation eve would
    // ever have generated? Anything else is refused without being adjudicated,
    // because adjudicating it is what would make the grant too wide.
    plan.operations
        .iter()
        .map(|op| {
            if authorizer.authorizes(op) {
                funnel.run(op)
            } else {
                FunnelReport {
                    path: op.path.clone(),
                    category: op.category.clone(),
                    tier: op.tier,
                    denial: Some(crate::error::Denial::Protected {
                        path: op.path.clone(),
                        rule: "not produced by any catalog category".into(),
                    }),
                    outcome: None,
                }
            }
        })
        .collect()
}

/// The home directory of the user who invoked `sudo`, not root's.
pub fn invoking_user_home() -> std::path::PathBuf {
    if let Ok(user) = std::env::var("SUDO_USER") {
        if !user.is_empty() {
            let candidate = std::path::PathBuf::from("/Users").join(&user);
            if candidate.is_dir() {
                return candidate;
            }
        }
    }
    dirs::home_dir().unwrap_or_else(|| std::path::PathBuf::from("/"))
}

/// The worker main loop. One plan per line in, one response per line out.
///
/// Every plan is checked against `authorizer` before the funnel sees it — this
/// is the process that holds root, and it does not trust its caller.
pub fn worker_main(authorizer: &dyn PlanAuthorizer) -> Result<()> {
    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout();

    for line in stdin.lock().lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let plan: Plan = serde_json::from_str(&line)?;
        let reports = run_plan_as_root(&plan, authorizer);
        writeln!(stdout, "{}", serde_json::to_string(&WorkerResponse { reports })?)?;
        stdout.flush()?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::risk::RiskTier;

    #[test]
    fn plans_serialize_round_trip() {
        let plan = Plan::new(vec![Operation::new(
            "sleepimage",
            "/private/var/vm/sleepimage",
            RiskTier::Privileged,
        )])
        .dry_run(true)
        .unattended(true);

        let json = serde_json::to_string(&plan).unwrap();
        let back: Plan = serde_json::from_str(&json).unwrap();
        assert_eq!(back.operations.len(), 1);
        assert!(back.dry_run);
        assert!(back.unattended);
        assert_eq!(back.operations[0].tier, RiskTier::Privileged);
    }

    /// Refuses everything, standing in for a catalog that does not produce the
    /// operation a caller invented.
    struct RefuseAll;
    impl PlanAuthorizer for RefuseAll {
        fn authorizes(&self, _op: &Operation) -> bool {
            false
        }
    }

    /// Regression for the escalation the security review found.
    ///
    /// The sudoers grant names one command, so anyone holding it could hand
    /// root a hand-written plan. If root adjudicates arbitrary paths, the
    /// grant is an arbitrary-root-deletion primitive rather than "run eve's
    /// categories" — a path like /Library/LaunchDaemons/<x>.plist is absolute,
    /// has no traversal and is no cache, so it would clear every funnel gate.
    #[test]
    fn root_refuses_operations_no_category_produces() {
        let tmp = tempfile::tempdir().unwrap();
        let victim = tmp.path().join("com.vendor.security-agent.plist");
        std::fs::write(&victim, b"x").unwrap();

        let plan = Plan::new(vec![Operation::new(
            "invented",
            &victim,
            RiskTier::Privileged,
        )])
        .dry_run(false);

        let reports = run_plan_as_root(&plan, &RefuseAll);
        assert_eq!(reports.len(), 1);
        assert!(
            reports[0].denial.is_some(),
            "root carried out an operation no category produces"
        );
        assert!(
            victim.exists(),
            "the file was deleted despite being unauthorized"
        );
    }

    #[test]
    fn an_empty_plan_needs_no_escalation() {
        let mut broker = SudoWorker::interactive();
        let reports = broker.execute(&Plan::new(vec![])).unwrap();
        assert!(reports.is_empty());
    }

    #[test]
    fn invoking_user_home_prefers_sudo_user() {
        // With no SUDO_USER set we fall back to the real home; the important
        // property is that we never silently return /var/root.
        std::env::remove_var("SUDO_USER");
        let home = invoking_user_home();
        assert_ne!(home, std::path::PathBuf::from("/var/root"));
    }
}
