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

/// Is this process being run as the privileged peer?
///
/// Split out so the rule is one testable thing rather than an argv comparison
/// copied into each binary — which is exactly how it came to be missing from
/// one of them.
pub fn is_worker_invocation<S: AsRef<str>>(args: &[S]) -> bool {
    args.len() == 2 && args[1].as_ref() == WORKER_ARG
}

/// Serve the privileged-peer role and exit, if that is what this invocation is.
///
/// **Every binary that can be elevated must call this before anything else.**
/// `AdminPrompt` elevates `current_exe()`, so the process macOS runs as root is
/// whichever binary the user was already running — and when the window gained
/// the administrator prompt, the app had no worker branch. Authenticating ran
/// `eve __worker`, fell through to `tauri::Builder::run()`, and **opened a
/// second window while removing nothing**. The plan was written, root was
/// granted, and no code ever read it.
///
/// Returning `bool` rather than diverging keeps the caller's own exit path
/// intact; a binary that ignores the result simply reintroduces the bug, which
/// is why both callers are one line.
pub fn serve_if_worker(authorizer: &dyn PlanAuthorizer) -> bool {
    let args: Vec<String> = std::env::args().collect();
    if !is_worker_invocation(&args) {
        return false;
    }
    if let Err(e) = worker_main(authorizer) {
        eprintln!("eve worker: {e}");
        std::process::exit(1);
    }
    true
}

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

/// Elevation through the macOS authentication dialog.
///
/// `sudo` cannot prompt without a controlling terminal, so from a window there
/// was no privileged path at all — the Applications screen could only tell the
/// user to go and open a terminal, for the single most ordinary thing a
/// cleaner does. `osascript … with administrator privileges` raises the
/// standard macOS admin dialog, which is the right prompt for a GUI app and
/// the same one Finder uses to move a system-owned app to the Trash.
///
/// **Never from launchd.** With no session to draw a dialog in, `do shell
/// script … with administrator privileges` blocks for ever rather than
/// failing. The unattended path must keep using [`SudoWorker::unattended`],
/// which is `sudo -n` and returns immediately when it cannot escalate.
///
/// One dialog per batch: the plan goes to a file, root's own copy of eve reads
/// it, re-runs the entire funnel, and writes its reports back. The channel is
/// a file rather than a pipe because `do shell script` gives no stdin — but
/// the security property is unchanged and never rested on the channel: root
/// re-adjudicates every operation against its own policy and its own
/// authorizer, so the worst a tampered plan can ask for is something eve would
/// have been willing to delete anyway.
pub struct AdminPrompt {
    prompt: String,
}

impl AdminPrompt {
    pub fn new(prompt: impl Into<String>) -> Self {
        AdminPrompt {
            prompt: prompt.into(),
        }
    }

    /// Quote a string for an AppleScript literal.
    fn applescript_literal(s: &str) -> String {
        s.replace('\\', r"\\").replace('"', r#"\""#)
    }

    /// Quote a path for `/bin/sh`, which is what `do shell script` runs.
    fn shell_single_quoted(p: &std::path::Path) -> String {
        format!("'{}'", p.to_string_lossy().replace('\'', r"'\''"))
    }
}

impl PrivilegeBroker for AdminPrompt {
    fn available(&mut self) -> bool {
        // A dialog can always be attempted from a session; whether the user
        // authenticates is their decision, not a capability question.
        std::env::current_exe().is_ok() && std::path::Path::new("/usr/bin/osascript").exists()
    }

    fn execute(&mut self, plan: &Plan) -> Result<Vec<FunnelReport>> {
        if plan.is_empty() {
            return Ok(Vec::new());
        }

        // **This** binary, not the root-owned helper at
        // [`PRIVILEGED_HELPER`]. That preference exists because a *standing*
        // NOPASSWD sudoers rule must name a binary the user cannot rewrite —
        // otherwise the grant is unbounded. An interactive administrator
        // prompt is not a standing grant: it is one authorisation, for one
        // batch, given knowingly, exactly as an installer receives one.
        //
        // Preferring the helper here also made the elevated side *stale*. The
        // copy on this machine was a day old and predated uninstall
        // operations existing at all, so root faithfully refused every one of
        // them — the privileged path ran, asked for a password, and reported
        // "not produced by any catalog category".
        let worker = std::env::current_exe()
            .map_err(|e| EveError::Privilege(format!("cannot locate this executable: {e}")))?;

        // A directory only this user can enter, created fresh per batch.
        let dir = std::env::temp_dir().join(format!("eve-admin-{}", std::process::id()));
        std::fs::create_dir_all(&dir)?;
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;
        }
        let plan_path = dir.join("plan.json");
        let out_path = dir.join("reports.json");
        std::fs::write(&plan_path, format!("{}\n", serde_json::to_string(plan)?))?;

        let command = format!(
            "{} {} < {} > {}",
            Self::shell_single_quoted(&worker),
            WORKER_ARG,
            Self::shell_single_quoted(&plan_path),
            Self::shell_single_quoted(&out_path),
        );
        let script = format!(
            "do shell script \"{}\" with administrator privileges with prompt \"{}\"",
            Self::applescript_literal(&command),
            Self::applescript_literal(&self.prompt),
        );

        let out = Command::new("/usr/bin/osascript")
            .arg("-e")
            .arg(&script)
            .output()
            .map_err(|e| EveError::Privilege(format!("could not show the admin prompt: {e}")))?;

        let response = std::fs::read_to_string(&out_path).unwrap_or_default();
        let _ = std::fs::remove_file(&plan_path);
        let _ = std::fs::remove_file(&out_path);
        let _ = std::fs::remove_dir(&dir);

        if !out.status.success() {
            let err = String::from_utf8_lossy(&out.stderr);
            // -128 is the user pressing Cancel. That is a decision, not a fault.
            if err.contains("-128") || err.contains("User canceled") {
                return Err(EveError::Privilege(
                    "administrator rights were not granted, so nothing was removed".into(),
                ));
            }
            return Err(EveError::Privilege(format!(
                "the privileged run failed: {}",
                err.trim()
            )));
        }

        let line = response.lines().find(|l| !l.trim().is_empty()).unwrap_or("");
        if line.is_empty() {
            return Err(EveError::Privilege(
                "the privileged worker produced no response".into(),
            ));
        }
        let parsed: WorkerResponse = serde_json::from_str(line)?;
        Ok(parsed.reports)
    }

    fn describe(&self) -> &'static str {
        "macOS administrator prompt"
    }
}

/// Run one Apple-shipped system binary as root, behind the administrator
/// prompt.
///
/// Deliberately not a general "run this as root" door. `program` must be an
/// absolute path under `/usr` or `/sbin` that already exists, and the argument
/// list is passed by the caller as literals — so the only things reachable
/// through here are tools Apple installed, and nothing a plan file, a
/// preference or a UI field can influence.
///
/// The deletion path does not use this: it needs root to re-run the whole
/// funnel, which is what [`AdminPrompt::execute`] and the worker protocol
/// exist for. This is for the handful of maintenance commands that are a
/// single fixed invocation, `purge` being the first.
pub fn run_system_command_as_admin(program: &str, args: &[&str], prompt: &str) -> Result<()> {
    let p = std::path::Path::new(program);
    let allowed = p.is_absolute()
        && (program.starts_with("/usr/bin/")
            || program.starts_with("/usr/sbin/")
            || program.starts_with("/sbin/"))
        && p.exists();
    if !allowed {
        return Err(EveError::Privilege(format!(
            "{program} is not an Apple-shipped system command"
        )));
    }
    // A space or a quote in an argument would end up inside the AppleScript
    // string and then inside `/bin/sh`. Callers pass literals, so refusing is
    // free — and it means a future caller cannot turn this into an injection
    // by passing something it read from disk.
    if args
        .iter()
        .any(|a| a.chars().any(|c| !c.is_ascii_alphanumeric() && !"-_.".contains(c)))
    {
        return Err(EveError::Privilege(
            "system command arguments must be plain flags".into(),
        ));
    }

    let command = std::iter::once(AdminPrompt::shell_single_quoted(p))
        .chain(args.iter().map(|a| (*a).to_string()))
        .collect::<Vec<_>>()
        .join(" ");
    let script = format!(
        "do shell script \"{}\" with administrator privileges with prompt \"{}\"",
        AdminPrompt::applescript_literal(&command),
        AdminPrompt::applescript_literal(prompt),
    );

    let out = Command::new("/usr/bin/osascript")
        .arg("-e")
        .arg(&script)
        .output()
        .map_err(|e| EveError::Privilege(format!("could not show the admin prompt: {e}")))?;
    if out.status.success() {
        return Ok(());
    }
    let err = String::from_utf8_lossy(&out.stderr);
    if err.contains("-128") || err.contains("User canceled") {
        return Err(EveError::Privilege(
            "administrator rights were not granted".into(),
        ));
    }
    Err(EveError::Privilege(err.trim().to_string()))
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
    let (home, uid, gid) = invoking_user();
    // Root re-reads the user's locks from their own settings rather than
    // taking the caller's word for them.
    let locks = crate::prefs::Preferences::load_default()
        .unwrap_or_default()
        .locked_paths;
    let policy = Policy::for_home(&home)
        .with_default_whitelist()
        .with_locks(locks);
    let liveness = Liveness::snapshot();
    let executor = if plan.dry_run {
        Executor::dry_run()
    } else {
        // Recoverable deletions land in the *user's* Trash, owned by them.
        // NSFileManager would use root's, where they could neither see the
        // item nor empty it to get the space back.
        Executor::live().trashing_into(home.join(".Trash"), uid, gid)
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
    invoking_user().0
}

/// Who asked, as root can determine it for itself: home, uid, gid.
///
/// Derived from the system, never from the request. Root must not take the
/// caller's word for whose home this is — a claimed home is a claimed set of
/// protection rules, and pointing them somewhere empty is how you get root to
/// treat the real one as unprotected.
///
/// `SUDO_USER` covers the `sudo` path. It is **absent** under the macOS
/// administrator dialog, because `do shell script … with administrator
/// privileges` does not go through sudo at all — so the owner of `/dev/console`
/// is the fallback, which is precisely the person sitting in front of the
/// window that raised the prompt.
pub fn invoking_user() -> (std::path::PathBuf, u32, u32) {
    fn by_name(name: &str) -> Option<(std::path::PathBuf, u32, u32)> {
        let c = std::ffi::CString::new(name).ok()?;
        // SAFETY: getpwnam returns a pointer into a static buffer or null; we
        // copy out of it immediately and never retain it.
        unsafe {
            let pw = libc::getpwnam(c.as_ptr());
            if pw.is_null() {
                return None;
            }
            let dir = std::ffi::CStr::from_ptr((*pw).pw_dir).to_string_lossy().into_owned();
            Some((std::path::PathBuf::from(dir), (*pw).pw_uid, (*pw).pw_gid))
        }
    }
    fn by_uid(uid: u32) -> Option<(std::path::PathBuf, u32, u32)> {
        // SAFETY: as above.
        unsafe {
            let pw = libc::getpwuid(uid);
            if pw.is_null() {
                return None;
            }
            let dir = std::ffi::CStr::from_ptr((*pw).pw_dir).to_string_lossy().into_owned();
            Some((std::path::PathBuf::from(dir), (*pw).pw_uid, (*pw).pw_gid))
        }
    }

    if let Ok(user) = std::env::var("SUDO_USER") {
        if !user.is_empty() {
            if let Some(found) = by_name(&user) {
                return found;
            }
        }
    }
    // The GUI session's owner.
    if let Ok(meta) = std::fs::metadata("/dev/console") {
        use std::os::unix::fs::MetadataExt;
        if meta.uid() != 0 {
            if let Some(found) = by_uid(meta.uid()) {
                return found;
            }
        }
    }
    let home = dirs::home_dir().unwrap_or_else(|| std::path::PathBuf::from("/"));
    // SAFETY: getuid/getgid cannot fail.
    unsafe { (home, libc::getuid(), libc::getgid()) }
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

    /// Regression: the app had no worker branch at all, so elevating it ran
    /// `eve __worker`, fell through to Tauri, and opened a second window while
    /// removing nothing. The rule is one function now, and both binaries call
    /// it as their first statement.
    #[test]
    fn the_worker_invocation_is_exactly_one_bare_argument() {
        assert!(is_worker_invocation(&["eve", WORKER_ARG]));

        // Anything else is a normal run and must reach the real entry point.
        assert!(!is_worker_invocation(&["eve"]));
        assert!(!is_worker_invocation(&["eve", "autoclean"]));
        assert!(!is_worker_invocation(&["eve", "clean", "--execute"]));
        // Not a prefix match, and not a subcommand somebody can smuggle in
        // behind another argument.
        assert!(!is_worker_invocation(&["eve", "__workers"]));
        assert!(!is_worker_invocation(&["eve", "clean", WORKER_ARG]));
        assert!(!is_worker_invocation(&["eve", WORKER_ARG, "extra"]));
    }

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
