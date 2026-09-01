//! eve installing its own background agent.
//!
//! Previously this needed Ansible, a Rust toolchain and a checkout. That is a
//! reasonable ask of the person who wrote it and an absurd one of somebody who
//! downloaded an app, so eve writes its own LaunchAgent.
//!
//! # Why the agent runs the app's own executable
//!
//! macOS grants a permission to a *program*, identified by its code signature.
//! A helper binary beside the app is a different program, so it needs its own
//! Full Disk Access grant — which is exactly the "grant it twice, in two
//! places, one of them hidden" experience this is meant to remove.
//!
//! So the LaunchAgent's program is `current_exe()`: the same file the user
//! double-clicked. It is the same signature, so it is the same TCC subject,
//! so **one grant covers both**. The executable checks its arguments before it
//! opens a window — invoked with `autoclean` it does the unattended run and
//! exits, and no window is ever created.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

pub const LABEL: &str = "tech.hartle.eve.autoclean";

/// How often launchd runs the check. This is a `statfs` and an immediate exit
/// in the common case; the interval the user actually cares about is the
/// cooldown between real runs, which lives in preferences.
const POLL_SECONDS: u64 = 300;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentStatus {
    pub installed: bool,
    pub loaded: bool,
    pub plist: PathBuf,
    /// The executable launchd will run. Shown so the user can see it is the
    /// same one they granted access to.
    pub program: Option<PathBuf>,
}

pub fn plist_path() -> PathBuf {
    home()
        .join("Library/LaunchAgents")
        .join(format!("{LABEL}.plist"))
}

fn home() -> PathBuf {
    dirs::home_dir().unwrap_or_else(|| PathBuf::from("/"))
}

fn log_dir() -> PathBuf {
    home().join("Library/Logs/hartle.tech")
}

/// launchd hands jobs a bare PATH, under which brew, docker, npm and mise all
/// resolve to nothing — and eve gates whole categories behind a PATH lookup,
/// so those categories would silently not run. No error, no log line, just
/// missing reclaim.
fn agent_path_env() -> String {
    format!(
        "/opt/homebrew/bin:/opt/homebrew/sbin:{}/.local/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin",
        home().display()
    )
}

/// The plist, as a string, for a given program.
///
/// Separate from installing it so it can be tested without touching launchd.
pub fn plist_xml(program: &Path) -> String {
    let logs = log_dir();
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{LABEL}</string>
    <key>ProgramArguments</key>
    <array>
        <string>{program}</string>
        <string>autoclean</string>
    </array>
    <key>StartInterval</key>
    <integer>{POLL_SECONDS}</integer>
    <key>RunAtLoad</key>
    <false/>
    <key>StandardOutPath</key>
    <string>{logs}/launchd.out.log</string>
    <key>StandardErrorPath</key>
    <string>{logs}/launchd.err.log</string>
    <key>ProcessType</key>
    <string>Background</string>
    <key>LowPriorityIO</key>
    <true/>
    <key>EnvironmentVariables</key>
    <dict>
        <key>PATH</key>
        <string>{path}</string>
    </dict>
</dict>
</plist>
"#,
        program = program.display(),
        logs = logs.display(),
        path = agent_path_env(),
    )
}

/// Install and load the agent, pointing at this executable.
pub fn install() -> Result<PathBuf, String> {
    let program = std::env::current_exe().map_err(|e| format!("cannot locate eve: {e}"))?;
    install_program(&program)
}

pub fn install_program(program: &Path) -> Result<PathBuf, String> {
    let plist = plist_path();
    for dir in [plist.parent().map(Path::to_path_buf), Some(log_dir())]
        .into_iter()
        .flatten()
    {
        std::fs::create_dir_all(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    }

    // Written whole and renamed into place: launchd reads this file, and a
    // half-written plist is a job that will not load with an error naming the
    // file rather than the truncation.
    let tmp = plist.with_extension(format!("tmp.{}", std::process::id()));
    std::fs::write(&tmp, plist_xml(program)).map_err(|e| format!("{}: {e}", tmp.display()))?;
    std::fs::rename(&tmp, &plist).map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        format!("{}: {e}", plist.display())
    })?;

    // Replace any previous registration. `bootout` on a job that is not loaded
    // fails, and that failure is expected on a first install — hence ignored.
    let _ = launchctl(&["bootout", &gui_target()]);
    launchctl(&["bootstrap", &gui_domain(), &plist.to_string_lossy()])?;
    Ok(plist)
}

pub fn uninstall() -> Result<(), String> {
    let _ = launchctl(&["bootout", &gui_target()]);
    let plist = plist_path();
    if plist.exists() {
        std::fs::remove_file(&plist).map_err(|e| format!("{}: {e}", plist.display()))?;
    }
    Ok(())
}

pub fn status() -> AgentStatus {
    let plist = plist_path();
    let installed = plist.exists();
    AgentStatus {
        installed,
        loaded: launchctl(&["print", &gui_target()]).is_ok(),
        program: installed.then(|| program_in(&plist)).flatten(),
        plist,
    }
}

/// The program a already-installed plist points at.
///
/// Read back rather than assumed, because an agent installed by an older copy
/// of eve — or by the Ansible role — points somewhere else, and the difference
/// is exactly what decides whether one permission grant is enough.
fn program_in(plist: &Path) -> Option<PathBuf> {
    let xml = std::fs::read_to_string(plist).ok()?;
    let start = xml.find("<array>")? + "<array>".len();
    let end = xml[start..].find("</array>")? + start;
    let first = &xml[start..end];
    let open = first.find("<string>")? + "<string>".len();
    let close = first[open..].find("</string>")? + open;
    Some(PathBuf::from(first[open..close].trim()))
}

fn uid() -> u32 {
    // SAFETY: getuid always succeeds and only reads a process property.
    unsafe { libc::getuid() }
}

fn gui_domain() -> String {
    format!("gui/{}", uid())
}

fn gui_target() -> String {
    format!("gui/{}/{LABEL}", uid())
}

fn launchctl(args: &[&str]) -> Result<String, String> {
    let out = std::process::Command::new("/bin/launchctl")
        .args(args)
        .output()
        .map_err(|e| format!("launchctl: {e}"))?;
    if out.status.success() {
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    } else {
        Err(String::from_utf8_lossy(&out.stderr).trim().to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_agent_runs_the_executable_it_is_given() {
        let xml = plist_xml(Path::new("/Applications/eve.app/Contents/MacOS/eve"));
        assert!(xml.contains("<string>/Applications/eve.app/Contents/MacOS/eve</string>"));
        assert!(xml.contains("<string>autoclean</string>"));
    }

    /// The whole point of pointing launchd at the app's own binary: one code
    /// signature, one TCC subject, one Full Disk Access grant. A helper binary
    /// beside the app would need its own.
    #[test]
    fn the_program_is_read_back_so_a_stale_agent_can_be_spotted() {
        let tmp = tempfile::tempdir().unwrap();
        let plist = tmp.path().join("agent.plist");
        std::fs::write(&plist, plist_xml(Path::new("/Applications/eve.app/Contents/MacOS/eve"))).unwrap();

        assert_eq!(
            program_in(&plist),
            Some(PathBuf::from("/Applications/eve.app/Contents/MacOS/eve"))
        );
    }

    /// launchd hands jobs a bare PATH, and eve gates whole categories behind a
    /// PATH lookup — so without this, brew/docker/npm categories silently do
    /// not run and nothing says why.
    #[test]
    fn the_agent_gets_a_path_that_can_find_homebrew() {
        let xml = plist_xml(Path::new("/x/eve"));
        assert!(xml.contains("/opt/homebrew/bin"), "brew would not resolve");
    }

    #[test]
    fn the_plist_is_well_formed_enough_to_parse_back() {
        let xml = plist_xml(Path::new("/x/eve"));
        assert!(xml.starts_with("<?xml"));
        assert_eq!(xml.matches("<dict>").count(), xml.matches("</dict>").count());
        assert_eq!(xml.matches("<array>").count(), xml.matches("</array>").count());
    }

    /// RunAtLoad would fire a clean the moment the user grants permission,
    /// with no warning and no preview.
    #[test]
    fn installing_the_agent_does_not_immediately_clean() {
        assert!(plist_xml(Path::new("/x/eve")).contains("<key>RunAtLoad</key>\n    <false/>"));
    }
}
