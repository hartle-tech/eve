//! Maintenance tasks that are not deletions.

use std::path::PathBuf;
use std::process::Command;

use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct Task {
    pub key: &'static str,
    pub title: &'static str,
    pub detail: &'static str,
    pub privileged: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct TaskResult {
    pub key: String,
    pub title: String,
    pub ran: bool,
    pub ok: bool,
    pub detail: Option<String>,
}

pub const TASKS: &[Task] = &[
    Task {
        key: "launchservices",
        title: "Rebuild the Launch Services database",
        detail: "Fixes duplicate or stale entries in Open With menus.",
        privileged: false,
    },
    Task {
        key: "broken_agents",
        title: "Remove broken login items",
        detail: "LaunchAgents whose target binary no longer exists.",
        privileged: false,
    },
    Task {
        key: "corrupt_prefs",
        title: "Remove corrupt preference files",
        detail: "Third-party plists that fail to parse.",
        privileged: false,
    },
    Task {
        key: "dns_cache",
        title: "Flush the DNS cache",
        detail: "Clears stale name resolution.",
        privileged: true,
    },
];

/// Rebuild the Launch Services database.
///
/// This is a whole-domain rescan, and it is deliberately a *user-triggered*
/// task rather than a step inside cleaning. Per-record removal is not
/// implementable: `lsregister -u` resolves the path before unregistering, so
/// on recent macOS it fails for exactly the records whose app is already gone.
pub fn rebuild_launch_services(dry_run: bool) -> TaskResult {
    let lsregister = "/System/Library/Frameworks/CoreServices.framework/Frameworks/\
                      LaunchServices.framework/Support/lsregister";
    let mut r = TaskResult {
        key: "launchservices".into(),
        title: "Rebuild the Launch Services database".into(),
        ran: false,
        ok: false,
        detail: None,
    };
    if !PathBuf::from(lsregister).exists() {
        r.detail = Some("lsregister not found".into());
        return r;
    }
    if dry_run {
        return r;
    }
    r.ran = true;
    match Command::new(lsregister)
        .args(["-kill", "-r", "-domain", "local", "-domain", "user"])
        .output()
    {
        Ok(o) => r.ok = o.status.success(),
        Err(e) => r.detail = Some(e.to_string()),
    }
    r
}

/// LaunchAgents whose program no longer exists.
///
/// A plist that cannot be read is *not* reported as broken. An unreadable file
/// says nothing about whether its target exists, and guessing in the
/// destructive direction is how a working login item gets deleted.
pub fn find_broken_agents(home: &std::path::Path) -> Vec<(PathBuf, String)> {
    let dir = home.join("Library/LaunchAgents");
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return Vec::new();
    };

    let mut out = Vec::new();
    for e in entries.flatten() {
        let p = e.path();
        if p.extension().map(|x| x != "plist").unwrap_or(true) {
            continue;
        }
        let Some(program) = plist_program(&p) else {
            continue; // Unreadable or no program key: not evidence of breakage.
        };
        // Only an absolute path can be judged; a bare name is resolved via
        // PATH at launch time and we cannot know launchd's PATH.
        if !program.starts_with('/') {
            continue;
        }
        if !PathBuf::from(&program).exists() {
            out.push((p, program));
        }
    }
    out
}

fn plist_program(plist: &std::path::Path) -> Option<String> {
    for key in ["Program", "ProgramArguments:0"] {
        let out = Command::new("/usr/libexec/PlistBuddy")
            .arg("-c")
            .arg(format!("Print :{key}"))
            .arg(plist)
            .output()
            .ok()?;
        if out.status.success() {
            let v = String::from_utf8_lossy(&out.stdout).trim().to_string();
            if !v.is_empty() {
                return Some(v);
            }
        }
    }
    None
}

/// Preference files that fail to parse.
pub fn find_corrupt_prefs(home: &std::path::Path) -> Vec<PathBuf> {
    let dir = home.join("Library/Preferences");
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return Vec::new();
    };
    entries
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().map(|x| x == "plist").unwrap_or(false))
        // Apple's own domains are managed by cfprefsd and must not be touched.
        .filter(|p| {
            !p.file_name()
                .map(|n| n.to_string_lossy().starts_with("com.apple."))
                .unwrap_or(false)
        })
        .filter(|p| {
            Command::new("/usr/bin/plutil")
                .arg("-lint")
                .arg(p)
                .output()
                .map(|o| !o.status.success())
                .unwrap_or(false)
        })
        .collect()
}

pub fn flush_dns(dry_run: bool) -> TaskResult {
    let mut r = TaskResult {
        key: "dns_cache".into(),
        title: "Flush the DNS cache".into(),
        ran: false,
        ok: false,
        detail: None,
    };
    if dry_run {
        return r;
    }
    let root = unsafe { libc::geteuid() } == 0;
    let mut cmd = if root {
        Command::new("/usr/bin/dscacheutil")
    } else {
        let mut c = Command::new("/usr/bin/sudo");
        c.arg("-n").arg("/usr/bin/dscacheutil");
        c
    };
    r.ran = true;
    match cmd.arg("-flushcache").output() {
        Ok(o) => r.ok = o.status.success(),
        Err(e) => r.detail = Some(e.to_string()),
    }
    r
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_launchagents_dir_yields_nothing() {
        let tmp = tempfile::tempdir().unwrap();
        assert!(find_broken_agents(tmp.path()).is_empty());
    }

    #[test]
    fn apple_domains_are_never_offered_as_corrupt() {
        let tmp = tempfile::tempdir().unwrap();
        let prefs = tmp.path().join("Library/Preferences");
        std::fs::create_dir_all(&prefs).unwrap();
        // Deliberately invalid, but an Apple domain.
        std::fs::write(prefs.join("com.apple.something.plist"), b"not a plist").unwrap();

        let found = find_corrupt_prefs(tmp.path());
        assert!(
            found.is_empty(),
            "an Apple-managed domain was offered for deletion"
        );
    }

    #[test]
    fn dry_run_tasks_do_not_execute() {
        assert!(!flush_dns(true).ran);
        assert!(!rebuild_launch_services(true).ran);
    }

    #[test]
    fn task_catalog_is_well_formed() {
        let mut keys: Vec<&str> = TASKS.iter().map(|t| t.key).collect();
        keys.sort_unstable();
        let n = keys.len();
        keys.dedup();
        assert_eq!(n, keys.len(), "duplicate task keys");
        assert!(TASKS.iter().all(|t| !t.title.is_empty()));
    }
}
