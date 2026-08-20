use std::collections::HashSet;
use std::path::Path;
use std::process::Command;

use crate::error::Denial;

/// Stage 3 of the funnel.
///
/// # Why this exists
///
/// Deleting an open SQLite cache can send the owning helper into a loop
/// writing to unlinked files **until the volume fills**. eve's unattended
/// trigger fires precisely when the disk is nearly full, so hitting this
/// failure mode makes the triggering condition strictly worse and then
/// re-fires after the cooldown. This check is the difference between a cleaner
/// and a footgun.
///
/// # Why it is tri-state
///
/// "I could not tell" is not "it is idle". An unreadable process table, a
/// missing `lsof`, a probe that errors — all of them deny. The only outcome
/// that permits deletion is a positive determination that nothing owns the
/// path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LivenessVerdict {
    /// Positively determined that no owner is running.
    Idle,
    /// An owner is running.
    Running(String),
    /// Could not determine. Treated as `Running` — this is the fail-closed leg.
    Unknown(String),
}

impl LivenessVerdict {
    pub fn permits_deletion(&self) -> bool {
        matches!(self, LivenessVerdict::Idle)
    }

    fn detail(&self) -> String {
        match self {
            LivenessVerdict::Idle => "idle".into(),
            LivenessVerdict::Running(d) => d.clone(),
            LivenessVerdict::Unknown(d) => format!("undetermined: {d}"),
        }
    }
}

/// Snapshot of the running process table, taken once and reused.
///
/// Forking `ps` per candidate path would dominate the runtime of a scan that
/// examines thousands of directories.
pub struct Liveness {
    commands: Option<Vec<String>>,
    has_lsof: bool,
}

impl Default for Liveness {
    fn default() -> Self {
        Self::snapshot()
    }
}

impl Liveness {
    /// Capture the process table now.
    pub fn snapshot() -> Self {
        let commands = Command::new("/bin/ps")
            .args(["-axo", "command="])
            .output()
            .ok()
            .filter(|o| o.status.success())
            .map(|o| {
                String::from_utf8_lossy(&o.stdout)
                    .lines()
                    .map(|l| l.trim().to_string())
                    .filter(|l| !l.is_empty())
                    .collect()
            });

        let has_lsof = Path::new("/usr/sbin/lsof").exists() || Path::new("/usr/bin/lsof").exists();

        Liveness {
            commands,
            has_lsof,
        }
    }

    /// A snapshot that always reports `Idle`. Tests only — never wire this into
    /// a real run.
    pub fn permissive_for_tests() -> Self {
        Liveness {
            commands: Some(Vec::new()),
            has_lsof: true,
        }
    }

    /// Check a deletion candidate.
    ///
    /// Only reverse-DNS directories under a cache root are subject to owner
    /// detection; everything else is judged solely on the SQLite signal, which
    /// applies anywhere.
    pub fn check(&self, path: &Path) -> LivenessVerdict {
        if let Some(v) = self.sqlite_signal(path) {
            return v;
        }

        let Some(bundle) = reverse_dns_component(path) else {
            return LivenessVerdict::Idle;
        };

        let Some(commands) = &self.commands else {
            return LivenessVerdict::Unknown("process table unreadable".into());
        };

        if !self.has_lsof {
            return LivenessVerdict::Unknown("lsof unavailable".into());
        }

        let needles = owner_needles(&bundle);
        for cmd in commands {
            let lower = cmd.to_ascii_lowercase();
            for needle in &needles {
                if lower.contains(needle) {
                    return LivenessVerdict::Running(format!("{bundle} appears live"));
                }
            }
        }

        LivenessVerdict::Idle
    }

    /// Refuse a SQLite database whose write-ahead log companions are present.
    ///
    /// A `-wal`/`-shm` pair means a writer has the database open, or left it
    /// open. Either way the file is not ours to remove.
    fn sqlite_signal(&self, path: &Path) -> Option<LivenessVerdict> {
        let mut hits: Vec<String> = Vec::new();
        let mut scan = |p: &Path| {
            let name = p.file_name()?.to_string_lossy().to_string();
            let is_db = name.ends_with(".sqlite")
                || name.ends_with(".db")
                || name.ends_with(".sqlite3");
            if !is_db {
                return None;
            }
            for suffix in ["-wal", "-shm"] {
                let companion = p.with_file_name(format!("{name}{suffix}"));
                if companion.exists() {
                    hits.push(name.clone());
                    return Some(());
                }
            }
            None
        };

        if path.is_file() {
            scan(path);
        } else if path.is_dir() {
            // One level only: this is a cheap signal, not an exhaustive audit.
            if let Ok(entries) = std::fs::read_dir(path) {
                for e in entries.flatten().take(2000) {
                    scan(&e.path());
                }
            }
        }

        if hits.is_empty() {
            None
        } else {
            Some(LivenessVerdict::Running(format!(
                "open SQLite WAL: {}",
                hits.join(", ")
            )))
        }
    }

    /// Convenience wrapper producing a [`Denial`] directly.
    pub fn gate(&self, path: &Path) -> Result<(), Denial> {
        let verdict = self.check(path);
        if verdict.permits_deletion() {
            Ok(())
        } else {
            Err(Denial::LiveOwner {
                path: path.to_path_buf(),
                detail: verdict.detail(),
            })
        }
    }
}

/// Pull a reverse-DNS bundle identifier out of a path component.
///
/// `~/Library/Caches/com.apple.Safari` -> `com.apple.Safari`
fn reverse_dns_component(path: &Path) -> Option<String> {
    let name = path.file_name()?.to_string_lossy();
    let segments: Vec<&str> = name.split('.').collect();
    if segments.len() < 3 {
        return None;
    }
    if segments
        .iter()
        .any(|s| s.is_empty() || !s.chars().all(|c| c.is_alphanumeric() || c == '-' || c == '_'))
    {
        return None;
    }
    Some(name.to_string())
}

/// What to look for in a running process's command line.
///
/// Both the whole identifier (helpers frequently embed it) and the final
/// segment as an app-bundle path fragment (`/Safari.app/`), which is how GUI
/// apps actually appear in `ps` output.
fn owner_needles(bundle: &str) -> Vec<String> {
    let mut out = HashSet::new();
    out.insert(bundle.to_ascii_lowercase());
    if let Some(last) = bundle.rsplit('.').next() {
        if last.len() >= 3 {
            out.insert(format!("/{}.app/", last.to_ascii_lowercase()));
        }
    }
    out.into_iter().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_reverse_dns_names() {
        assert_eq!(
            reverse_dns_component(Path::new("/Users/tester/Library/Caches/com.apple.Safari")).as_deref(),
            Some("com.apple.Safari")
        );
        // Not reverse-DNS: too few segments.
        assert_eq!(
            reverse_dns_component(Path::new("/Users/tester/Library/Caches/Google")),
            None
        );
        // Not reverse-DNS: has a path-ish or spaced segment.
        assert_eq!(
            reverse_dns_component(Path::new("/Users/tester/Library/Caches/my cache.v2.tmp")),
            None
        );
    }

    /// The #1390 acceptance test: an open SQLite cache must be refused.
    #[test]
    fn refuses_a_sqlite_cache_with_a_live_wal() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("com.autodesk.fusion");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("cache.sqlite"), b"x").unwrap();
        std::fs::write(dir.join("cache.sqlite-shm"), b"x").unwrap();

        let l = Liveness::permissive_for_tests();
        let verdict = l.check(&dir);
        assert!(
            !verdict.permits_deletion(),
            "open SQLite WAL was not refused: {verdict:?}"
        );
        assert!(l.gate(&dir).is_err());
    }

    #[test]
    fn allows_a_sqlite_file_with_no_wal_companions() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("com.example.quiet");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("cache.sqlite"), b"x").unwrap();

        let l = Liveness::permissive_for_tests();
        assert!(l.check(&dir).permits_deletion());
    }

    #[test]
    fn unreadable_process_table_fails_closed() {
        let l = Liveness {
            commands: None,
            has_lsof: true,
        };
        let verdict = l.check(Path::new("/Users/tester/Library/Caches/com.apple.Safari"));
        assert!(matches!(verdict, LivenessVerdict::Unknown(_)));
        assert!(!verdict.permits_deletion(), "unknown must not permit deletion");
    }

    #[test]
    fn missing_lsof_fails_closed() {
        let l = Liveness {
            commands: Some(vec![]),
            has_lsof: false,
        };
        let verdict = l.check(Path::new("/Users/tester/Library/Caches/com.apple.Safari"));
        assert!(!verdict.permits_deletion());
    }

    #[test]
    fn a_running_owner_is_detected() {
        let l = Liveness {
            commands: Some(vec![
                "/Applications/Safari.app/Contents/MacOS/Safari".to_string()
            ]),
            has_lsof: true,
        };
        let verdict = l.check(Path::new("/Users/tester/Library/Caches/com.apple.Safari"));
        assert!(matches!(verdict, LivenessVerdict::Running(_)));
    }

    #[test]
    fn a_helper_embedding_the_bundle_id_is_detected() {
        let l = Liveness {
            commands: Some(vec![
                "/Users/tester/Library/Application Support/com.autodesk.fusion/helper --daemon"
                    .to_string(),
            ]),
            has_lsof: true,
        };
        let verdict = l.check(Path::new("/Users/tester/Library/Caches/com.autodesk.fusion"));
        assert!(matches!(verdict, LivenessVerdict::Running(_)));
    }

    #[test]
    fn non_bundle_directories_are_not_owner_checked() {
        let l = Liveness {
            commands: None, // would be Unknown if it were checked
            has_lsof: false,
        };
        assert!(l.check(Path::new("/tmp/some-build-dir")).permits_deletion());
    }
}
