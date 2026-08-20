use std::fs::OpenOptions;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::error::Result;
use crate::executor::{Disposition, ExecOutcome};

/// Who asked for the operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Principal {
    User,
    Root,
    Unattended,
}

/// One line of the append-only journal.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JournalEntry {
    pub at: u64,
    pub session: String,
    pub category: String,
    pub path: PathBuf,
    pub disposition: Disposition,
    pub tier: String,
    pub principal: Principal,
    pub bytes: u64,
    pub files: u64,
    pub dry_run: bool,
    pub error: Option<String>,
}

impl JournalEntry {
    /// `YYYY-MM-DD HH:MM:SS` in UTC.
    pub fn timestamp(&self) -> String {
        format_epoch(self.at)
    }

    /// Whether this entry can be undone — only Trash moves are recoverable.
    pub fn recoverable(&self) -> bool {
        !self.dry_run
            && self.error.is_none()
            && matches!(self.disposition, Disposition::Trash | Disposition::EmptyContents)
    }
}

/// Stage 5 of the funnel: an append-only record of what happened.
///
/// Auditability is the whole point of an unattended cleaner. If eve ran at 3am
/// and the disk is different this morning, the journal is the only thing that
/// can say why.
pub struct Journal {
    path: PathBuf,
    session: String,
}

impl Journal {
    pub fn open_default() -> Result<Self> {
        let base = dirs::home_dir()
            .unwrap_or_else(|| PathBuf::from("/tmp"))
            .join("Library/Application Support/hartle.tech/eve");
        std::fs::create_dir_all(&base)?;
        Journal::open(base.join("journal.jsonl"))
    }

    pub fn open(path: impl Into<PathBuf>) -> Result<Self> {
        let path = path.into();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let session = format!(
            "{:x}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        );
        Ok(Journal { path, session })
    }

    pub fn session(&self) -> &str {
        &self.session
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn record(
        &self,
        category: &str,
        tier: &str,
        principal: Principal,
        outcome: &ExecOutcome,
    ) -> Result<()> {
        let entry = JournalEntry {
            at: now_secs(),
            session: self.session.clone(),
            category: category.to_string(),
            path: outcome.path.clone(),
            disposition: outcome.disposition,
            tier: tier.to_string(),
            principal,
            bytes: outcome.bytes,
            files: outcome.files,
            dry_run: outcome.dry_run,
            error: outcome.error.clone(),
        };
        self.append(&entry)
    }

    pub fn append(&self, entry: &JournalEntry) -> Result<()> {
        let mut f = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        writeln!(f, "{}", serde_json::to_string(entry)?)?;
        Ok(())
    }

    /// Read the journal back, newest last. Malformed lines are skipped rather
    /// than aborting the read — a truncated final write must not make the
    /// entire history unreadable.
    pub fn read_all(&self) -> Result<Vec<JournalEntry>> {
        Journal::read_from(&self.path)
    }

    pub fn read_from(path: &Path) -> Result<Vec<JournalEntry>> {
        let Ok(f) = std::fs::File::open(path) else {
            return Ok(Vec::new());
        };
        Ok(BufReader::new(f)
            .lines()
            .map_while(std::result::Result::ok)
            .filter_map(|l| serde_json::from_str(&l).ok())
            .collect())
    }
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Civil date from a Unix timestamp, UTC. Howard Hinnant's `civil_from_days`.
pub fn format_epoch(secs: u64) -> String {
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;

    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };

    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
        y,
        m,
        d,
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn outcome(path: &str, bytes: u64) -> ExecOutcome {
        ExecOutcome {
            path: PathBuf::from(path),
            disposition: Disposition::Trash,
            bytes,
            files: 1,
            complete: true,
            dry_run: false,
            error: None,
        }
    }

    #[test]
    fn round_trips_entries() {
        let tmp = tempfile::tempdir().unwrap();
        let j = Journal::open(tmp.path().join("j.jsonl")).unwrap();

        j.record("caches", "safe", Principal::User, &outcome("/a", 100))
            .unwrap();
        j.record("logs", "safe", Principal::Root, &outcome("/b", 200))
            .unwrap();

        let all = j.read_all().unwrap();
        assert_eq!(all.len(), 2);
        assert_eq!(all[0].category, "caches");
        assert_eq!(all[1].principal, Principal::Root);
        assert_eq!(all.iter().map(|e| e.bytes).sum::<u64>(), 300);
    }

    #[test]
    fn a_corrupt_line_does_not_destroy_the_history() {
        let tmp = tempfile::tempdir().unwrap();
        let p = tmp.path().join("j.jsonl");
        let j = Journal::open(&p).unwrap();
        j.record("caches", "safe", Principal::User, &outcome("/a", 100))
            .unwrap();

        // Simulate a torn final write.
        let mut f = OpenOptions::new().append(true).open(&p).unwrap();
        writeln!(f, "{{\"at\": 1, \"trunc").unwrap();

        let all = j.read_all().unwrap();
        assert_eq!(all.len(), 1, "one good line should survive a torn one");
    }

    #[test]
    fn missing_journal_reads_as_empty() {
        let entries = Journal::read_from(Path::new("/nonexistent/eve/journal.jsonl")).unwrap();
        assert!(entries.is_empty());
    }

    #[test]
    fn formats_epochs_as_utc_civil_time() {
        assert_eq!(format_epoch(0), "1970-01-01 00:00:00");
        assert_eq!(format_epoch(1_000_000_000), "2001-09-09 01:46:40");
        assert_eq!(format_epoch(1_755_000_000), "2025-08-12 12:00:00");
    }

    #[test]
    fn only_trash_moves_are_recoverable() {
        let mut e = JournalEntry {
            at: 0,
            session: "s".into(),
            category: "c".into(),
            path: "/a".into(),
            disposition: Disposition::Trash,
            tier: "safe".into(),
            principal: Principal::User,
            bytes: 1,
            files: 1,
            dry_run: false,
            error: None,
        };
        assert!(e.recoverable());

        e.disposition = Disposition::Permanent;
        assert!(!e.recoverable());

        e.disposition = Disposition::Trash;
        e.dry_run = true;
        assert!(!e.recoverable());
    }
}
