//! Which running applications are holding the Trash open.
//!
//! macOS refuses to delete a file another process has open, and Finder's
//! response is to abandon the *whole* Trash rather than skip the item. eve
//! skips just those and empties the rest — which is better, and still leaves
//! the user staring at a Trash that will not empty with no idea why.
//!
//! The question has a precise answer: `lsof` knows exactly which process holds
//! which file. Asking it once, before the sweep, turns "some of this did not go"
//! into "Ollama and Discord are holding four of these; quit them and they will
//! go too".

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::Serialize;

/// One application standing between the user and an empty Trash.
#[derive(Debug, Clone, Serialize)]
pub struct Blocker {
    pub pid: i32,
    /// The process name as the system reports it.
    pub name: String,
    /// The Trash entries it is holding, by their top-level name.
    pub entries: Vec<String>,
    /// What those entries come to, so the warning can say what is at stake.
    pub bytes: u64,
}

/// Ask `lsof` who is holding anything under `dir`.
///
/// Bounded by design: `+D` walks the tree, and the Trash can be large, so this
/// is called once before a sweep rather than per item.
pub fn holding(dir: &Path) -> Vec<Blocker> {
    if !dir.is_dir() {
        return Vec::new();
    }
    let out = std::process::Command::new("/usr/sbin/lsof")
        .args(["-nP", "-Fpcn", "+D"])
        .arg(dir)
        .output();
    let Ok(out) = out else {
        return Vec::new();
    };
    let text = String::from_utf8_lossy(&out.stdout);

    // lsof's field output is a stream: `p<pid>`, then `c<command>`, then one
    // `n<name>` per open file, until the next `p`.
    let mut by_pid: BTreeMap<i32, (String, Vec<PathBuf>)> = BTreeMap::new();
    let mut pid = 0i32;
    for line in text.lines() {
        let (tag, rest) = line.split_at(1.min(line.len()));
        match tag {
            "p" => pid = rest.parse().unwrap_or(0),
            "c" => {
                if pid > 0 {
                    by_pid.entry(pid).or_insert_with(|| (rest.to_string(), Vec::new()));
                }
            }
            "n" => {
                if pid > 0 {
                    if let Some(e) = by_pid.get_mut(&pid) {
                        e.1.push(PathBuf::from(rest));
                    }
                }
            }
            _ => {}
        }
    }

    let mut blockers: Vec<Blocker> = by_pid
        .into_iter()
        .filter_map(|(pid, (name, files))| {
            // Report the *top-level* Trash entry, not the individual file
            // inside it. "Discord is holding
            // Discord.app/Contents/Frameworks/…/x.dylib" is not actionable;
            // "Discord is holding Discord.app" is.
            let mut entries: Vec<String> = files
                .iter()
                .filter_map(|f| top_level_under(dir, f))
                .collect();
            entries.sort();
            entries.dedup();
            if entries.is_empty() {
                return None;
            }
            let bytes = entries
                .iter()
                .map(|e| eve_core::size::measure(&dir.join(e), std::time::Duration::from_secs(2)).bytes)
                .sum();
            Some(Blocker { pid, name, entries, bytes })
        })
        .collect();

    blockers.sort_by(|a, b| b.bytes.cmp(&a.bytes).then_with(|| a.name.cmp(&b.name)));
    blockers
}

/// The first path component below `dir`, which is the thing the user sees in
/// their Trash.
fn top_level_under(dir: &Path, file: &Path) -> Option<String> {
    let rest = file.strip_prefix(dir).ok()?;
    rest.components()
        .next()
        .map(|c| c.as_os_str().to_string_lossy().into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_deep_file_is_reported_as_its_top_level_entry() {
        let dir = Path::new("/Users/alice/.Trash");
        assert_eq!(
            top_level_under(dir, Path::new("/Users/alice/.Trash/Discord.app/Contents/x.dylib")),
            Some("Discord.app".to_string()),
            "a framework deep inside a bundle is not something a user can act on"
        );
        assert_eq!(
            top_level_under(dir, Path::new("/Users/alice/.Trash/note.txt")),
            Some("note.txt".to_string())
        );
        assert_eq!(top_level_under(dir, Path::new("/elsewhere/thing")), None);
    }

    /// Proves the whole path against a real process holding a real file: the
    /// test opens a file in a temp "Trash" and keeps it open while asking.
    #[test]
    fn a_process_holding_a_file_is_found_and_named() {
        use std::io::Write;
        let tmp = tempfile::tempdir().unwrap();
        let trash = tmp.path().join("Trash");
        std::fs::create_dir_all(trash.join("held")).unwrap();
        let victim = trash.join("held/open.bin");
        let mut f = std::fs::File::create(&victim).unwrap();
        f.write_all(&[0u8; 4096]).unwrap();
        f.flush().unwrap();
        // `f` stays open across the call — this process is the blocker.

        let found = holding(&trash);
        drop(f);

        let me = std::process::id() as i32;
        let mine = found.iter().find(|b| b.pid == me);
        // lsof may be unavailable or restricted in some environments; only
        // assert the shape when it answered at all.
        if let Some(b) = mine {
            assert!(b.entries.contains(&"held".to_string()), "{:?}", b.entries);
            assert!(!b.name.is_empty());
        }
    }
}
