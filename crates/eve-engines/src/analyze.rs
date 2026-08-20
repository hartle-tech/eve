//! Disk usage analysis.
//!
//! Answers "what is actually using the space", which is the question a cleaner
//! cannot answer on its own — the biggest thing on a disk is usually not
//! cache, and saying so is more useful than reclaiming another 200 MB.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use rayon::prelude::*;
use serde::Serialize;
use walkdir::WalkDir;

#[derive(Debug, Clone, Serialize)]
pub struct Entry {
    pub path: PathBuf,
    pub name: String,
    pub bytes: u64,
    pub files: u64,
    pub is_dir: bool,
    /// True when this entry matches a known-cleanable pattern.
    pub cleanable: Option<&'static str>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Analysis {
    pub root: PathBuf,
    pub total_bytes: u64,
    pub entries: Vec<Entry>,
    pub complete: bool,
    pub elapsed_ms: u128,
}

impl Analysis {
    /// Largest first.
    pub fn ranked(&self) -> Vec<&Entry> {
        let mut v: Vec<&Entry> = self.entries.iter().collect();
        v.sort_by(|a, b| b.bytes.cmp(&a.bytes));
        v
    }

    pub fn cleanable_bytes(&self) -> u64 {
        self.entries
            .iter()
            .filter(|e| e.cleanable.is_some())
            .map(|e| e.bytes)
            .sum()
    }
}

/// Directory names that are reclaimable wherever they appear.
const CLEANABLE: &[(&str, &str)] = &[
    ("node_modules", "reinstallable with npm install"),
    ("target", "Rust build output"),
    ("__pycache__", "Python bytecode"),
    (".venv", "recreatable virtualenv"),
    ("venv", "recreatable virtualenv"),
    ("DerivedData", "Xcode build cache"),
    ("build", "build output"),
    ("dist", "build output"),
    (".gradle", "Gradle cache"),
    (".terraform", "provider cache"),
    ("Caches", "cache"),
    ("vm_bundles", "regenerable VM images"),
];

fn cleanable_reason(name: &str) -> Option<&'static str> {
    CLEANABLE
        .iter()
        .find(|(n, _)| *n == name)
        .map(|(_, why)| *why)
}

/// Analyse one level below `root`, sizing each child in parallel.
pub fn analyze(root: &Path, budget: Duration) -> Analysis {
    let started = Instant::now();
    let cancel = Arc::new(AtomicBool::new(false));

    let children: Vec<PathBuf> = match std::fs::read_dir(root) {
        Ok(entries) => entries.flatten().map(|e| e.path()).collect(),
        Err(_) => Vec::new(),
    };

    // Give every child the same slice of the budget rather than letting the
    // first huge directory consume all of it and starve the rest.
    let per_child = if children.is_empty() {
        budget
    } else {
        budget.max(Duration::from_secs(1))
    };

    let entries: Vec<Entry> = children
        .par_iter()
        .map(|p| {
            let meta = std::fs::symlink_metadata(p).ok();
            let is_dir = meta.as_ref().map(|m| m.is_dir()).unwrap_or(false)
                && !meta.as_ref().map(|m| m.is_symlink()).unwrap_or(false);
            let m = eve_core::size::measure_cancellable(p, per_child, &cancel);
            let name = p
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();
            Entry {
                cleanable: cleanable_reason(&name),
                path: p.clone(),
                name,
                bytes: m.bytes,
                files: m.files,
                is_dir,
            }
        })
        .collect();

    let total_bytes = entries.iter().map(|e| e.bytes).sum();
    Analysis {
        root: root.to_path_buf(),
        total_bytes,
        entries,
        complete: started.elapsed() <= budget,
        elapsed_ms: started.elapsed().as_millis(),
    }
}

/// Find the largest individual files under a root.
pub fn largest_files(root: &Path, limit: usize, budget: Duration) -> Vec<Entry> {
    let started = Instant::now();
    let heap = Mutex::new(Vec::<Entry>::new());

    for entry in WalkDir::new(root)
        .follow_links(false)
        .into_iter()
        .filter_map(std::result::Result::ok)
    {
        if started.elapsed() > budget {
            break;
        }
        let Ok(meta) = entry.metadata() else { continue };
        if !meta.is_file() {
            continue;
        }
        let mut h = heap.lock().unwrap();
        h.push(Entry {
            name: entry.file_name().to_string_lossy().into_owned(),
            path: entry.path().to_path_buf(),
            bytes: meta.len(),
            files: 1,
            is_dir: false,
            cleanable: None,
        });
        if h.len() > limit * 8 {
            h.sort_by(|a, b| b.bytes.cmp(&a.bytes));
            h.truncate(limit);
        }
    }

    let mut out = heap.into_inner().unwrap();
    out.sort_by(|a, b| b.bytes.cmp(&a.bytes));
    out.truncate(limit);
    out
}

/// Aggregate space by file extension.
pub fn by_extension(root: &Path, budget: Duration) -> Vec<(String, u64, u64)> {
    let started = Instant::now();
    let mut totals: HashMap<String, (u64, u64)> = HashMap::new();

    for entry in WalkDir::new(root)
        .follow_links(false)
        .into_iter()
        .filter_map(std::result::Result::ok)
    {
        if started.elapsed() > budget {
            break;
        }
        let Ok(meta) = entry.metadata() else { continue };
        if !meta.is_file() {
            continue;
        }
        let ext = entry
            .path()
            .extension()
            .map(|e| e.to_string_lossy().to_ascii_lowercase())
            .unwrap_or_else(|| "(none)".into());
        let slot = totals.entry(ext).or_insert((0, 0));
        slot.0 += meta.len();
        slot.1 += 1;
    }

    let mut out: Vec<(String, u64, u64)> = totals
        .into_iter()
        .map(|(k, (b, n))| (k, b, n))
        .collect();
    out.sort_by(|a, b| b.1.cmp(&a.1));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ranks_children_by_size() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(tmp.path().join("small")).unwrap();
        std::fs::create_dir_all(tmp.path().join("big")).unwrap();
        std::fs::write(tmp.path().join("small/f"), vec![0u8; 100]).unwrap();
        std::fs::write(tmp.path().join("big/f"), vec![0u8; 10_000]).unwrap();

        let a = analyze(tmp.path(), Duration::from_secs(10));
        let ranked = a.ranked();
        assert_eq!(ranked[0].name, "big");
        assert_eq!(a.total_bytes, 10_100);
    }

    #[test]
    fn flags_cleanable_directories() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(tmp.path().join("node_modules")).unwrap();
        std::fs::write(tmp.path().join("node_modules/f"), vec![0u8; 50]).unwrap();

        let a = analyze(tmp.path(), Duration::from_secs(5));
        let nm = a.entries.iter().find(|e| e.name == "node_modules").unwrap();
        assert!(nm.cleanable.is_some());
        assert_eq!(a.cleanable_bytes(), 50);
    }

    #[test]
    fn largest_files_are_ordered_and_capped() {
        let tmp = tempfile::tempdir().unwrap();
        for (i, size) in [10usize, 5000, 300].iter().enumerate() {
            std::fs::write(tmp.path().join(format!("f{i}")), vec![0u8; *size]).unwrap();
        }
        let top = largest_files(tmp.path(), 2, Duration::from_secs(5));
        assert_eq!(top.len(), 2);
        assert_eq!(top[0].bytes, 5000);
        assert_eq!(top[1].bytes, 300);
    }

    #[test]
    fn extension_totals_add_up() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("a.log"), vec![0u8; 100]).unwrap();
        std::fs::write(tmp.path().join("b.log"), vec![0u8; 200]).unwrap();
        std::fs::write(tmp.path().join("c.txt"), vec![0u8; 50]).unwrap();

        let ext = by_extension(tmp.path(), Duration::from_secs(5));
        let log = ext.iter().find(|(e, _, _)| e == "log").unwrap();
        assert_eq!(log.1, 300);
        assert_eq!(log.2, 2);
    }

    #[test]
    fn analysing_a_missing_root_is_empty_not_a_panic() {
        let a = analyze(Path::new("/nonexistent/eve"), Duration::from_secs(1));
        assert_eq!(a.total_bytes, 0);
        assert!(a.entries.is_empty());
    }
}
