//! Leftover installer files: disk images, packages and archives that were
//! downloaded, used once, and never removed.

use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use serde::Serialize;
use walkdir::WalkDir;

#[derive(Debug, Clone, Serialize)]
pub struct Installer {
    pub path: PathBuf,
    pub bytes: u64,
    pub age_days: u64,
    pub kind: &'static str,
}

const KINDS: &[(&str, &str)] = &[
    ("dmg", "disk image"),
    ("pkg", "installer package"),
    ("mpkg", "installer package"),
    ("iso", "disc image"),
];

/// Archives are only offered when an identically-named directory sits beside
/// them — evidence the archive was already extracted and is now redundant.
const ARCHIVE_EXTS: &[&str] = &["zip", "tar", "gz", "tgz", "xz", "bz2"];

fn kind_for(path: &Path) -> Option<&'static str> {
    let ext = path.extension()?.to_string_lossy().to_ascii_lowercase();
    if let Some((_, label)) = KINDS.iter().find(|(e, _)| *e == ext) {
        return Some(label);
    }
    if ARCHIVE_EXTS.contains(&ext.as_str()) {
        let stem = path.file_stem()?;
        let sibling = path.with_file_name(stem);
        // `foo.tar.gz` -> strip twice before comparing.
        let sibling = if sibling.extension().is_some() {
            sibling.with_extension("")
        } else {
            sibling
        };
        if sibling.is_dir() {
            return Some("extracted archive");
        }
    }
    None
}

/// Scan the usual landing zones for installers older than `min_age_days`.
pub fn find(home: &Path, min_age_days: u64, budget: Duration) -> Vec<Installer> {
    let roots = [
        home.join("Downloads"),
        home.join("Desktop"),
        home.join("Documents"),
    ];
    let started = SystemTime::now();
    let cutoff = SystemTime::now() - Duration::from_secs(min_age_days * 86_400);
    let mut out = Vec::new();

    for root in roots {
        if !root.is_dir() {
            continue;
        }
        for entry in WalkDir::new(&root)
            .max_depth(3)
            .follow_links(false)
            .into_iter()
            .filter_map(std::result::Result::ok)
        {
            if started.elapsed().map(|e| e > budget).unwrap_or(false) {
                return out;
            }
            let Ok(meta) = entry.metadata() else { continue };
            if !meta.is_file() {
                continue;
            }
            let Some(kind) = kind_for(entry.path()) else {
                continue;
            };
            let Ok(modified) = meta.modified() else {
                continue;
            };
            if modified > cutoff {
                continue;
            }
            let age_days = SystemTime::now()
                .duration_since(modified)
                .map(|d| d.as_secs() / 86_400)
                .unwrap_or(0);
            out.push(Installer {
                path: entry.path().to_path_buf(),
                bytes: meta.len(),
                age_days,
                kind,
            });
        }
    }

    out.sort_by(|a, b| b.bytes.cmp(&a.bytes));
    out
}

/// Turn findings into funnel operations.
///
/// These live in Downloads, Desktop and Documents — the last of which the
/// policy protects. The exemption is declared per file, never for the folder.
pub fn to_operations(found: &[Installer]) -> Vec<eve_core::funnel::Operation> {
    use eve_core::executor::Disposition;
    use eve_core::funnel::Operation;
    use eve_core::risk::RiskTier;

    found
        .iter()
        .map(|i| {
            Operation::new("installer", &i.path, RiskTier::Review)
                .with_disposition(Disposition::Trash)
                .with_exemptions(vec![i.path.clone()])
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognises_disk_images_and_packages() {
        assert_eq!(kind_for(Path::new("/x/App.dmg")), Some("disk image"));
        assert_eq!(kind_for(Path::new("/x/Tool.pkg")), Some("installer package"));
        assert_eq!(kind_for(Path::new("/x/notes.txt")), None);
    }

    #[test]
    fn archives_are_only_offered_when_already_extracted() {
        let tmp = tempfile::tempdir().unwrap();
        let lone = tmp.path().join("thing.zip");
        std::fs::write(&lone, b"x").unwrap();
        assert_eq!(kind_for(&lone), None, "unextracted archive was offered");

        std::fs::create_dir_all(tmp.path().join("thing")).unwrap();
        assert_eq!(kind_for(&lone), Some("extracted archive"));
    }

    #[test]
    fn fresh_downloads_are_left_alone() {
        let tmp = tempfile::tempdir().unwrap();
        let dl = tmp.path().join("Downloads");
        std::fs::create_dir_all(&dl).unwrap();
        std::fs::write(dl.join("New.dmg"), vec![0u8; 1000]).unwrap();

        let found = find(tmp.path(), 30, Duration::from_secs(5));
        assert!(found.is_empty(), "a just-downloaded installer was offered");
    }

    #[test]
    fn operations_exempt_each_file_individually() {
        let installers = vec![Installer {
            path: PathBuf::from("/Users/t/Documents/Old.dmg"),
            bytes: 1,
            age_days: 100,
            kind: "disk image",
        }];
        let ops = to_operations(&installers);
        assert_eq!(ops[0].exemptions.0, vec![PathBuf::from("/Users/t/Documents/Old.dmg")]);
        assert_eq!(ops[0].tier, eve_core::risk::RiskTier::Review);
    }
}
