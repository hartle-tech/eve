use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use walkdir::WalkDir;

/// Format a byte count the way a human reads it.
pub fn human_bytes(n: u64) -> String {
    const UNITS: [&str; 6] = ["B", "KB", "MB", "GB", "TB", "PB"];
    let mut v = n as f64;
    let mut i = 0;
    while v >= 1024.0 && i < UNITS.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 {
        format!("{n} B")
    } else {
        format!("{v:.1} {}", UNITS[i])
    }
}

/// The outcome of measuring a path.
///
/// `complete` is the load-bearing field. A scan that timed out or hit an
/// unreadable subtree reports what it found *and says so* — a partial number
/// silently presented as a total is how a 100 GB directory gets shown as 0 B
/// and quietly dropped from a summary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Measurement {
    pub bytes: u64,
    pub files: u64,
    pub complete: bool,
    /// The walk found an entry it could enumerate but not `lstat`.
    ///
    /// This is the macOS **Data Vault** signature. `readdir` hands back a
    /// name; `lstat` on that same name returns EPERM. The file cannot be
    /// stat'd, renamed or unlinked by anyone — not the owner, not root — and
    /// no permission grant changes that.
    ///
    /// It is deliberately distinct from `complete`. A walk that ran out of
    /// budget is *incomplete*: try again with longer and it finishes. A walk
    /// that hit a vault is *denied*: trying again forever will not help, and
    /// anything containing one can never be fully deleted. Only the second
    /// may block a move to the Trash — see `Executor::remove`.
    pub denied: bool,
}

impl Measurement {
    pub const EMPTY: Measurement = Measurement {
        bytes: 0,
        files: 0,
        complete: true,
        denied: false,
    };
}

/// What a file actually occupies, not what it claims to be.
///
/// `len()` is the *apparent* size — how far the file reads. For a sparse file
/// that is a fiction: a container store or a VM disk image is allocated lazily,
/// so the file says 100 GB and holds 4. Podman's store on this machine reports
/// **108.29 GB apparent against 4.00 GB allocated**, and eve was showing the
/// first number. Every figure eve prints is a promise about space the user will
/// get back, so it has to be the second.
///
/// `st_blocks` is in 512-byte units by definition, whatever the filesystem's
/// own block size is — that is what `du` reports and it is the number that
/// changes when you delete the file. APFS clones behave the same way: two files
/// sharing blocks each report the full apparent size, and deleting one frees
/// nothing.
#[cfg(unix)]
pub fn on_disk(meta: &std::fs::Metadata) -> u64 {
    use std::os::unix::fs::MetadataExt;
    meta.blocks().saturating_mul(512)
}

#[cfg(not(unix))]
pub fn on_disk(meta: &std::fs::Metadata) -> u64 {
    meta.len()
}

/// Whether an error means "this entry exists and cannot be stat'd".
///
/// Re-stats rather than trusting the walker's error kind, because
/// `PermissionDenied` also covers the ordinary case of a directory we may not
/// *read* — TCC, usually, which a Full Disk Access grant fixes and which does
/// not make anything undeletable. Only a name that survives `readdir` and then
/// fails `lstat` is a vault.
fn is_unstattable(path: &Path) -> bool {
    matches!(
        std::fs::symlink_metadata(path),
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied
    )
}

/// Recursive apparent size, bounded by a wall-clock budget.
///
/// Never follows symlinks: a redirected cache directory must not cause the
/// sizing pass to walk into (and later report on) the user's documents.
pub fn measure(path: &Path, budget: Duration) -> Measurement {
    measure_cancellable(path, budget, &Arc::new(AtomicBool::new(false)))
}

/// As [`measure`], but also abortable from another thread.
pub fn measure_cancellable(
    path: &Path,
    budget: Duration,
    cancel: &Arc<AtomicBool>,
) -> Measurement {
    let meta = match std::fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(_) => return Measurement::EMPTY,
    };

    if meta.is_file() || meta.is_symlink() {
        return Measurement {
            bytes: on_disk(&meta),
            files: 1,
            complete: true,
            denied: false,
        };
    }

    let started = Instant::now();
    let bytes = AtomicU64::new(0);
    let files = AtomicU64::new(0);
    let mut complete = true;
    let mut denied = false;

    for entry in WalkDir::new(path).follow_links(false).into_iter() {
        if started.elapsed() > budget || cancel.load(Ordering::Relaxed) {
            complete = false;
            break;
        }
        match entry {
            // A name the walker accepted but whose metadata it cannot read.
            // On APFS the file type comes from the directory entry itself, so
            // a vault child is handed over as an `Ok` and only fails here.
            Ok(e) => match e.metadata() {
                Ok(m) => {
                    if m.is_file() || m.is_symlink() {
                        bytes.fetch_add(on_disk(&m), Ordering::Relaxed);
                        files.fetch_add(1, Ordering::Relaxed);
                    }
                }
                Err(_) => {
                    complete = false;
                    denied |= is_unstattable(e.path());
                }
            },
            // An unreadable subtree is a real gap in the number, not a zero.
            Err(e) => {
                complete = false;
                denied |= e.path().is_some_and(is_unstattable);
            }
        }
    }

    Measurement {
        bytes: bytes.load(Ordering::Relaxed),
        files: files.load(Ordering::Relaxed),
        complete,
        denied,
    }
}

/// Free bytes on the volume containing `path`.
pub fn free_space(path: &Path) -> Option<u64> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    let c = CString::new(path.as_os_str().as_bytes()).ok()?;
    // SAFETY: `statfs` writes into a zeroed, correctly sized struct and we only
    // read from it after checking the return code.
    unsafe {
        let mut st: libc::statfs = std::mem::zeroed();
        if libc::statfs(c.as_ptr(), &mut st) != 0 {
            return None;
        }
        Some(st.f_bavail * st.f_bsize as u64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn human_bytes_reads_naturally() {
        assert_eq!(human_bytes(0), "0 B");
        assert_eq!(human_bytes(512), "512 B");
        assert_eq!(human_bytes(1024), "1.0 KB");
        assert_eq!(human_bytes(1024 * 1024 * 3 / 2), "1.5 MB");
        assert_eq!(human_bytes(2 * 1024 * 1024 * 1024), "2.0 GB");
    }

    /// A sparse file claims far more than it occupies, and eve's numbers are
    /// promises about space the user will get back. Podman's store here reads
    /// 108 GB apparent against 4 GB allocated; eve was reporting the first.
    #[test]
    fn a_sparse_file_is_measured_by_what_it_occupies() {
        use std::io::{Seek, SeekFrom, Write};
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("disk.img");

        // 64 MB of hole, then one byte. Apparent size 64 MB; allocated ~0.
        let mut f = std::fs::File::create(&path).unwrap();
        f.seek(SeekFrom::Start(64 * 1024 * 1024)).unwrap();
        f.write_all(b"x").unwrap();
        f.sync_all().unwrap();
        drop(f);

        let apparent = std::fs::metadata(&path).unwrap().len();
        let m = measure(tmp.path(), Duration::from_secs(5));

        assert!(apparent > 64 * 1024 * 1024, "the fixture is not sparse");
        assert!(
            m.bytes < apparent / 4,
            "measured {} against an apparent {} — this is the number that told \
             the user a 4 GB container store was 108 GB",
            m.bytes,
            apparent
        );
    }

    #[test]
    fn measure_counts_a_tree() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(tmp.path().join("a/b")).unwrap();
        std::fs::write(tmp.path().join("a/one"), vec![0u8; 100]).unwrap();
        std::fs::write(tmp.path().join("a/b/two"), vec![0u8; 250]).unwrap();

        let m = measure(tmp.path(), Duration::from_secs(5));
        // Allocated, not apparent — so a 100-byte file occupies a whole block.
        // The invariant that survives both is "at least what was written".
        assert!(m.bytes >= 350, "measured {} for 350 bytes written", m.bytes);
        assert_eq!(m.files, 2);
        assert!(m.complete);
    }

    #[test]
    fn measure_of_missing_path_is_empty_and_complete() {
        let m = measure(Path::new("/nonexistent/eve/test/path"), Duration::from_secs(1));
        assert_eq!(m, Measurement::EMPTY);
    }

    /// The macOS **Data Vault** signature, and the reason four directories sat
    /// in this machine's Trash for nine months.
    ///
    /// `readdir` hands back a name; `lstat` on that same name then returns
    /// EPERM. Nothing can rename, unlink or even stat it — not the owner, not
    /// root. eve moved the *parent* to the Trash (a rename, which succeeds),
    /// stranding a vault that can never be emptied.
    ///
    /// A directory we hold `r` but not `x` on reproduces the signature exactly
    /// — enumerable, un-stattable — which is what makes it testable at all.
    #[test]
    fn a_directory_whose_children_cannot_be_stat_is_reported_denied() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let inner = tmp.path().join("inner");
        std::fs::create_dir_all(inner.join("subdir")).unwrap();
        std::fs::write(inner.join("file"), vec![0u8; 10]).unwrap();
        std::fs::set_permissions(&inner, std::fs::Permissions::from_mode(0o400)).unwrap();

        let m = measure(tmp.path(), Duration::from_secs(5));
        let restore = std::fs::set_permissions(&inner, std::fs::Permissions::from_mode(0o700));

        assert!(m.denied, "an un-stattable entry was not reported");
        assert!(!m.complete, "a denied walk cannot claim to be complete");
        restore.unwrap();
    }

    /// `denied` must mean "something here cannot be touched", not merely
    /// "the walk ran out of time" — the two have completely different
    /// consequences, and only one of them may block a Trash move.
    #[test]
    fn an_ordinary_tree_is_never_reported_denied() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(tmp.path().join("a/b")).unwrap();
        std::fs::write(tmp.path().join("a/b/f"), vec![0u8; 64]).unwrap();

        let m = measure(tmp.path(), Duration::from_secs(5));
        assert!(!m.denied);
        assert!(m.complete);

        // A budget of zero truncates the walk. That is incomplete, not denied.
        let truncated = measure(tmp.path(), Duration::from_nanos(1));
        assert!(!truncated.denied, "a timeout must not read as a permission wall");
    }

    #[test]
    fn measure_does_not_follow_symlinks_out_of_the_tree() {
        let tmp = tempfile::tempdir().unwrap();
        let outside = tmp.path().join("outside");
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::write(outside.join("big"), vec![0u8; 10_000]).unwrap();

        let inside = tmp.path().join("inside");
        std::fs::create_dir_all(&inside).unwrap();
        std::os::unix::fs::symlink(&outside, inside.join("link")).unwrap();

        // The symlink counts as a single entry, not as the 10 KB behind it.
        let m = measure(&inside, Duration::from_secs(5));
        assert!(m.bytes < 1000, "followed the symlink: {} bytes", m.bytes);
    }
}
