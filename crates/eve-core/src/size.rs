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
}

impl Measurement {
    pub const EMPTY: Measurement = Measurement {
        bytes: 0,
        files: 0,
        complete: true,
    };
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
            bytes: meta.len(),
            files: 1,
            complete: true,
        };
    }

    let started = Instant::now();
    let bytes = AtomicU64::new(0);
    let files = AtomicU64::new(0);
    let mut complete = true;

    for entry in WalkDir::new(path).follow_links(false).into_iter() {
        if started.elapsed() > budget || cancel.load(Ordering::Relaxed) {
            complete = false;
            break;
        }
        match entry {
            Ok(e) => {
                if let Ok(m) = e.metadata() {
                    if m.is_file() || m.is_symlink() {
                        bytes.fetch_add(m.len(), Ordering::Relaxed);
                        files.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
            // An unreadable subtree is a real gap in the number, not a zero.
            Err(_) => complete = false,
        }
    }

    Measurement {
        bytes: bytes.load(Ordering::Relaxed),
        files: files.load(Ordering::Relaxed),
        complete,
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

    #[test]
    fn measure_counts_a_tree() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(tmp.path().join("a/b")).unwrap();
        std::fs::write(tmp.path().join("a/one"), vec![0u8; 100]).unwrap();
        std::fs::write(tmp.path().join("a/b/two"), vec![0u8; 250]).unwrap();

        let m = measure(tmp.path(), Duration::from_secs(5));
        assert_eq!(m.bytes, 350);
        assert_eq!(m.files, 2);
        assert!(m.complete);
    }

    #[test]
    fn measure_of_missing_path_is_empty_and_complete() {
        let m = measure(Path::new("/nonexistent/eve/test/path"), Duration::from_secs(1));
        assert_eq!(m, Measurement::EMPTY);
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
