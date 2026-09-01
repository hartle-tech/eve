//! Walking the disk the way OmniDiskSweeper does: one directory at a time,
//! biggest first, with sizes you can drill into.
//!
//! The distinction from [`crate::analyze`] is what it is *for*. `analyze`
//! answers "what is big in my home directory" in one shot and ranks the
//! result. This answers "what is inside here", repeatedly, as the user walks
//! down — so it has to be fast per level rather than thorough once, and it has
//! to return something for every child including the ones it could not read.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, LazyLock, Mutex};
use std::time::{Duration, Instant};

use rayon::prelude::*;
use serde::Serialize;

/// One row.
#[derive(Debug, Clone, Serialize)]
pub struct BrowseEntry {
    pub name: String,
    pub path: PathBuf,
    pub bytes: u64,
    pub is_dir: bool,
    /// How many entries are inside, for directories. Zero for files.
    pub children: u64,
    /// False when the size is a floor rather than a total — the walk hit its
    /// budget or a subtree it could not read. A partial number that presents
    /// itself as a total is how a cleaner talks somebody into deleting the
    /// wrong thing.
    pub complete: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct BrowseResult {
    pub path: PathBuf,
    /// `None` at the root the user started from, so the UI knows not to offer
    /// "up" past it.
    pub parent: Option<PathBuf>,
    pub entries: Vec<BrowseEntry>,
    pub total: u64,
    pub complete: bool,
}

/// What one child may spend being measured.
///
/// Per child, not per listing: one enormous directory among twenty must not
/// starve the other nineteen of any answer at all, and a listing-wide budget
/// does exactly that — whichever children the scheduler reaches last get
/// whatever is left, which is usually nothing, and their sizes come back
/// wrong rather than merely approximate.
const CHILD_BUDGET: Duration = Duration::from_millis(1200);

/// The hard ceiling on a whole listing, whatever the children are doing.
///
/// The children are measured in parallel, so this is reached only by a
/// directory both very wide and very deep. It exists so that no navigation can
/// ever hang: the rows that ran out say so, and drilling into one measures it
/// again with a fresh budget all to itself.
const LISTING_BUDGET: Duration = Duration::from_millis(4000);

/// Sizes already measured this session.
///
/// The single biggest win available here, because of how the view is actually
/// used: walk in, look, walk back up. Without a cache the walk back up costs
/// exactly as much as the walk in did — the same directories, re-measured from
/// scratch, every time. With one it is instant.
///
/// **Truncated measurements are kept too**, and that is deliberate.
///
/// They were not, and the result was that going Home cost two and a half
/// seconds *every single time*: the home directory's biggest children never
/// finish inside a child budget, so nothing about them was ever remembered and
/// every visit re-measured them from scratch — to arrive at the same partial
/// numbers it had already shown. A wait that produces a different answer can be
/// worth it; a wait that reproduces the previous answer is pure cost.
///
/// So a partial result is remembered *as partial*, the row still says so, and
/// `refresh` re-measures on demand for anyone who wants a better number.
/// Nothing is invalidated on a delete: the deleting path clears the parent's
/// entry directly, which is the only moment eve knows a size has changed.
static MEASURED: LazyLock<Mutex<HashMap<PathBuf, (u64, u64, bool)>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// Forget a cached size. Called after a deletion, which is the one thing that
/// makes a remembered number a lie.
pub fn forget(path: &Path) {
    if let Ok(mut cache) = MEASURED.lock() {
        cache.remove(path);
        // Whatever was deleted changed the size of everything above it.
        let mut parent = path.parent();
        while let Some(p) = parent {
            cache.remove(p);
            parent = p.parent();
        }
    }
}

pub fn browse(path: &Path) -> Result<BrowseResult, String> {
    let meta = std::fs::symlink_metadata(path).map_err(|e| format!("{}: {e}", path.display()))?;
    if !meta.is_dir() {
        return Err(format!("{} is not a directory", path.display()));
    }

    let read = std::fs::read_dir(path).map_err(|e| {
        // Overwhelmingly TCC rather than mode bits, and the remedy is
        // completely different, so it is worth naming.
        if e.kind() == std::io::ErrorKind::PermissionDenied {
            format!(
                "{} cannot be read — eve may need Full Disk Access",
                path.display()
            )
        } else {
            format!("{}: {e}", path.display())
        }
    })?;

    let children: Vec<PathBuf> = read.flatten().map(|c| c.path()).collect();

    // One deadline for the listing, shared by every child, plus a cancel flag
    // the deep walks poll. Without the flag a single enormous subtree would
    // run to its own completion after the deadline had already passed and
    // hold the whole listing open behind it.
    let deadline = Instant::now() + LISTING_BUDGET;
    let expired = Arc::new(AtomicBool::new(false));
    let ticker = Arc::clone(&expired);
    let stop = std::thread::spawn(move || {
        while Instant::now() < deadline {
            if ticker.load(Ordering::Relaxed) {
                return;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        ticker.store(true, Ordering::Relaxed);
    });

    // Measured in parallel. The work is almost entirely blocked on the
    // filesystem, so the children overlap nearly perfectly.
    let mut entries: Vec<BrowseEntry> = children
        .par_iter()
        .map(|cpath| measure_child(cpath, deadline, &expired))
        .collect();

    // Release the timer thread whether or not the deadline was reached.
    expired.store(true, Ordering::Relaxed);
    let _ = stop.join();

    let complete = entries.iter().all(|e| e.complete);

    // Biggest first. That is the entire point of the view — the rows near the
    // top are the ones worth a decision.
    entries.sort_by(|a, b| b.bytes.cmp(&a.bytes).then_with(|| a.name.cmp(&b.name)));

    Ok(BrowseResult {
        total: entries.iter().map(|e| e.bytes).sum(),
        parent: path.parent().map(Path::to_path_buf),
        path: path.to_path_buf(),
        entries,
        complete,
    })
}

/// Size one row: from the cache if it is known, otherwise by walking it, with
/// its own budget and the listing's shared deadline over the top.
fn measure_child(cpath: &Path, deadline: Instant, cancel: &Arc<AtomicBool>) -> BrowseEntry {
    let Ok(cmeta) = std::fs::symlink_metadata(cpath) else {
        // Present but unreadable. Listed at zero rather than hidden: a row the
        // user can see and question beats a silent omission.
        return BrowseEntry {
            name: file_name(cpath),
            path: cpath.to_path_buf(),
            bytes: 0,
            is_dir: false,
            children: 0,
            complete: false,
        };
    };

    let is_dir = cmeta.is_dir() && !cmeta.is_symlink();
    let (bytes, files, whole) = if !is_dir {
        (eve_core::size::on_disk(&cmeta), 1, true)
    } else if let Some((bytes, files, complete)) = cached(cpath) {
        (bytes, files, complete)
    } else {
        // Its own budget, capped by whatever is left of the listing's.
        let left = deadline
            .saturating_duration_since(Instant::now())
            .min(CHILD_BUDGET);
        let m = eve_core::size::measure_cancellable(cpath, left, cancel);
        // Remembered either way — see the note on MEASURED.
        remember(cpath, m.bytes, m.files, m.complete);
        (m.bytes, m.files, m.complete)
    };

    BrowseEntry {
        name: file_name(cpath),
        path: cpath.to_path_buf(),
        bytes,
        is_dir,
        children: if is_dir { files } else { 0 },
        complete: whole,
    }
}

fn cached(path: &Path) -> Option<(u64, u64, bool)> {
    MEASURED.lock().ok()?.get(path).copied()
}

fn remember(path: &Path, bytes: u64, files: u64, complete: bool) {
    if let Ok(mut cache) = MEASURED.lock() {
        cache.insert(path.to_path_buf(), (bytes, files, complete));
    }
}

/// Drop remembered sizes for one directory's children, so the next listing
/// measures them again. What the Disk view's Refresh does.
pub fn refresh(dir: &Path) {
    if let Ok(mut cache) = MEASURED.lock() {
        cache.retain(|p, _| p.parent() != Some(dir));
    }
}

fn file_name(p: &Path) -> String {
    p.file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| p.display().to_string())
}

/// Turn browser selections into operations for the funnel.
///
/// Deliberately produces `Operation`s rather than deleting: a path the user
/// picked by hand is exactly the case the protection policy, the whitelist and
/// the live-owner check exist for. Letting the browser delete directly would
/// put the one arbitrary-path entry point in eve outside every gate.
///
/// `Destructive` because the user chose these individually — they are not a
/// category eve reasoned about, so they never run unattended and they carry
/// the tier that demands a typed confirmation.
///
/// Each operation exempts **exactly the path it names**, and nothing wider.
/// Without that the browser could not delete most of what it showed: anything
/// under `~/Documents`, `~/Pictures` or `~/Projects` — which is to say the
/// rows the "biggest first" ranking puts at the top — was refused as protected
/// user data. The user walked to the item, ticked it and typed `delete`; there
/// is no stronger statement of intent available in the product, and treating
/// it as an accident is what made the Disk view look broken.
///
/// The exemption is narrow by construction. It unlocks the selected path and
/// its contents, never a sibling, and never the protected root above it —
/// `Policy::check` refuses a protected root outright, exemption or not. The
/// critical rules, the liveness gate and the user's whitelist are all still in
/// front of this, so a hand-picked path cannot reach `/System`, cannot remove
/// a directory something is actively using, and cannot take a cache the user
/// has told eve to leave alone.
pub fn to_operations(paths: &[PathBuf]) -> Vec<eve_core::Operation> {
    paths
        .iter()
        .map(|p| {
            eve_core::Operation::new("browse", p.clone(), eve_core::RiskTier::Destructive)
                .with_disposition(eve_core::executor::Disposition::Trash)
                .with_exemptions(vec![p.clone()])
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tree() -> tempfile::TempDir {
        let t = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(t.path().join("big/inner")).unwrap();
        std::fs::write(t.path().join("big/inner/blob"), vec![0u8; 8192]).unwrap();
        std::fs::create_dir_all(t.path().join("small")).unwrap();
        std::fs::write(t.path().join("small/a"), vec![0u8; 64]).unwrap();
        std::fs::write(t.path().join("loose.txt"), vec![0u8; 1024]).unwrap();
        t
    }

    #[test]
    fn biggest_first_is_the_whole_point() {
        let t = tree();
        let r = browse(t.path()).unwrap();
        // Sizes are allocated blocks now, so the two small entries can tie —
        // what must hold is that the genuinely large one leads.
        assert_eq!(r.entries[0].name, "big");
        assert!(r.entries[0].bytes >= 8192, "got {}", r.entries[0].bytes);
        let names: Vec<&str> = r.entries.iter().map(|e| e.name.as_str()).collect();
        assert!(names.contains(&"loose.txt") && names.contains(&"small"));
    }

    #[test]
    fn directories_report_what_is_inside_them() {
        let t = tree();
        let r = browse(t.path()).unwrap();
        let big = r.entries.iter().find(|e| e.name == "big").unwrap();
        assert!(big.is_dir);
        assert!(big.children >= 1, "a directory should count its contents");

        let loose = r.entries.iter().find(|e| e.name == "loose.txt").unwrap();
        assert!(!loose.is_dir);
        assert_eq!(loose.children, 0);
    }

    #[test]
    fn the_total_is_the_sum_of_the_rows_shown() {
        let t = tree();
        let r = browse(t.path()).unwrap();
        assert_eq!(r.total, r.entries.iter().map(|e| e.bytes).sum::<u64>());
    }

    #[test]
    fn a_file_is_not_browsable() {
        let t = tree();
        assert!(browse(&t.path().join("loose.txt")).is_err());
    }

    #[test]
    fn the_starting_point_knows_its_parent() {
        let t = tree();
        let r = browse(&t.path().join("big")).unwrap();
        assert_eq!(r.parent.as_deref(), Some(t.path()));
    }

    /// Everything the browser deletes goes through the funnel, as
    /// `Destructive` — the user picked these paths by hand, so they are not a
    /// category eve reasoned about and they must never run unattended.
    #[test]
    fn browser_deletions_are_destructive_and_recoverable() {
        let ops = to_operations(&[PathBuf::from("/tmp/x/a")]);
        assert_eq!(ops[0].tier, eve_core::RiskTier::Destructive);
        assert!(!ops[0].tier.allowed_unattended());
        assert!(ops[0].tier.needs_typed_confirmation());
        assert_eq!(
            ops[0].disposition,
            eve_core::executor::Disposition::Trash,
            "a hand-picked path must stay recoverable"
        );
    }

    /// Regression: the Disk view could not delete most of what it showed.
    ///
    /// Every pick went through the funnel with *no* exemption, so anything
    /// under `~/Documents`, `~/Projects`, `~/Pictures` — which is to say most
    /// of what the browser ranks at the top — was refused as protected user
    /// data. The user had walked to it, ticked it and typed `delete`; there is
    /// no stronger statement of intent available, and treating it as an
    /// accident made the feature useless.
    #[test]
    fn a_hand_picked_path_carries_its_own_exemption() {
        let picked = PathBuf::from("/Users/tester/Projects/old-build");
        let ops = to_operations(&[picked.clone()]);
        assert_eq!(ops[0].exemptions.0, vec![picked]);
    }

    /// The exemption is for the item picked and nothing else. Ticking one
    /// folder must not quietly unlock its siblings.
    #[test]
    fn the_exemption_covers_only_what_was_picked() {
        use eve_core::policy::Policy;
        let policy = Policy::for_home("/Users/tester");
        let ops = to_operations(&[PathBuf::from("/Users/tester/Documents/old")]);

        assert!(policy.check(&ops[0].path, &ops[0].exemptions).is_ok());
        assert!(
            policy
                .check(std::path::Path::new("/Users/tester/Documents/other"), &ops[0].exemptions)
                .is_err(),
            "one selection unlocked a sibling"
        );
        assert!(
            policy
                .check(std::path::Path::new("/Users/tester/Documents"), &ops[0].exemptions)
                .is_err(),
            "a selection unlocked the protected root above it"
        );
    }

    /// Listing a directory has to feel like a click, not like a scan.
    ///
    /// Each child used to be measured in turn, on a single thread — so a
    /// directory of ninety entries could spend over a minute before the first
    /// row appeared. This machine's home directory took 13.2 s, at every
    /// level, every time. The children are now measured together, under a
    /// ceiling for the listing as a whole.
    #[test]
    fn a_wide_directory_lists_within_the_budget() {
        let t = tempfile::tempdir().unwrap();
        for i in 0..120 {
            let d = t.path().join(format!("child{i:03}"));
            std::fs::create_dir_all(d.join("nested")).unwrap();
            std::fs::write(d.join("nested/blob"), vec![0u8; 1024]).unwrap();
        }
        let started = std::time::Instant::now();
        let r = browse(t.path()).unwrap();
        let took = started.elapsed();

        assert_eq!(r.entries.len(), 120);
        assert!(r.total >= 120 * 1024, "parallel measuring lost bytes: {}", r.total);
        assert!(
            took < LISTING_BUDGET,
            "a 120-entry listing took {took:?}, ceiling is {LISTING_BUDGET:?}"
        );
    }

    /// Going back to a directory whose children could not be measured in full
    /// must still be instant. It was not: nothing partial was remembered, so
    /// Home re-measured its biggest children on every visit and arrived at the
    /// same partial numbers two and a half seconds later.
    #[test]
    fn a_partial_measurement_is_remembered_too() {
        let t = tempfile::tempdir().unwrap();
        let deep = t.path().join("deep");
        std::fs::create_dir_all(&deep).unwrap();
        for i in 0..300 {
            std::fs::write(deep.join(format!("f{i}")), vec![0u8; 4096]).unwrap();
        }

        forget(&deep);
        let first = browse(t.path()).unwrap();
        let started = std::time::Instant::now();
        let second = browse(t.path()).unwrap();
        let took = started.elapsed();

        assert_eq!(first.total, second.total, "the remembered answer changed");
        assert!(
            took < Duration::from_millis(120),
            "a second visit still cost {took:?}"
        );
    }

    /// Walking back up must not cost what walking in did.
    #[test]
    fn a_second_visit_reuses_what_was_already_measured() {
        let t = tempfile::tempdir().unwrap();
        let big = t.path().join("big");
        std::fs::create_dir_all(big.join("a/b/c")).unwrap();
        for i in 0..400 {
            std::fs::write(big.join(format!("a/b/c/f{i}")), vec![0u8; 256]).unwrap();
        }

        let first = browse(t.path()).unwrap();
        let started = std::time::Instant::now();
        let second = browse(t.path()).unwrap();
        let took = started.elapsed();

        assert_eq!(first.total, second.total, "the cache changed the answer");
        assert!(
            took < Duration::from_millis(120),
            "a cached listing still took {took:?}"
        );
    }

    /// A remembered size is a lie the moment something is deleted, and it is a
    /// lie about every directory above it too.
    #[test]
    fn deleting_forgets_the_sizes_that_deletion_changed() {
        let t = tempfile::tempdir().unwrap();
        let nested = t.path().join("outer/inner");
        std::fs::create_dir_all(&nested).unwrap();
        std::fs::write(nested.join("blob"), vec![0u8; 2048]).unwrap();

        let first_total = browse(t.path()).unwrap().total;
        assert!(first_total >= 2048, "got {first_total}");
        std::fs::remove_file(nested.join("blob")).unwrap();
        // Still remembered, so still wrong — which is exactly why the deleting
        // path has to say so.
        let first_total = browse(t.path()).unwrap().total;
        assert!(first_total >= 2048, "got {first_total}");

        forget(&nested);
        assert_eq!(
            browse(t.path()).unwrap().total,
            0,
            "forget() did not clear the ancestors of what was deleted"
        );
    }

    #[test]
    fn an_unreadable_directory_says_what_to_do_about_it() {
        use std::os::unix::fs::PermissionsExt;
        let t = tempfile::tempdir().unwrap();
        let locked = t.path().join("locked");
        std::fs::create_dir(&locked).unwrap();
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000)).unwrap();
        if std::fs::read_dir(&locked).is_ok() {
            return; // running as root
        }
        let err = browse(&locked).unwrap_err();
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(err.contains("Full Disk Access"), "unhelpful: {err}");
    }
}
