//! Memory: what is actually true, and the two things that actually change it.
//!
//! # What the commercial cleaners do
//!
//! Every Mac "memory booster" on the market — the menu-bar tile with a **Free
//! Up** button — does one thing: it runs Apple's own `/usr/sbin/purge`.
//! MacPaw, whose product is the biggest of them, says so in as many words:
//! *"the RAM freeing feature inside most cleaner apps does essentially the same
//! thing as running the purge command in Terminal … you are paying for
//! convenience and a polished interface, not for a fundamentally superior
//! technical process."*
//!
//! `purge` drops the **file-backed cache**: pages the kernel is holding because
//! a file was read recently. It does not touch memory a process is actually
//! using, it does not compress anything, and it does not reduce swap.
//!
//! # Why the number on the tile is misleading
//!
//! Those tiles report the rise in *free* pages and call it memory reclaimed.
//! It is not a reclaim, it is a **discard**. macOS was keeping those pages
//! because re-reading the file costs a disk seek and keeping it costs nothing —
//! free memory on a healthy Mac is wasted memory. Dropping the cache makes the
//! next few seconds *slower*, and the pages refill within minutes. The graph
//! moves; the machine does not get faster.
//!
//! So eve does offer the button, because it is real and occasionally useful
//! (it is what Apple's own engineers reach for before a benchmark, to get a
//! cold-cache starting point). It just refuses to describe a cache discard as
//! though memory had been recovered, and it always reports the measured
//! before/after rather than a promise.
//!
//! # The two modes
//!
//! **Safe** is `purge`: reversible by definition — the cache refills — and
//! shipped by Apple.
//!
//! **Unsafe** is forced eviction: allocate memory until the kernel raises a
//! low-memory notification, which makes it evict and compress other processes'
//! pages. That genuinely frees anonymous memory, and it does it by pushing
//! somebody else's working set into the compressor or onto swap. Under real
//! pressure macOS answers a low-memory notification by killing the largest
//! offender. That is why it is never unattended and never a default.
//!
//! Deleting swap files or the hibernation image is not offered at all. See
//! [`fixed_costs`].

use std::process::Command;

use serde::Serialize;

/// How much of a risk an action carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Mode {
    /// Reversible, Apple-shipped, no other process is affected.
    Safe,
    /// Deliberately degrades the rest of the system to move a number.
    /// Requires the user to say so, every time.
    Unsafe,
}

/// The system's own pressure verdict, straight from the kernel.
///
/// This is the same value Activity Monitor's Memory Pressure graph is drawn
/// from, so eve and Activity Monitor can never disagree — which is what would
/// happen if eve computed a percentage of its own.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Pressure {
    Normal,
    Warning,
    Critical,
    Unknown,
}

impl Pressure {
    fn from_sysctl(v: i64) -> Pressure {
        // <sys/kern_memorystatus.h>: NORMAL 1, WARN 2, CRITICAL 4.
        match v {
            1 => Pressure::Normal,
            2 => Pressure::Warning,
            4 => Pressure::Critical,
            _ => Pressure::Unknown,
        }
    }
}

/// What memory looks like right now. Every field is bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct MemorySnapshot {
    pub total: u64,
    /// Pages the kernel is holding for nobody.
    pub free: u64,
    /// In use and recently touched.
    pub active: u64,
    /// In use but not touched lately — reclaimable without any help from eve.
    pub inactive: u64,
    /// Read ahead speculatively. The cheapest thing in memory to lose.
    pub speculative: u64,
    /// The kernel and things that cannot be paged out. Not reclaimable.
    pub wired: u64,
    /// What the compressor occupies after squeezing pages that would
    /// otherwise have gone to swap.
    pub compressed: u64,
    /// Backed by a file on disk — this is the cache `purge` discards.
    pub file_backed: u64,
    pub swap_total: u64,
    pub swap_used: u64,
    pub pressure: Pressure,
}

impl MemorySnapshot {
    /// Read the current state. Never fails: an unreadable field reads as zero
    /// rather than taking the whole snapshot down, because a partial truth
    /// about memory is still worth showing.
    pub fn read() -> MemorySnapshot {
        let vm = vm_stat();
        let page = vm.get("page size").copied().unwrap_or(4096);
        let pages = |k: &str| vm.get(k).copied().unwrap_or(0).saturating_mul(page);
        let (swap_total, swap_used) = swap_usage();

        MemorySnapshot {
            total: sysctl_u64("hw.memsize").unwrap_or(0),
            free: pages("Pages free"),
            active: pages("Pages active"),
            inactive: pages("Pages inactive"),
            speculative: pages("Pages speculative"),
            wired: pages("Pages wired down"),
            compressed: pages("Pages occupied by compressor"),
            file_backed: pages("File-backed pages"),
            swap_total,
            swap_used,
            pressure: sysctl_u64("kern.memorystatus_vm_pressure_level")
                .map(|v| Pressure::from_sysctl(v as i64))
                .unwrap_or(Pressure::Unknown),
        }
    }

    /// What `purge` could plausibly discard: the file cache and the pages read
    /// ahead on spec.
    ///
    /// Named "discardable" and not "reclaimable" on purpose. Nothing here is
    /// lost memory being recovered — it is memory doing a useful job that eve
    /// can stop it doing.
    pub fn discardable(&self) -> u64 {
        self.file_backed.saturating_add(self.speculative)
    }
}

/// A memory action eve can take.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Boost {
    /// `/usr/sbin/purge` — discard the file-backed cache.
    DropCaches,
    /// Allocate until the kernel raises a low-memory notification, forcing it
    /// to evict and compress other processes' pages.
    ForceEviction,
}

/// One offerable action, described honestly enough to decide against it.
#[derive(Debug, Clone, Serialize)]
pub struct BoostOption {
    pub key: &'static str,
    pub title: &'static str,
    pub mode: Mode,
    pub needs_root: bool,
    /// What it does mechanically.
    pub detail: &'static str,
    /// What it costs. Never empty — an action with no downside would not need
    /// two modes.
    pub caveat: &'static str,
}

pub const BOOSTS: &[BoostOption] = &[
    BoostOption {
        key: "drop_caches",
        title: "Drop the disk cache",
        mode: Mode::Safe,
        needs_root: true,
        detail: "Runs Apple's own purge. Discards pages the kernel is holding \
                 from files you read recently, so free memory goes up.",
        caveat: "This is what every \"free up RAM\" button on the App Store \
                 does. It does not make your Mac faster — the next few seconds \
                 are slower, because everything it dropped has to be read \
                 again, and the cache refills within minutes.",
    },
    BoostOption {
        key: "force_eviction",
        title: "Force the kernel to evict",
        mode: Mode::Unsafe,
        needs_root: false,
        detail: "Allocates memory until macOS raises a low-memory warning, \
                 which makes it compress or swap out pages other applications \
                 are still using.",
        caveat: "This frees real memory by taking it from something else. \
                 Other apps will stutter as their pages come back, and macOS \
                 answers a low-memory warning by killing the largest consumer \
                 — which can be the app you are working in. Never run \
                 unattended.",
    },
];

/// What actually happened, measured.
#[derive(Debug, Clone, Serialize)]
pub struct BoostResult {
    pub key: String,
    pub mode: Mode,
    pub ran: bool,
    pub ok: bool,
    pub before: MemorySnapshot,
    pub after: MemorySnapshot,
    /// Free memory after minus free memory before. Signed, and often negative
    /// — the machine keeps running while eve measures, and pretending
    /// otherwise would be the same lie as the tile.
    pub freed: i64,
    pub detail: Option<String>,
}

impl BoostResult {
    /// Whether the change is big enough to be a result rather than noise.
    ///
    /// A tenth of a gigabyte of movement on a machine that is allocating and
    /// freeing continuously means nothing, and reporting it as a win is
    /// exactly the behaviour eve exists to not have.
    pub fn is_significant(&self) -> bool {
        self.freed.unsigned_abs() > 100 * 1024 * 1024
    }
}

/// Run a memory action.
///
/// `dry_run` measures and reports without doing anything, so the preview and
/// the real run answer the same question — the same contract the cleaning
/// funnel keeps.
pub fn run(boost: Boost, dry_run: bool) -> BoostResult {
    let before = MemorySnapshot::read();
    let (key, mode) = match boost {
        Boost::DropCaches => ("drop_caches", Mode::Safe),
        Boost::ForceEviction => ("force_eviction", Mode::Unsafe),
    };
    let mut r = BoostResult {
        key: key.into(),
        mode,
        ran: false,
        ok: false,
        before,
        after: before,
        freed: 0,
        detail: None,
    };
    if dry_run {
        return r;
    }

    r.ran = true;
    let outcome = match boost {
        Boost::DropCaches => purge(),
        Boost::ForceEviction => force_eviction(),
    };
    match outcome {
        Ok(()) => r.ok = true,
        Err(e) => r.detail = Some(e),
    }

    r.after = MemorySnapshot::read();
    r.freed = r.after.free as i64 - r.before.free as i64;
    r
}

/// `purge` is root-only.
///
/// When eve is already root it runs directly; otherwise it raises the standard
/// macOS administrator dialog rather than a `sudo -n` that would fail silently
/// in the background and leave the user looking at an unchanged number with no
/// explanation.
fn purge() -> Result<(), String> {
    if unsafe { libc::geteuid() } == 0 {
        return match Command::new("/usr/sbin/purge").output() {
            Ok(o) if o.status.success() => Ok(()),
            Ok(o) => Err(String::from_utf8_lossy(&o.stderr).trim().to_string()),
            Err(e) => Err(e.to_string()),
        };
    }
    eve_core::privilege::run_system_command_as_admin(
        "/usr/sbin/purge",
        &[],
        "eve needs administrator rights to drop the disk cache.",
    )
    .map_err(|e| e.to_string())
}

/// Allocate until the kernel complains, then stop.
///
/// `memory_pressure -l critical` allocates and then *waits forever* by design,
/// so it is run with a wall-clock ceiling and killed. Without the ceiling a
/// tool whose documented behaviour is "allocate memory and wait forever" would
/// sit there holding the machine down until eve exited.
fn force_eviction() -> Result<(), String> {
    let mut child = Command::new("/usr/bin/memory_pressure")
        .args(["-l", "critical", "-Q"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .map_err(|e| e.to_string())?;

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
    loop {
        match child.try_wait() {
            Ok(Some(_)) => return Ok(()),
            Ok(None) => {}
            Err(e) => return Err(e.to_string()),
        }
        if std::time::Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Ok(());
        }
        std::thread::sleep(std::time::Duration::from_millis(200));
    }
}

/// Disk that memory management occupies and that nothing can reclaim.
///
/// Reported so the user can see where the space went, and deliberately *not*
/// offered as a deletion. Rival cleaners do offer it, and the gigabytes they
/// claim come straight back:
///
/// * `/private/var/vm/sleepimage` is preallocated for safe sleep. Delete it
///   and macOS writes a new one the next time the lid closes. On Apple
///   Silicon `hibernatemode` cannot be turned off to stop that.
/// * `/private/var/vm/swapfile*` are in use by the kernel. macOS grows and
///   shrinks them itself; removing one under a running system is not a cleanup.
pub fn fixed_costs() -> Vec<FixedCost> {
    let mut out = Vec::new();
    let dir = std::path::Path::new("/private/var/vm");
    let Ok(entries) = std::fs::read_dir(dir) else {
        return out;
    };
    for e in entries.flatten() {
        let name = e.file_name().to_string_lossy().to_string();
        let Ok(meta) = e.metadata() else { continue };
        let why = if name == "sleepimage" {
            "Your Mac's hibernation image. macOS rewrites it the next time the \
             lid closes, so deleting it frees nothing lasting."
        } else if name.starts_with("swapfile") {
            "In use by the kernel as swap. macOS grows and shrinks these itself."
        } else {
            continue;
        };
        out.push(FixedCost {
            path: e.path().to_string_lossy().to_string(),
            bytes: meta.len(),
            why: why.into(),
        });
    }
    out.sort_by(|a, b| b.bytes.cmp(&a.bytes));
    out
}

#[derive(Debug, Clone, Serialize)]
pub struct FixedCost {
    pub path: String,
    pub bytes: u64,
    pub why: String,
}

/// Parse `vm_stat` into page counts, plus the page size under the key
/// `"page size"`.
///
/// The header line carries the page size and every Mac does not use 4096 — an
/// Apple Silicon machine uses 16384, so a hardcoded 4096 would under-report
/// memory by a factor of four on exactly the machines eve runs on.
fn vm_stat() -> std::collections::HashMap<String, u64> {
    let mut out = std::collections::HashMap::new();
    let Ok(o) = Command::new("/usr/bin/vm_stat").output() else {
        return out;
    };
    let text = String::from_utf8_lossy(&o.stdout);
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("Mach Virtual Memory Statistics:") {
            if let Some(n) = rest
                .split("page size of ")
                .nth(1)
                .and_then(|s| s.split_whitespace().next())
                .and_then(|s| s.parse::<u64>().ok())
            {
                out.insert("page size".into(), n);
            }
            continue;
        }
        let Some((k, v)) = line.split_once(':') else {
            continue;
        };
        let v = v.trim().trim_end_matches('.');
        if let Ok(n) = v.parse::<u64>() {
            out.insert(k.trim().to_string(), n);
        }
    }
    out
}

/// `vm.swapusage` as (total, used) bytes.
fn swap_usage() -> (u64, u64) {
    let Ok(o) = Command::new("/usr/sbin/sysctl")
        .args(["-n", "vm.swapusage"])
        .output()
    else {
        return (0, 0);
    };
    let text = String::from_utf8_lossy(&o.stdout);
    let field = |name: &str| -> u64 {
        text.split(name)
            .nth(1)
            .and_then(|s| s.trim().strip_prefix('='))
            .map(str::trim)
            .and_then(|s| s.split_whitespace().next())
            .map(parse_mega)
            .unwrap_or(0)
    };
    (field("total"), field("used"))
}

/// `"2627.81M"` → bytes. The suffix is the unit `sysctl` chose, so it has to
/// be honoured rather than assumed to be megabytes.
fn parse_mega(s: &str) -> u64 {
    let (num, unit) = s.split_at(s.len().saturating_sub(1));
    let Ok(v) = num.parse::<f64>() else {
        return 0;
    };
    let scale = match unit {
        "K" => 1024.0,
        "M" => 1024.0 * 1024.0,
        "G" => 1024.0 * 1024.0 * 1024.0,
        _ => return s.parse::<f64>().unwrap_or(0.0) as u64,
    };
    (v * scale) as u64
}

fn sysctl_u64(name: &str) -> Option<u64> {
    let o = Command::new("/usr/sbin/sysctl")
        .args(["-n", name])
        .output()
        .ok()?;
    String::from_utf8_lossy(&o.stdout).trim().parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_snapshot_reads_a_plausible_machine() {
        let m = MemorySnapshot::read();
        assert!(m.total > 0, "hw.memsize should be readable");
        // Wired memory alone is always hundreds of megabytes on a running Mac.
        assert!(m.wired > 64 * 1024 * 1024, "wired looks like pages, not bytes: {}", m.wired);
        assert!(
            m.active + m.inactive + m.wired + m.free <= m.total * 2,
            "the parts dwarf the whole — the page size is probably wrong"
        );
    }

    /// The page size is 16384 on Apple Silicon. Assuming 4096 is the specific
    /// bug this parser exists to avoid.
    #[test]
    fn the_page_size_comes_from_the_header() {
        let vm = vm_stat();
        let page = vm.get("page size").copied().unwrap_or(0);
        assert!(
            page == 4096 || page == 16384,
            "unexpected page size {page}"
        );
    }

    #[test]
    fn swap_units_are_honoured() {
        assert_eq!(parse_mega("1.00M"), 1024 * 1024);
        assert_eq!(parse_mega("2.00G"), 2 * 1024 * 1024 * 1024);
        assert_eq!(parse_mega("512.00K"), 512 * 1024);
        assert_eq!(parse_mega(""), 0);
    }

    #[test]
    fn a_dry_run_changes_nothing_and_claims_nothing() {
        let r = run(Boost::DropCaches, true);
        assert!(!r.ran);
        assert_eq!(r.freed, 0);
        assert!(!r.is_significant());
    }

    /// Noise must not read as a result.
    #[test]
    fn small_movements_are_not_significant() {
        let m = MemorySnapshot::read();
        let mut r = BoostResult {
            key: "drop_caches".into(),
            mode: Mode::Safe,
            ran: true,
            ok: true,
            before: m,
            after: m,
            freed: 50 * 1024 * 1024,
            detail: None,
        };
        assert!(!r.is_significant());
        r.freed = 400 * 1024 * 1024;
        assert!(r.is_significant());
        // A negative delta is a real answer, not an error to hide.
        r.freed = -400 * 1024 * 1024;
        assert!(r.is_significant());
    }

    #[test]
    fn every_boost_names_a_cost() {
        assert!(BOOSTS.iter().all(|b| !b.caveat.is_empty()));
        assert!(BOOSTS.iter().any(|b| b.mode == Mode::Safe));
        assert!(BOOSTS.iter().any(|b| b.mode == Mode::Unsafe));
    }

    /// The hibernation image is reported, never offered.
    #[test]
    fn fixed_costs_are_described_as_unreclaimable() {
        for c in fixed_costs() {
            assert!(!c.why.is_empty(), "{} has no explanation", c.path);
        }
    }
}
