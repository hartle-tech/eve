//! Targets that cannot be written down as a fixed path.
//!
//! Each kind resolves to a concrete list at scan time. Resolution is
//! *discovery only* — nothing here deletes, and every path produced still
//! goes through the full funnel afterwards.

use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use serde::{Deserialize, Serialize};
use walkdir::WalkDir;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Kind {
    /// The per-user /var/folders cache and temp directories.
    DarwinUserScratch,
    /// Cache dirs inside sandboxed app containers.
    ContainerCaches,
    /// Chromium-style cache subdirectories inside Electron apps.
    ElectronCaches,
    /// Every Gradle wrapper except the newest.
    GradleOldWrappers,
    /// Every pyenv Python except the pinned one.
    PyenvOldVersions,
    /// __pycache__ directories under the source tree.
    PyCache,
    /// node_modules in projects untouched for 90 days.
    StaleNodeModules,
    /// registry.terraform.io provider copies (OpenTofu's are kept).
    TerraformProviders,
    /// Superseded Claude CLI installs.
    ClaudeOldVersions,
    /// Cached tool output under ~/.claude/projects.
    ClaudeToolResults,
    /// Siri / TTS / dictation asset packs.
    SiriAssets,
    /// Rust build directories under the source tree.
    RustTargets,
    /// Python virtual environments under the source tree.
    PythonVenvs,
    /// Workspace state and indexes for VS Code, VSCodium and Eclipse.
    IdeCaches,
}

impl Kind {
    pub fn resolve(self, home: &Path) -> Vec<PathBuf> {
        match self {
            Kind::DarwinUserScratch => darwin_scratch(),
            Kind::ContainerCaches => container_caches(home),
            Kind::ElectronCaches => electron_caches(home),
            Kind::GradleOldWrappers => gradle_old_wrappers(home),
            Kind::PyenvOldVersions => pyenv_old_versions(home),
            Kind::PyCache => pycache(home),
            Kind::StaleNodeModules => stale_node_modules(home),
            Kind::TerraformProviders => terraform_providers(home),
            Kind::ClaudeOldVersions => claude_old_versions(home),
            Kind::ClaudeToolResults => claude_tool_results(home),
            Kind::SiriAssets => siri_assets(),
            Kind::RustTargets => rust_targets(home),
            Kind::PythonVenvs => python_venvs(home),
            Kind::IdeCaches => ide_caches(home),
        }
    }
}

/// `target/` directories that are genuinely Rust build output.
///
/// The name alone is not enough — `target` is an ordinary word and appears in
/// plenty of trees that are not Cargo projects. A sibling `Cargo.toml` is what
/// makes it a build directory, and it is the difference between reclaiming
/// build artifacts and deleting somebody's data.
fn rust_targets(home: &Path) -> Vec<PathBuf> {
    walk_for_dir_named(&home.join("Projects"), "target", 8)
        .into_iter()
        .filter(|p| p.parent().is_some_and(|parent| parent.join("Cargo.toml").is_file()))
        .collect()
}

/// Virtual environments, proven by their own marker file.
///
/// `pyvenv.cfg` is written by `venv` and `virtualenv` and by nothing else, so
/// it distinguishes a throwaway environment from a directory that merely
/// happens to be called `.venv`.
fn python_venvs(home: &Path) -> Vec<PathBuf> {
    let root = home.join("Projects");
    let mut out = Vec::new();
    for name in [".venv", "venv", ".virtualenv"] {
        out.extend(
            walk_for_dir_named(&root, name, 6)
                .into_iter()
                .filter(|p| p.join("pyvenv.cfg").is_file()),
        );
    }
    out.sort();
    out.dedup();
    out
}

/// Editor workspace state: indexes, per-project caches, crash logs.
///
/// Rebuilt on next open, at the cost of one re-index. JetBrains is deliberately
/// absent — its caches are on the protection whitelist because re-indexing a
/// large project costs hours rather than seconds.
fn ide_caches(home: &Path) -> Vec<PathBuf> {
    [
        "Library/Application Support/Code/Cache",
        "Library/Application Support/Code/CachedData",
        "Library/Application Support/Code/logs",
        "Library/Application Support/VSCodium/Cache",
        "Library/Application Support/VSCodium/CachedData",
        "Library/Application Support/VSCodium/logs",
        "Library/Caches/com.microsoft.VSCode",
        "Library/Caches/com.vscodium",
        "eclipse-workspace/.metadata/.plugins/org.eclipse.core.resources/.history",
    ]
    .iter()
    .map(|p| home.join(p))
    .filter(|p| p.is_dir())
    .collect()
}

fn getconf(var: &str) -> Option<PathBuf> {
    let out = std::process::Command::new("/usr/bin/getconf")
        .arg(var)
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if s.is_empty() {
        None
    } else {
        Some(PathBuf::from(s))
    }
}

fn darwin_scratch() -> Vec<PathBuf> {
    ["DARWIN_USER_CACHE_DIR", "DARWIN_USER_TEMP_DIR"]
        .iter()
        .filter_map(|v| getconf(v))
        .filter(|p| p.is_dir())
        .collect()
}

fn container_caches(home: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for base in ["Library/Containers", "Library/Group Containers"] {
        let dir = home.join(base);
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for e in entries.flatten() {
            for sub in ["Data/Library/Caches", "Library/Caches"] {
                let c = e.path().join(sub);
                if c.is_dir() {
                    out.push(c);
                }
            }
        }
    }
    out
}

/// Chromium's cache subdirectory names, as embedded by every Electron app.
const ELECTRON_CACHE_DIRS: &[&str] = &[
    "Cache",
    "Code Cache",
    "GPUCache",
    "CacheStorage",
    "ShaderCache",
    "DawnGraphiteCache",
    "DawnWebGPUCache",
    "blob_storage",
];

fn electron_caches(home: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for root in [
        home.join("Library/Application Support"),
        home.join(".gemini"),
        home.join(".antigravity"),
    ] {
        if !root.is_dir() {
            continue;
        }
        // Depth is bounded: these live a few levels down, and an unbounded walk
        // of Application Support is minutes of I/O for no extra yield.
        for entry in WalkDir::new(&root)
            .max_depth(5)
            .follow_links(false)
            .into_iter()
            .filter_map(std::result::Result::ok)
        {
            if !entry.file_type().is_dir() {
                continue;
            }
            let name = entry.file_name().to_string_lossy();
            if ELECTRON_CACHE_DIRS.iter().any(|d| *d == name) {
                out.push(entry.path().to_path_buf());
            }
        }
    }
    out
}

/// Keep the most recently modified wrapper, drop the rest.
fn gradle_old_wrappers(home: &Path) -> Vec<PathBuf> {
    let dists = home.join(".gradle/wrapper/dists");
    let Ok(entries) = std::fs::read_dir(&dists) else {
        return Vec::new();
    };
    let mut dirs: Vec<(SystemTime, PathBuf)> = entries
        .flatten()
        .filter(|e| e.path().is_dir())
        .filter_map(|e| {
            let mtime = e.metadata().ok()?.modified().ok()?;
            Some((mtime, e.path()))
        })
        .collect();
    dirs.sort_by_key(|(t, _)| *t);
    dirs.pop(); // keep newest
    dirs.into_iter().map(|(_, p)| p).collect()
}

/// Keep whatever ~/.pyenv/version pins. If nothing is pinned, keep everything —
/// deleting every interpreter because a config file is missing is not a
/// cleanup, it is an outage.
fn pyenv_old_versions(home: &Path) -> Vec<PathBuf> {
    let versions = home.join(".pyenv/versions");
    let Ok(pinned) = std::fs::read_to_string(home.join(".pyenv/version")) else {
        return Vec::new();
    };
    let pinned = pinned.trim().to_string();
    if pinned.is_empty() {
        return Vec::new();
    }
    let Ok(entries) = std::fs::read_dir(&versions) else {
        return Vec::new();
    };
    entries
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.is_dir() && p.file_name().map(|n| n != pinned.as_str()).unwrap_or(false))
        .collect()
}

/// Keep whatever ~/.local/bin/claude resolves to.
fn claude_old_versions(home: &Path) -> Vec<PathBuf> {
    let versions = home.join(".local/share/claude/versions");
    let live = std::fs::canonicalize(home.join(".local/bin/claude")).ok();
    let Ok(entries) = std::fs::read_dir(&versions) else {
        return Vec::new();
    };
    entries
        .flatten()
        .map(|e| e.path())
        .filter(|p| {
            let canon = std::fs::canonicalize(p).ok();
            match (&live, &canon) {
                // Keep anything the live symlink points into.
                (Some(l), Some(c)) => !l.starts_with(c),
                _ => true,
            }
        })
        .collect()
}

fn claude_tool_results(home: &Path) -> Vec<PathBuf> {
    let root = home.join(".claude/projects");
    if !root.is_dir() {
        return Vec::new();
    }
    WalkDir::new(&root)
        .max_depth(3)
        .follow_links(false)
        .into_iter()
        .filter_map(std::result::Result::ok)
        .filter(|e| e.file_type().is_dir() && e.file_name() == "tool-results")
        .map(|e| e.path().to_path_buf())
        .collect()
}

fn pycache(home: &Path) -> Vec<PathBuf> {
    walk_for_dir_named(&home.join("Projects"), "__pycache__", 8)
}

/// node_modules whose project has not been touched in 90 days.
fn stale_node_modules(home: &Path) -> Vec<PathBuf> {
    let cutoff = SystemTime::now() - Duration::from_secs(90 * 86_400);
    walk_for_dir_named(&home.join("Projects"), "node_modules", 6)
        .into_iter()
        .filter(|nm| {
            let Some(project) = nm.parent() else {
                return false;
            };
            // Judge by the project's own files, not by node_modules' mtime,
            // which npm rewrites on every unrelated install.
            let Ok(meta) = std::fs::metadata(project.join("package.json")) else {
                return false;
            };
            meta.modified().map(|m| m < cutoff).unwrap_or(false)
        })
        .collect()
}

fn terraform_providers(home: &Path) -> Vec<PathBuf> {
    walk_for_dir_named(&home.join("Projects"), ".terraform", 8)
        .into_iter()
        .map(|tf| tf.join("providers/registry.terraform.io"))
        .filter(|p| p.is_dir())
        .collect()
}

/// Find directories with a given name, without descending into matches.
fn walk_for_dir_named(root: &Path, name: &str, max_depth: usize) -> Vec<PathBuf> {
    if !root.is_dir() {
        return Vec::new();
    }
    let mut out = Vec::new();
    let mut it = WalkDir::new(root)
        .max_depth(max_depth)
        .follow_links(false)
        .into_iter();
    while let Some(entry) = it.next() {
        let Ok(entry) = entry else { continue };
        if entry.file_type().is_dir() && entry.file_name() == name {
            out.push(entry.path().to_path_buf());
            // No point walking inside something we are about to remove.
            it.skip_current_dir();
        }
    }
    out
}

#[cfg(test)]
mod guard_tests {
    use super::*;

    /// `target` is an ordinary word. Only a sibling `Cargo.toml` makes one a
    /// build directory, and the difference is reclaiming build output versus
    /// deleting somebody's data.
    #[test]
    fn only_a_target_beside_a_cargo_toml_counts() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path();

        let crate_dir = home.join("Projects/thing");
        std::fs::create_dir_all(crate_dir.join("target/debug")).unwrap();
        std::fs::write(crate_dir.join("Cargo.toml"), b"[package]").unwrap();

        // A design project with a folder called target and no Cargo.toml.
        let art = home.join("Projects/artwork");
        std::fs::create_dir_all(art.join("target")).unwrap();
        std::fs::write(art.join("target/final.psd"), b"x").unwrap();

        let found = rust_targets(home);
        assert!(found.contains(&crate_dir.join("target")), "missed a real target dir");
        assert!(
            !found.contains(&art.join("target")),
            "a folder merely named target was offered for deletion"
        );
    }

    /// `pyvenv.cfg` is written by venv and virtualenv and nothing else.
    #[test]
    fn only_a_venv_with_its_marker_counts() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path();

        let real = home.join("Projects/app/.venv");
        std::fs::create_dir_all(real.join("lib")).unwrap();
        std::fs::write(real.join("pyvenv.cfg"), b"home = /usr").unwrap();

        let impostor = home.join("Projects/notes/venv");
        std::fs::create_dir_all(&impostor).unwrap();
        std::fs::write(impostor.join("plan.md"), b"x").unwrap();

        let found = python_venvs(home);
        assert!(found.contains(&real), "missed a real virtualenv");
        assert!(!found.contains(&impostor), "a directory named venv was offered anyway");
    }

    /// JetBrains re-indexing costs hours, so its caches stay whitelisted and
    /// this category must not reach for them.
    #[test]
    fn editor_caches_leave_jetbrains_alone() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path();
        for p in [
            "Library/Application Support/Code/Cache",
            "Library/Caches/JetBrains/IntelliJIdea",
        ] {
            std::fs::create_dir_all(home.join(p)).unwrap();
        }
        let found = ide_caches(home);
        assert!(found.contains(&home.join("Library/Application Support/Code/Cache")));
        assert!(
            !found.iter().any(|p| p.to_string_lossy().contains("JetBrains")),
            "JetBrains caches were offered despite being deliberately protected"
        );
    }
}

const SIRI_ASSET_PREFIXES: &[&str] = &[
    "com_apple_MobileAsset_UAF_Siri",
    "com_apple_MobileAsset_VoiceTrigger",
    "com_apple_MobileAsset_TTSAXResourceModelAssets",
    "com_apple_MobileAsset_UAF_Speech_AutomaticSpeechRecognition",
];

fn siri_assets() -> Vec<PathBuf> {
    let base = Path::new("/System/Library/AssetsV2");
    let Ok(entries) = std::fs::read_dir(base) else {
        return Vec::new();
    };
    entries
        .flatten()
        .map(|e| e.path())
        .filter(|p| {
            p.file_name()
                .map(|n| {
                    let n = n.to_string_lossy();
                    SIRI_ASSET_PREFIXES.iter().any(|pre| n.starts_with(pre))
                })
                .unwrap_or(false)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gradle_keeps_the_newest_wrapper() {
        let tmp = tempfile::tempdir().unwrap();
        let dists = tmp.path().join(".gradle/wrapper/dists");
        std::fs::create_dir_all(dists.join("gradle-8.0-bin")).unwrap();
        std::fs::create_dir_all(dists.join("gradle-8.5-bin")).unwrap();

        // Make 8.5 unambiguously newer.
        let newer = dists.join("gradle-8.5-bin");
        std::fs::write(newer.join("marker"), b"x").unwrap();
        std::thread::sleep(Duration::from_millis(20));
        filetime_touch(&newer);

        let old = gradle_old_wrappers(tmp.path());
        assert_eq!(old.len(), 1, "should keep exactly one wrapper");
        assert!(old[0].ends_with("gradle-8.0-bin"));
    }

    fn filetime_touch(p: &Path) {
        // Re-write a file inside to bump the directory mtime portably.
        let _ = std::fs::write(p.join("touch"), b"y");
    }

    #[test]
    fn pyenv_keeps_the_pinned_version() {
        let tmp = tempfile::tempdir().unwrap();
        let versions = tmp.path().join(".pyenv/versions");
        std::fs::create_dir_all(versions.join("3.12.0")).unwrap();
        std::fs::create_dir_all(versions.join("3.14.3")).unwrap();
        std::fs::write(tmp.path().join(".pyenv/version"), "3.14.3\n").unwrap();

        let old = pyenv_old_versions(tmp.path());
        assert_eq!(old.len(), 1);
        assert!(old[0].ends_with("3.12.0"));
    }

    /// Deleting every interpreter because a pin file is missing is an outage,
    /// not a cleanup.
    #[test]
    fn pyenv_with_no_pin_deletes_nothing() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(tmp.path().join(".pyenv/versions/3.12.0")).unwrap();
        assert!(pyenv_old_versions(tmp.path()).is_empty());
    }

    #[test]
    fn terraform_keeps_opentofu_and_drops_hashicorp() {
        let tmp = tempfile::tempdir().unwrap();
        let tf = tmp.path().join("Projects/infra/.terraform/providers");
        std::fs::create_dir_all(tf.join("registry.terraform.io/hashicorp/aws")).unwrap();
        std::fs::create_dir_all(tf.join("registry.opentofu.org/hashicorp/aws")).unwrap();

        let drops = terraform_providers(tmp.path());
        assert_eq!(drops.len(), 1);
        assert!(drops[0].ends_with("registry.terraform.io"));
        assert!(tf.join("registry.opentofu.org").is_dir());
    }

    #[test]
    fn walk_does_not_descend_into_its_own_matches() {
        let tmp = tempfile::tempdir().unwrap();
        let outer = tmp.path().join("Projects/a/node_modules");
        std::fs::create_dir_all(outer.join("pkg/node_modules")).unwrap();

        let found = walk_for_dir_named(&tmp.path().join("Projects"), "node_modules", 8);
        assert_eq!(found.len(), 1, "nested node_modules should not be listed separately");
    }

    #[test]
    fn stale_node_modules_ignores_fresh_projects() {
        let tmp = tempfile::tempdir().unwrap();
        let proj = tmp.path().join("Projects/fresh");
        std::fs::create_dir_all(proj.join("node_modules")).unwrap();
        std::fs::write(proj.join("package.json"), b"{}").unwrap();

        assert!(
            stale_node_modules(tmp.path()).is_empty(),
            "a just-written project must not be considered stale"
        );
    }

    #[test]
    fn pycache_finds_nested_caches() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(tmp.path().join("Projects/x/src/__pycache__")).unwrap();
        std::fs::create_dir_all(tmp.path().join("Projects/y/__pycache__")).unwrap();
        assert_eq!(pycache(tmp.path()).len(), 2);
    }

    #[test]
    fn missing_roots_resolve_to_nothing() {
        let tmp = tempfile::tempdir().unwrap();
        for kind in [
            Kind::ContainerCaches,
            Kind::ElectronCaches,
            Kind::GradleOldWrappers,
            Kind::PyenvOldVersions,
            Kind::PyCache,
            Kind::StaleNodeModules,
            Kind::TerraformProviders,
            Kind::ClaudeOldVersions,
            Kind::ClaudeToolResults,
        ] {
            assert!(
                kind.resolve(tmp.path()).is_empty(),
                "{kind:?} invented targets in an empty home"
            );
        }
    }
}
