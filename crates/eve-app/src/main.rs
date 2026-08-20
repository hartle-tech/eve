//! The eve desktop application.
//!
//! A thin shell over the same engines the CLI uses. No cleaning logic lives
//! here — the app builds the same `Selection` and calls the same `Cleaner`, so
//! the safety funnel cannot be bypassed by coming in through the window
//! instead of the terminal.

// Do not spawn a console window alongside the app on Windows. Harmless on
// macOS, and keeps the target open.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::time::Duration;

use eve_core::journal::{Journal, JournalEntry};
use eve_core::liveness::Liveness;
use eve_core::policy::Policy;
use eve_core::privilege::SudoWorker;
use eve_engines::analyze::Analysis;
use eve_engines::clean::{CleanReport, Cleaner, Selection};
use eve_engines::status::Status;
use eve_engines::{analyze, status};
use serde::Deserialize;

/// What the UI sends when the user presses Clean or Rescan.
#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Request {
    #[serde(default)]
    skip: Vec<String>,
    #[serde(default)]
    include: Vec<String>,
    #[serde(default)]
    privileged: bool,
}

impl Request {
    fn selection(&self) -> Selection {
        Selection {
            skip: self.skip.clone(),
            include: self.include.clone(),
            allow_privileged: self.privileged,
            // A window on screen means a human is present, so the unattended
            // tier gate does not apply. Destructive tiers still require the
            // user to opt in explicitly.
            unattended: false,
            only: Vec::new(),
        }
    }
}

fn policy() -> Policy {
    Policy::current().with_default_whitelist()
}

#[tauri::command]
fn scan(request: Request) -> CleanReport {
    let policy = policy();
    let liveness = Liveness::snapshot();
    let cleaner = Cleaner::new(&policy, &liveness);
    cleaner.scan(&eve_catalog::catalog(), &request.selection())
}

#[tauri::command]
fn clean(request: Request) -> CleanReport {
    let policy = policy();
    let liveness = Liveness::snapshot();
    let journal = Journal::open_default().ok();
    let mut cleaner = Cleaner::new(&policy, &liveness);
    if let Some(j) = &journal {
        cleaner = cleaner.with_journal(j);
    }
    let catalog = eve_catalog::catalog();

    // The worker is created per invocation and dropped at the end of it, so
    // root exists only for the duration of the clean the user asked for.
    let mut broker = request.privileged.then(SudoWorker::interactive);
    match broker.as_mut() {
        Some(b) => cleaner.execute(&catalog, &request.selection(), Some(b)),
        None => cleaner.execute(&catalog, &request.selection(), None),
    }
}

#[tauri::command]
fn system_status() -> Status {
    status::collect()
}

#[tauri::command]
fn history() -> Vec<JournalEntry> {
    Journal::open_default()
        .and_then(|j| j.read_all())
        .unwrap_or_default()
}

#[tauri::command]
fn disk_analysis(path: Option<String>) -> Analysis {
    let root = path
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| dirs_home());
    analyze::analyze(&root, Duration::from_secs(45))
}

fn dirs_home() -> std::path::PathBuf {
    std::env::var_os("HOME")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::PathBuf::from("/"))
}

/// The active whitelist, so the UI can show what is protected and why.
#[tauri::command]
fn whitelist() -> Vec<(String, String)> {
    policy()
        .whitelist_patterns()
        .into_iter()
        .map(|(p, s)| (p.to_string(), s.to_string()))
        .collect()
}

fn main() {
    tauri::Builder::default()
        .setup(|app| {
            // A real NSVisualEffectView behind the window. Painting a flat
            // grey panel and calling it a sidebar is the single clearest
            // giveaway that a Mac app was not written for the Mac: the
            // material has to actually sample and blur what is behind it.
            use tauri::Manager;
            if let Some(window) = app.get_webview_window("main") {
                let _ = window_vibrancy::apply_vibrancy(
                    &window,
                    window_vibrancy::NSVisualEffectMaterial::Sidebar,
                    Some(window_vibrancy::NSVisualEffectState::Active),
                    None,
                );
            }
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            scan,
            clean,
            system_status,
            history,
            disk_analysis,
            whitelist
        ])
        .run(tauri::generate_context!())
        .expect("failed to start eve");
}
