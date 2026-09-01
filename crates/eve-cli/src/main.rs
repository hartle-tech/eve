//! `eve` — macOS cleanup, analysis and maintenance.

mod render;
mod tui;

use std::io::{IsTerminal, Write};
use std::path::PathBuf;
use std::time::Duration;

use clap::{Parser, Subcommand};

use eve_core::journal::Journal;
use eve_core::liveness::Liveness;
use eve_core::policy::Policy;
use eve_core::prefs::{Preferences, TrashExclusions, TrashSweep};
use eve_core::privilege::{PrivilegeBroker, SudoWorker};
use eve_core::size::human_bytes;
use eve_engines::clean::{Cleaner, Selection};
use eve_engines::{analyze, installer, optimize, status, uninstall};
use render::Style;

#[derive(Parser)]
#[command(
    name = "eve",
    version,
    about = "Clean, analyse and maintain macOS.",
    long_about = "eve reclaims disk space and keeps macOS tidy.\n\nEvery deletion passes a \
                  five-stage safety funnel: path validation, protection policy, a live-owner \
                  check, a Trash-by-default executor and an append-only journal.\n\nNothing \
                  is deleted without --execute."
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,

    /// Machine-readable output.
    #[arg(long, global = true)]
    json: bool,

    /// Show categories that found nothing.
    #[arg(long, short, global = true)]
    verbose: bool,
}

#[derive(Subcommand)]
enum Command {
    /// Reclaim disk space.
    Clean {
        /// Actually delete. Without this, eve only previews.
        #[arg(long)]
        execute: bool,
        /// Skip the confirmation prompt.
        #[arg(long, short)]
        yes: bool,
        /// Only these categories (comma-separated).
        #[arg(long, value_delimiter = ',')]
        only: Vec<String>,
        /// Skip these categories.
        #[arg(long, value_delimiter = ',')]
        skip: Vec<String>,
        /// Opt in to categories that are off by default.
        #[arg(long, value_delimiter = ',')]
        include: Vec<String>,
        /// Include categories that need root.
        #[arg(long, short)]
        privileged: bool,
        /// No human present: enforces the unattended tier gate.
        #[arg(long)]
        unattended: bool,
        /// Also permanently empty the Trash — and remember it from now on.
        #[arg(long, overrides_with = "no_empty_trash")]
        empty_trash: bool,
        /// Stop emptying the Trash — and remember that from now on.
        #[arg(long, overrides_with = "empty_trash")]
        no_empty_trash: bool,
    },
    /// Install, remove or inspect the background agent.
    Agent {
        #[command(subcommand)]
        action: Option<AgentAction>,
    },
    /// What macOS is letting eve do, and how to fix what it is not.
    Permissions {
        /// Open the Privacy pane for the first thing that is missing.
        #[arg(long)]
        fix: bool,
    },
    /// Show or change the settings eve remembers.
    Config {
        #[command(subcommand)]
        action: Option<ConfigAction>,
    },
    /// List every category and what it does.
    Categories,
    /// Explore disk usage.
    Analyze {
        /// Directory to analyse. Defaults to your home directory.
        path: Option<PathBuf>,
        /// Show the largest individual files instead of directories.
        #[arg(long)]
        files: bool,
        /// Group by file extension.
        #[arg(long)]
        extensions: bool,
        /// How many rows.
        #[arg(long, default_value_t = 20)]
        limit: usize,
    },
    /// List one directory, biggest first — and optionally delete from it.
    ///
    /// The same engine and the same funnel the window's Disk view uses, which
    /// is the point: the browser is testable from a terminal instead of only
    /// through a webview.
    Browse {
        /// Directory to list. Defaults to your home directory.
        path: Option<PathBuf>,
        /// Delete these paths through the funnel instead of listing.
        #[arg(long, value_delimiter = ',')]
        delete: Vec<PathBuf>,
        /// Actually delete. Without this, `--delete` only previews.
        #[arg(long)]
        execute: bool,
        /// Report how long the listing took.
        #[arg(long)]
        timing: bool,
    },
    /// Remove an application and its leftovers.
    Uninstall {
        /// Application name. Omit to list what is installed.
        app: Option<String>,
        #[arg(long)]
        execute: bool,
        #[arg(long, short)]
        yes: bool,
        /// Remove applications the system owns.
        ///
        /// Anything installed by a `.pkg` lands in /Applications as
        /// `root:wheel`, and POSIX will not let you move a directory you
        /// cannot write into a different parent — so those cannot be
        /// uninstalled at all without this. Prompts for your password.
        #[arg(long, short)]
        privileged: bool,
    },
    /// Which running apps are holding your Trash open.
    ///
    /// macOS will not delete a file another process has open, so those entries
    /// stay put. This says which apps to quit, before the sweep rather than
    /// after it.
    TrashBlockers,
    /// Find leftover installer files.
    Installer {
        #[arg(long, default_value_t = 30)]
        min_age_days: u64,
        #[arg(long)]
        execute: bool,
        #[arg(long, short)]
        yes: bool,
    },
    /// System maintenance tasks.
    Optimize {
        #[arg(long)]
        execute: bool,
    },
    /// System health and live metrics.
    Status,
    /// What eve has done.
    History {
        #[arg(long, default_value_t = 40)]
        limit: usize,
    },
    /// Show the active protection whitelist.
    Whitelist,
    /// The interactive terminal interface.
    Tui,
    /// Unattended low-disk trigger. Invoked by the LaunchAgent, not by hand.
    Autoclean {
        /// Override the stored threshold for this run only.
        ///
        /// Absent means "use what `eve config threshold-gb` stored". Passing
        /// it does NOT persist: deployed LaunchAgent plists still pass the old
        /// values on the command line, and a sticky flag here would have every
        /// unattended run quietly reset whatever the user configured.
        #[arg(long)]
        threshold_gb: Option<u64>,
        /// Override the stored cooldown for this run only. Not persisted.
        #[arg(long)]
        cooldown_sec: Option<u64>,
        /// Go through the motions without deleting.
        #[arg(long)]
        dry_run: bool,
    },
}

#[derive(Subcommand)]
enum AgentAction {
    /// Write the LaunchAgent and load it. No Ansible, no toolchain.
    Install {
        /// Run this executable instead of the current one.
        ///
        /// Defaults to whichever eve you invoked. Point it at
        /// `/Applications/eve.app/Contents/MacOS/eve` and the background run
        /// shares the app's permissions instead of needing its own — macOS
        /// grants access to a program, and those are two different programs.
        #[arg(long)]
        program: Option<PathBuf>,
    },
    /// Unload it and remove the plist.
    Uninstall,
}

#[derive(Subcommand)]
enum ConfigAction {
    /// Actually free the space, instead of only moving things to the Trash.
    ///
    /// Off — the default — means eve is entirely reversible: everything it
    /// removes goes to the Trash and eve never empties it. On means a cleanup
    /// frees what it reports, and none of it can be recovered.
    ///
    /// Regenerable caches are deleted outright; anything adjacent to real user
    /// data still goes to the Trash whichever way this is set.
    DirectCleanup {
        /// on | off
        state: String,
    },
    /// Stop eve cleaning one category, everywhere — including the unattended run.
    ///
    /// eve cleans developer caches by default and some of those are not caches
    /// in any useful sense: `pyenv_old` removes every Python except the pinned
    /// one, `gradle_wrappers` every wrapper except the newest. On a machine
    /// that builds against an older toolchain that is breakage, not cleanup.
    Disable {
        /// Category key, as shown by `eve categories`.
        key: String,
    },
    /// Let eve clean a category again.
    Enable {
        key: String,
    },
    /// Deprecated spelling of `direct-cleanup`.
    #[command(hide = true)]
    EmptyTrash { state: String },
    /// Deprecated. The sweep now always runs at the end when cleanup is direct.
    #[command(hide = true)]
    EmptyTrashAt { when: String },
    /// Deprecated spelling of `direct-cleanup`.
    #[command(hide = true)]
    PermanentDelete { state: String },
    /// Fire the unattended run below this much free space.
    ThresholdGb { gb: u64 },
    /// Minimum seconds between real unattended runs.
    CooldownSec { seconds: u64 },
    /// Never delete a Trash entry matching this glob.
    ///
    /// Matched against the entry's name, or against the whole path if the
    /// pattern contains a slash.
    Exclude { pattern: String },
    /// Drop an exclusion.
    Unexclude { pattern: String },
    /// Never remove anything inside this directory, whatever asks.
    ///
    /// The strongest refusal eve has. Nothing lifts it — not an exemption, not
    /// a tier, not the unattended run, not eve running as root.
    Lock { path: PathBuf },
    /// Let eve touch a directory again.
    Unlock { path: PathBuf },
    /// Forget everything and go back to defaults.
    Reset,
}

fn main() {
    // The privileged peer. Checked before clap so the hidden argument never
    // appears in help output or competes with a real subcommand.
    if eve_core::privilege::serve_if_worker(&CatalogAuthorizer::build()) {
        return;
    }

    let cli = Cli::parse();
    let style = if cli.json {
        Style::plain()
    } else {
        Style::detect()
    };

    let code = match run(&cli, &style) {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("{}: {e}", style.red("error"));
            1
        }
    };
    std::process::exit(code);
}

/// Root only carries out operations the catalog actually produces.
///
/// Without this the sudoers grant means "delete anything eve's protection
/// rules happen not to cover", because the worker would adjudicate whatever
/// path a caller wrote into the plan. The grant is supposed to mean "run eve's
/// categories", and this is what makes those two the same sentence.
/// Shared with the app, which is also a privileged peer.
use eve_engines::authorizer::CatalogAuthorizer;

fn home() -> PathBuf {
    dirs::home_dir().unwrap_or_else(|| PathBuf::from("/"))
}

fn policy() -> Policy {
    // Locks are part of the policy, not an afterthought applied by whoever
    // remembered: every caller builds the policy here, so a locked directory
    // is locked for the window, the CLI and the unattended run alike.
    let locks = Preferences::load_default().unwrap_or_default().locked_paths;
    Policy::current().with_default_whitelist().with_locks(locks)
}

fn run(cli: &Cli, style: &Style) -> anyhow::Result<()> {
    match cli.command.as_ref() {
        None => {
            if std::io::stdout().is_terminal() {
                tui::run()
            } else {
                // Piped with no subcommand: a summary is more useful than help.
                cmd_status(cli, style)
            }
        }
        Some(Command::Clean {
            execute,
            yes,
            only,
            skip,
            include,
            privileged,
            unattended,
            empty_trash,
            no_empty_trash,
        }) => cmd_clean(
            cli,
            style,
            CleanArgs {
                execute: *execute,
                yes: *yes,
                only: only.clone(),
                skip: skip.clone(),
                include: include.clone(),
                privileged: *privileged,
                unattended: *unattended,
                empty_trash: tri_state(*empty_trash, *no_empty_trash),
            },
        ),
        Some(Command::Config { action }) => cmd_config(cli, style, action.as_ref()),
        Some(Command::Agent { action }) => cmd_agent(cli, style, action.as_ref()),
        Some(Command::Permissions { fix }) => cmd_permissions(cli, style, *fix),
        Some(Command::Categories) => cmd_categories(cli, style),
        Some(Command::Analyze {
            path,
            files,
            extensions,
            limit,
        }) => cmd_analyze(cli, style, path.clone(), *files, *extensions, *limit),
        Some(Command::Browse {
            path,
            delete,
            execute,
            timing,
        }) => cmd_browse(cli, style, path.clone(), delete.clone(), *execute, *timing),
        Some(Command::Uninstall {
            app,
            execute,
            yes,
            privileged,
        }) => cmd_uninstall(cli, style, app.clone(), *execute, *yes, *privileged),
        Some(Command::TrashBlockers) => cmd_trash_blockers(cli, style),
        Some(Command::Installer {
            min_age_days,
            execute,
            yes,
        }) => cmd_installer(cli, style, *min_age_days, *execute, *yes),
        Some(Command::Optimize { execute }) => cmd_optimize(cli, style, *execute),
        Some(Command::Status) => cmd_status(cli, style),
        Some(Command::History { limit }) => cmd_history(cli, style, *limit),
        Some(Command::Whitelist) => cmd_whitelist(cli, style),
        Some(Command::Tui) => tui::run(),
        Some(Command::Autoclean {
            threshold_gb,
            cooldown_sec,
            dry_run,
        }) => eve_engines::autoclean::run(&eve_engines::autoclean::Config {
            threshold_gb: *threshold_gb,
            cooldown_sec: *cooldown_sec,
            dry_run: *dry_run,
        }),
    }
}

struct CleanArgs {
    execute: bool,
    yes: bool,
    only: Vec<String>,
    skip: Vec<String>,
    include: Vec<String>,
    privileged: bool,
    unattended: bool,
    /// `Some` when the user named the flag this run, and is therefore also
    /// changing the stored setting.
    empty_trash: Option<bool>,
}

fn parse_on_off(state: &str) -> anyhow::Result<bool> {
    match state.to_lowercase().as_str() {
        "on" | "true" | "yes" | "1" => Ok(true),
        "off" | "false" | "no" | "0" => Ok(false),
        other => anyhow::bail!("expected on or off, got {other:?}"),
    }
}

/// A pair of opposing flags read as one setting.
fn tri_state(on: bool, off: bool) -> Option<bool> {
    match (on, off) {
        (true, false) => Some(true),
        (false, true) => Some(false),
        // clap's `overrides_with` makes both-at-once impossible; neither means
        // "leave the stored value alone".
        _ => None,
    }
}

/// Load the stored preferences, saying so if they could not be read.
///
/// A file that will not parse falls back to defaults *loudly*. Silence there
/// would turn `empty-trash` back off without telling anyone, and the user
/// would go on believing their Trash was being emptied.
fn preferences(style: &Style) -> Preferences {
    Preferences::load_default().unwrap_or_else(|e| {
        eprintln!(
            "{}: stored settings not applied — {e}",
            style.yellow("warning")
        );
        Preferences::default()
    })
}

fn cmd_clean(cli: &Cli, style: &Style, args: CleanArgs) -> anyhow::Result<()> {
    let mut prefs = preferences(style);
    if let Some(want) = args.empty_trash {
        if prefs.empty_trash != want {
            prefs.empty_trash = want;
            if let Err(e) = prefs.save_default() {
                // Worth failing on: the user asked for a durable change and it
                // did not happen. Carrying on would apply it once and silently
                // forget it.
                anyhow::bail!("could not save the setting: {e}");
            }
        }
    }

    let policy = policy();
    let liveness = Liveness::snapshot();
    let journal = Journal::open_default().ok();
    let catalog = eve_catalog::catalog();

    let sel = Selection {
        only: args.only,
        // The stored choices come first, so a category switched off in the
        // window is off here too. All four callers read the same list —
        // otherwise "off" means whichever frontend you last used.
        skip: prefs
            .disabled_categories
            .iter()
            .cloned()
            .chain(args.skip.into_iter())
            .collect(),
        include: args.include,
        unattended: args.unattended,
        allow_privileged: args.privileged,
        empty_trash: prefs.empty_trash,
        empty_trash_at: prefs.empty_trash_at,
        permanent_delete: prefs.permanent_delete,
    };
    let (execute, yes, privileged, unattended) =
        (args.execute, args.yes, args.privileged, args.unattended);

    let mut cleaner =
        Cleaner::new(&policy, &liveness).with_trash_exclusions(TrashExclusions::compile(&prefs));
    if let Some(j) = &journal {
        cleaner = cleaner.with_journal(j);
    }

    // Always scan first. The preview is what the confirmation is about, and
    // it is produced by the same funnel the real run uses.
    let preview = cleaner.scan(&catalog, &sel);

    if !execute {
        if cli.json {
            println!("{}", serde_json::to_string_pretty(&preview)?);
        } else {
            render::print_report(&preview, style, cli.verbose);
        }
        return Ok(());
    }

    if !yes {
        if !cli.json {
            render::print_report(&preview, style, cli.verbose);
        }
        if !confirm(style, preview.total_bytes(), trash_bytes(&preview))? {
            println!("Aborted.");
            return Ok(());
        }
    }

    let mut broker: Option<Box<dyn PrivilegeBroker>> = if privileged {
        Some(Box::new(if unattended {
            SudoWorker::unattended()
        } else {
            SudoWorker::interactive()
        }))
    } else {
        None
    };

    let mut report = match broker.as_deref_mut() {
        Some(b) => cleaner.execute(&catalog, &sel, Some(b)),
        None => cleaner.execute(&catalog, &sel, None),
    };
    report.newly_excluded = eve_engines::clean::learn_undeletable(&report);

    if cli.json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        render::print_report(&report, style, cli.verbose);
        // Said out loud, because eve added these itself. A list that grows on
        // its own is a policy change, and the terminal has no Settings screen
        // to notice it in later.
        if !report.newly_excluded.is_empty() {
            println!(
                "\n  {} {} — permanently undeletable, so eve will skip {} from now on.\n  \
                 Undo with: eve config unexclude '<pattern>'",
                style.bold("Learned:"),
                style.yellow(&report.newly_excluded.join(", ")),
                if report.newly_excluded.len() == 1 { "it" } else { "them" },
            );
        }
        if report.categories.iter().any(|c| c.key == "siri_assets") {
            render::print_settings_hints(style);
        }
    }

    // A privileged uninstall can leave a root-owned bundle in the Trash that
    // the user cannot remove. Offer to finish the job in the same breath,
    // rather than leaving the Trash in the stuck state.
    if args.execute && args.privileged {
        match empty_trash_as_admin(style) {
            Ok(0) => {}
            Ok(freed) => println!(
                "\n  {} {} freed from the Trash with administrator rights",
                style.bold("Also:"),
                style.green(&human_bytes(freed))
            ),
            Err(e) => println!("\n  {} {e}", style.yellow("⊘")),
        }
    }
    Ok(())
}

/// What the Trash emptying alone would remove, if it is part of this run.
fn trash_bytes(report: &eve_engines::clean::CleanReport) -> u64 {
    report
        .categories
        .iter()
        .filter(|c| c.key == "trash")
        .map(|c| c.bytes())
        .sum()
}

fn confirm(style: &Style, bytes: u64, permanent: u64) -> anyhow::Result<bool> {
    if !std::io::stdin().is_terminal() {
        // No one is there to answer. Refusing is the only safe reading of
        // silence; --yes exists for exactly this case.
        eprintln!("Refusing to delete without a terminal to confirm on. Pass --yes.");
        return Ok(false);
    }
    // Everything else in a clean lands in the Trash and can be pulled back
    // out. This part cannot, so it gets said out loud rather than folded into
    // one total.
    if permanent > 0 {
        println!(
            "\n{} {} of that is the Trash, and emptying it cannot be undone.",
            style.bold(&style.yellow("!")),
            style.bold(&human_bytes(permanent))
        );
    }
    print!(
        "\n{} about to reclaim {}. Continue? [y/N] ",
        style.bold(&style.yellow("!")),
        style.bold(&human_bytes(bytes))
    );
    std::io::stdout().flush()?;
    let mut answer = String::new();
    std::io::stdin().read_line(&mut answer)?;
    Ok(matches!(answer.trim().to_lowercase().as_str(), "y" | "yes"))
}

fn cmd_config(cli: &Cli, style: &Style, action: Option<&ConfigAction>) -> anyhow::Result<()> {
    let mut prefs = Preferences::load_default().map_err(|e| anyhow::anyhow!(e))?;

    let changed = match action {
        None => false,
        Some(ConfigAction::DirectCleanup { state })
        | Some(ConfigAction::EmptyTrash { state })
        | Some(ConfigAction::PermanentDelete { state }) => {
            prefs.set_direct_cleanup(parse_on_off(state)?);
            true
        }
        Some(ConfigAction::Disable { key }) | Some(ConfigAction::Enable { key }) => {
            let known: Vec<&str> = eve_catalog::catalog().iter().map(|c| c.key).collect();
            if !known.contains(&key.as_str()) {
                anyhow::bail!(
                    "no category called {key:?} — `eve categories` lists them all"
                );
            }
            let on = matches!(action, Some(ConfigAction::Enable { .. }));
            prefs.set_category(key, on);
            true
        }
        Some(ConfigAction::EmptyTrashAt { when }) => {
            prefs.empty_trash_at = match when.to_lowercase().as_str() {
                "start" | "before" => TrashSweep::Start,
                "end" | "after" => TrashSweep::End,
                other => anyhow::bail!("expected start or end, got {other:?}"),
            };
            true
        }
        Some(ConfigAction::ThresholdGb { gb }) => {
            if *gb == 0 {
                anyhow::bail!("a 0 GB threshold would never fire");
            }
            prefs.threshold_gb = *gb;
            true
        }
        Some(ConfigAction::CooldownSec { seconds }) => {
            prefs.cooldown_sec = *seconds;
            true
        }
        Some(ConfigAction::Exclude { pattern }) => prefs
            .exclude_trash(pattern)
            .map_err(|e| anyhow::anyhow!("{pattern:?} is not a valid glob: {e}"))?,
        Some(ConfigAction::Unexclude { pattern }) => {
            if !prefs.unexclude_trash(pattern) {
                anyhow::bail!("no exclusion {pattern:?} to remove");
            }
            true
        }
        Some(ConfigAction::Lock { path }) | Some(ConfigAction::Unlock { path }) => {
            let lock = matches!(action, Some(ConfigAction::Lock { .. }));
            // Absolute, because the policy compares whole paths and a relative
            // one would silently never match anything the funnel is asked about.
            let abs = if path.is_absolute() {
                path.clone()
            } else {
                std::env::current_dir()?.join(path)
            };
            prefs.set_locked(&abs.to_string_lossy(), lock);
            true
        }
        Some(ConfigAction::Reset) => {
            prefs = Preferences::default();
            true
        }
    };

    if changed {
        prefs.save_default().map_err(|e| anyhow::anyhow!(e))?;
    }

    if cli.json {
        println!("{}", serde_json::to_string_pretty(&prefs)?);
        return Ok(());
    }

    println!("\n{}", style.bold("Settings"));
    println!(
        "  {:<16} {}",
        style.cyan("direct-cleanup"),
        if prefs.direct_cleanup() {
            style.yellow("on")
        } else {
            style.dim("off")
        }
    );
    println!(
        "  {:<16} {}",
        "",
        style.dim(if prefs.direct_cleanup() {
            "a cleanup frees what it reports — regenerable caches are deleted \
             outright and the Trash is emptied afterwards. None of it is recoverable."
        } else {
            "everything goes to the Trash and eve never empties it, so nothing \
             eve does is irreversible — and nothing is actually freed"
        })
    );

    println!("\n{}", style.bold("Unattended runs"));
    println!("  {:<16} {} GB free", style.cyan("threshold-gb"), prefs.threshold_gb);
    println!(
        "  {:<16} {} s between real runs",
        style.cyan("cooldown-sec"),
        prefs.cooldown_sec
    );

    if !prefs.disabled_categories.is_empty() {
        println!("\n{}", style.bold("Switched off — eve will not clean these"));
        for k in &prefs.disabled_categories {
            println!("  • {k}");
        }
        println!(
            "  {}",
            style.dim("`eve config enable <key>` puts one back.")
        );
    }

    println!("\n{}", style.bold("Never emptied from the Trash"));
    for (pattern, source) in prefs.effective_trash_exclusions() {
        println!(
            "  {} {:<52} {}",
            style.green("•"),
            pattern,
            style.dim(source)
        );
    }
    println!(
        "\n  {}",
        style.dim(&Preferences::default_path().display().to_string())
    );
    println!();
    Ok(())
}

fn cmd_agent(cli: &Cli, style: &Style, action: Option<&AgentAction>) -> anyhow::Result<()> {
    match action {
        Some(AgentAction::Install { program }) => {
            let plist = match program {
                Some(p) => {
                    let p = std::fs::canonicalize(p)
                        .map_err(|e| anyhow::anyhow!("{}: {e}", p.display()))?;
                    eve_core::agent::install_program(&p)
                }
                None => eve_core::agent::install(),
            }
            .map_err(|e| anyhow::anyhow!(e))?;
            if !cli.json {
                println!("\n{} {}", style.green("installed"), plist.display());
            }
        }
        Some(AgentAction::Uninstall) => {
            eve_core::agent::uninstall().map_err(|e| anyhow::anyhow!(e))?;
            if !cli.json {
                println!("\n{}", style.dim("removed"));
            }
        }
        None => {}
    }

    let status = eve_core::agent::status();
    if cli.json {
        println!("{}", serde_json::to_string_pretty(&status)?);
        return Ok(());
    }

    println!("\n{}", style.bold("Background agent"));
    println!(
        "  {:<10} {}",
        "state",
        match (status.installed, status.loaded) {
            (true, true) => style.green("installed and loaded"),
            (true, false) => style.yellow("installed but not loaded"),
            _ => style.dim("not installed — `eve agent install`"),
        }
    );
    if let Some(program) = &status.program {
        println!("  {:<10} {}", "runs", program.display());
        // The one thing worth checking by eye: launchd must run the same
        // binary the permission was granted to, or the unattended run is
        // silently blind while the app in front of you works fine.
        let mine = std::env::current_exe().ok();
        if mine.as_deref() != Some(program.as_path()) {
            println!(
                "  {:<10} {}",
                "",
                style.yellow(&format!(
                    "not this binary ({}) — each needs its own Full Disk Access grant",
                    mine.map(|p| p.display().to_string()).unwrap_or_default()
                ))
            );
        }
    }
    println!("  {:<10} {}\n", "plist", style.dim(&status.plist.display().to_string()));
    Ok(())
}

fn cmd_permissions(cli: &Cli, style: &Style, fix: bool) -> anyhow::Result<()> {
    use eve_core::permissions::{self, PermissionState};

    // Ask before reporting, so anything eve has never requested is at least
    // listed in System Settings by the time the user goes looking.
    permissions::provoke_all();
    let all = permissions::check_all();

    if cli.json {
        println!("{}", serde_json::to_string_pretty(&all)?);
        return Ok(());
    }

    println!("\n{}", style.bold("Permissions"));
    for p in &all {
        let (mark, label) = match p.state {
            PermissionState::Granted => (style.green("✓"), style.green("granted")),
            PermissionState::Denied => (style.red("✗"), style.red("not granted")),
            PermissionState::Unknown => (style.dim("?"), style.dim("cannot be checked")),
        };
        println!("  {} {:<20} {}", mark, p.title, label);
        if p.state != PermissionState::Granted {
            println!("    {}", style.dim(p.what_breaks));
            println!("    {}", style.dim(&format!("look for {:?}", p.look_for)));
        }
    }

    let missing: Vec<_> = all
        .iter()
        .filter(|p| p.state == PermissionState::Denied)
        .collect();

    if missing.is_empty() {
        println!("\n  {}\n", style.green("Nothing is missing."));
        return Ok(());
    }

    if fix {
        let first = missing[0];
        println!("\n  {}", style.dim(&format!("opening {}", first.title)));
        std::process::Command::new("/usr/bin/open")
            .arg(first.settings_url)
            .status()?;
    } else {
        println!("\n  {}\n", style.dim("eve permissions --fix opens the right pane."));
    }
    Ok(())
}

fn cmd_categories(cli: &Cli, style: &Style) -> anyhow::Result<()> {
    let catalog = eve_catalog::catalog();
    if cli.json {
        println!("{}", serde_json::to_string_pretty(&catalog)?);
        return Ok(());
    }

    for group in eve_catalog::Group::all() {
        let cats: Vec<_> = catalog.iter().filter(|c| c.group == group).collect();
        if cats.is_empty() {
            continue;
        }
        println!("\n{}", style.bold(group.title()));
        for c in cats {
            let mut flags = vec![c.tier.to_string()];
            if c.needs_root() {
                flags.push("root".into());
            }
            if !c.available() {
                flags.push("unavailable".into());
            }
            if !c.on_by_default() {
                flags.push("opt-in".into());
            }
            println!(
                "  {:<22} {}",
                style.cyan(c.key),
                style.dim(&format!("[{}]", flags.join(", ")))
            );
            println!("  {:<22} {}", "", c.description);
        }
    }
    println!();
    Ok(())
}

fn cmd_analyze(
    cli: &Cli,
    style: &Style,
    path: Option<PathBuf>,
    files: bool,
    extensions: bool,
    limit: usize,
) -> anyhow::Result<()> {
    let root = path.unwrap_or_else(home);
    let budget = Duration::from_secs(45);

    if extensions {
        let rows = analyze::by_extension(&root, budget);
        if cli.json {
            println!("{}", serde_json::to_string_pretty(&rows)?);
            return Ok(());
        }
        println!("\n{}", style.bold(&format!("By extension — {}", root.display())));
        for (ext, bytes, count) in rows.iter().take(limit) {
            println!(
                "  {:>10}  {:<14} {}",
                style.green(&human_bytes(*bytes)),
                ext,
                style.dim(&format!("{count} files"))
            );
        }
        println!();
        return Ok(());
    }

    if files {
        let rows = analyze::largest_files(&root, limit, budget);
        if cli.json {
            println!("{}", serde_json::to_string_pretty(&rows)?);
            return Ok(());
        }
        println!("\n{}", style.bold(&format!("Largest files — {}", root.display())));
        for e in &rows {
            println!(
                "  {:>10}  {}",
                style.green(&human_bytes(e.bytes)),
                e.path.display()
            );
        }
        println!();
        return Ok(());
    }

    let a = analyze::analyze(&root, budget);
    if cli.json {
        println!("{}", serde_json::to_string_pretty(&a)?);
        return Ok(());
    }

    println!("\n{}", style.bold(&format!("{}", root.display())));
    println!(
        "{}\n",
        style.dim(&format!(
            "{} total · {} reclaimable",
            human_bytes(a.total_bytes),
            human_bytes(a.cleanable_bytes())
        ))
    );

    let ranked = a.ranked();
    let widest = ranked.iter().take(limit).map(|e| e.bytes).max().unwrap_or(1);
    for e in ranked.iter().take(limit) {
        let bar_width = ((e.bytes as f64 / widest.max(1) as f64) * 24.0).round() as usize;
        let bar = "█".repeat(bar_width.max(usize::from(e.bytes > 0)));
        let tag = match e.cleanable {
            Some(why) => style.yellow(&format!("  ← {why}")),
            None => String::new(),
        };
        println!(
            "  {:>10}  {:<24} {}{}",
            style.green(&human_bytes(e.bytes)),
            style.dim(&bar),
            e.name,
            tag
        );
    }
    if !a.complete {
        println!("\n{}", style.dim("Scan hit its time budget; totals are partial."));
    }
    println!();
    Ok(())
}

/// Remove what is in the Trash that only root can remove.
///
/// A privileged uninstall lands a root-owned bundle in the user's Trash —
/// macOS refuses to let even root hand a signed bundle over — and the user is
/// then unable to empty their own Trash. Without this, eve's own admin
/// uninstall would manufacture the stuck Trash it spent all day fixing.
fn empty_trash_as_admin(style: &Style) -> anyhow::Result<u64> {
    use eve_core::privilege::PrivilegeBroker;

    let trash = home().join(".Trash");
    let stuck = eve_core::executor::Executor::trash_needs_admin(&trash);
    if stuck.is_empty() {
        return Ok(0);
    }

    println!(
        "\n  {} {} item(s) in the Trash are owned by the system and need administrator rights.",
        style.yellow("⚠"),
        stuck.len()
    );
    for p in &stuck {
        println!("    {}", p.display());
    }

    let ops: Vec<eve_core::Operation> = stuck
        .iter()
        .map(|p| {
            eve_core::Operation::new("trash", p.clone(), eve_core::RiskTier::Review)
                .with_disposition(eve_core::executor::Disposition::Permanent)
        })
        .collect();

    let mut broker = eve_core::privilege::AdminPrompt::new(
        "eve needs administrator rights to empty items the system owns from your Trash.",
    );
    let reports = broker.execute(&eve_core::privilege::Plan::new(ops).dry_run(false))?;

    let mut freed = 0;
    for r in reports {
        match r.problem() {
            Some(why) => println!("  {} {}", style.yellow("⊘"), why),
            None => freed += r.bytes(),
        }
    }
    Ok(freed)
}

/// The Disk view, from a terminal.
///
/// Exists so the browser and its deletions can be proven without a webview —
/// the window's Disk screen calls exactly these two functions.
fn cmd_browse(
    cli: &Cli,
    style: &Style,
    path: Option<PathBuf>,
    delete: Vec<PathBuf>,
    execute: bool,
    timing: bool,
) -> anyhow::Result<()> {
    if !delete.is_empty() {
        let ops = eve_engines::browse::to_operations(&delete);
        let policy = policy();
        let liveness = Liveness::snapshot();
        let journal = Journal::open_default().ok();
        let executor = if execute {
            eve_core::executor::Executor::live()
        } else {
            eve_core::executor::Executor::dry_run()
        };
        let mut funnel = eve_core::funnel::Funnel::new(&policy, &liveness, &executor);
        if let Some(j) = &journal {
            funnel = funnel.with_journal(j);
        }
        let reports = funnel.run_all(&ops);
        if cli.json {
            println!("{}", serde_json::to_string_pretty(&reports)?);
            return Ok(());
        }
        if !execute {
            println!("\n{}", style.dim("Preview — nothing will be deleted"));
        }
        for r in &reports {
            match r.problem() {
                Some(why) => println!("  {} {}", style.yellow("⊘"), why),
                None => println!(
                    "  {} {} {}",
                    style.green("✓"),
                    human_bytes(r.bytes()),
                    r.path.display()
                ),
            }
        }
        return Ok(());
    }

    let root = path.unwrap_or_else(home);
    let started = std::time::Instant::now();
    let result = eve_engines::browse::browse(&root).map_err(|e| anyhow::anyhow!(e))?;
    let elapsed = started.elapsed();

    if cli.json {
        println!("{}", serde_json::to_string_pretty(&result)?);
    } else {
        println!("\n{}", style.bold(&result.path.display().to_string()));
        for e in &result.entries {
            println!(
                "  {:>10}  {}{}{}",
                style.green(&human_bytes(e.bytes)),
                if e.is_dir { "📁 " } else { "" },
                e.name,
                if e.complete { String::new() } else { style.dim(" (partial)") }
            );
        }
        println!(
            "\n  {} {} across {} items",
            style.bold("Total:"),
            style.green(&human_bytes(result.total)),
            result.entries.len()
        );
    }
    if timing {
        // Twice, because the second one is the number that matters. Walking
        // into a folder and back out is the normal way this view is used, and
        // the return trip used to cost exactly as much as the trip in.
        let again = std::time::Instant::now();
        let _ = eve_engines::browse::browse(&root);
        println!(
            "  listing took {} ms cold, {} ms warm",
            elapsed.as_millis(),
            again.elapsed().as_millis()
        );
    }
    Ok(())
}

fn cmd_uninstall(
    cli: &Cli,
    style: &Style,
    app: Option<String>,
    execute: bool,
    yes: bool,
    privileged: bool,
) -> anyhow::Result<()> {
    let apps = uninstall::list_apps(&[]);

    let Some(name) = app else {
        if cli.json {
            println!("{}", serde_json::to_string_pretty(&apps)?);
            return Ok(());
        }
        println!("\n{}", style.bold("Installed applications"));
        for a in &apps {
            println!(
                "  {:>10}  {:<34} {}",
                style.green(&human_bytes(a.bytes)),
                a.name,
                style.dim(a.bundle_id.as_deref().unwrap_or("no bundle id"))
            );
        }
        println!("\n{}", style.dim("eve uninstall \"<name>\" to see a removal plan."));
        return Ok(());
    };

    let needle = name.to_lowercase();
    let Some(target) = apps.iter().find(|a| a.name.to_lowercase() == needle).or_else(|| {
        apps.iter()
            .find(|a| a.name.to_lowercase().contains(&needle))
    }) else {
        anyhow::bail!("no application matching {name:?}");
    };

    let plan = uninstall::plan(target, &home());
    if cli.json {
        println!("{}", serde_json::to_string_pretty(&plan)?);
        return Ok(());
    }

    println!("\n{}", style.bold(&format!("Remove {}", plan.app.name)));
    println!(
        "  {:>10}  {}",
        style.green(&human_bytes(plan.app.bytes)),
        plan.bundle_path.display()
    );
    for l in &plan.leftovers {
        println!(
            "  {:>10}  {} {}",
            style.green(&human_bytes(l.bytes)),
            l.path.display(),
            style.dim(&format!("({})", l.kind))
        );
    }
    match plan.siblings {
        uninstall::SiblingScan::Sole => {}
        uninstall::SiblingScan::SiblingFound => println!(
            "\n  {}",
            style.yellow("Another install of this bundle exists — shared files kept.")
        ),
        uninstall::SiblingScan::Indeterminate => println!(
            "\n  {}",
            style.yellow(
                "Could not prove this is the only install — shared files kept, \
                 which is the conservative reading."
            )
        ),
    }
    println!(
        "\n  {} {}",
        style.bold("Total:"),
        style.bold(&style.green(&human_bytes(plan.total_bytes)))
    );

    // Said before the run, not after it. An app the system owns cannot be
    // moved by this user at all, and finding that out only once the removal
    // has "failed" is how it reads as a bug in eve.
    let system_owned = eve_core::executor::Executor::needs_admin_to_relocate(&plan.bundle_path);
    if system_owned && !privileged {
        println!(
            "\n  {}",
            style.yellow(
                "The system owns this application — it was installed by a package, not \
                 dragged in. Removing it needs administrator rights: add --privileged."
            )
        );
    }

    if !execute {
        println!("\n{}", style.dim("Run with --execute to remove."));
        return Ok(());
    }
    if !yes && !confirm(style, plan.total_bytes, 0)? {
        println!("Aborted.");
        return Ok(());
    }

    let ops = uninstall::plan_to_operations(&plan);

    // Root re-runs the whole funnel on its own side; it is trusted with the
    // request, never with the parent's verdict.
    let reports = if privileged {
        // The macOS dialog rather than sudo: it works with or without a
        // terminal, which is what lets the window offer this at all, and it is
        // the same prompt Finder raises to move a system-owned app to the
        // Trash. Falls back to sudo when there is no window server to draw in.
        let mut broker: Box<dyn PrivilegeBroker> = if std::env::var_os("SSH_TTY").is_some() {
            Box::new(SudoWorker::interactive())
        } else {
            Box::new(eve_core::privilege::AdminPrompt::new(
                "eve needs administrator rights to remove an application the system owns.",
            ))
        };
        if !broker.available() {
            anyhow::bail!("could not escalate — {}", broker.describe());
        }
        broker.execute(&eve_core::privilege::Plan::new(ops).dry_run(false))?
    } else {
        let policy = policy();
        let liveness = Liveness::snapshot();
        let journal = Journal::open_default().ok();
        let executor = eve_core::executor::Executor::live();
        let mut funnel = eve_core::funnel::Funnel::new(&policy, &liveness, &executor);
        if let Some(j) = &journal {
            funnel = funnel.with_journal(j);
        }
        funnel.run_all(&ops)
    };

    let mut freed = 0;
    for report in reports {
        match report.problem() {
            Some(why) => println!("  {} {}", style.yellow("⊘"), why),
            None => freed += report.bytes(),
        }
    }
    println!(
        "\n  {} {}",
        style.bold("Removed:"),
        style.green(&human_bytes(freed))
    );
    Ok(())
}

fn cmd_trash_blockers(cli: &Cli, style: &Style) -> anyhow::Result<()> {
    let trash = home().join(".Trash");
    let blockers = eve_engines::blockers::holding(&trash);
    if cli.json {
        println!("{}", serde_json::to_string_pretty(&blockers)?);
        return Ok(());
    }
    if blockers.is_empty() {
        println!("\n{}\n", style.dim("Nothing is holding your Trash open."));
        return Ok(());
    }
    println!("\n{}", style.bold("Holding your Trash open"));
    for b in &blockers {
        println!(
            "  {:>10}  {} {}",
            style.green(&human_bytes(b.bytes)),
            b.name,
            style.dim(&format!("({}) — {}", b.pid, b.entries.join(", ")))
        );
    }
    println!(
        "\n  {}\n",
        style.dim("Quit these and the entries they hold will empty with the rest.")
    );
    Ok(())
}

fn cmd_installer(
    cli: &Cli,
    style: &Style,
    min_age_days: u64,
    execute: bool,
    yes: bool,
) -> anyhow::Result<()> {
    let found = installer::find(&home(), min_age_days, Duration::from_secs(30));
    if cli.json {
        println!("{}", serde_json::to_string_pretty(&found)?);
        return Ok(());
    }

    if found.is_empty() {
        println!("\n{}\n", style.dim("No leftover installers found."));
        return Ok(());
    }

    let total: u64 = found.iter().map(|i| i.bytes).sum();
    println!("\n{}", style.bold("Leftover installers"));
    for i in &found {
        println!(
            "  {:>10}  {:<52} {}",
            style.green(&human_bytes(i.bytes)),
            i.path.display(),
            style.dim(&format!("{} · {}d", i.kind, i.age_days))
        );
    }
    println!("\n  {} {}", style.bold("Total:"), style.green(&human_bytes(total)));

    if !execute {
        println!("\n{}\n", style.dim("Run with --execute to move these to the Trash."));
        return Ok(());
    }
    if !yes && !confirm(style, total, 0)? {
        println!("Aborted.");
        return Ok(());
    }

    let policy = policy();
    let liveness = Liveness::snapshot();
    let executor = eve_core::executor::Executor::live();
    let funnel = eve_core::funnel::Funnel::new(&policy, &liveness, &executor);
    let mut freed = 0;
    for r in funnel.run_all(&installer::to_operations(&found)) {
        match r.problem() {
            Some(why) => println!("  {} {}", style.yellow("⊘"), why),
            None => freed += r.bytes(),
        }
    }
    println!("\n  {} {}\n", style.bold("Reclaimed:"), style.green(&human_bytes(freed)));
    Ok(())
}

fn cmd_optimize(cli: &Cli, style: &Style, execute: bool) -> anyhow::Result<()> {
    let h = home();
    let broken = optimize::find_broken_agents(&h);
    let corrupt = optimize::find_corrupt_prefs(&h);

    if cli.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "broken_agents": broken.iter().map(|(p, prog)| {
                    serde_json::json!({ "plist": p, "missing_program": prog })
                }).collect::<Vec<_>>(),
                "corrupt_preferences": corrupt,
                "tasks": optimize::TASKS,
            }))?
        );
        return Ok(());
    }

    println!("\n{}", style.bold("Maintenance"));
    if broken.is_empty() && corrupt.is_empty() {
        println!("  {}", style.dim("No broken login items or corrupt preferences."));
    }
    for (plist, program) in &broken {
        println!(
            "  {} {} {}",
            style.yellow("⚠"),
            plist.display(),
            style.dim(&format!("→ missing {program}"))
        );
    }
    for p in &corrupt {
        println!("  {} {} {}", style.yellow("⚠"), p.display(), style.dim("unparseable"));
    }

    println!("\n{}", style.bold("Tasks"));
    for t in optimize::TASKS {
        println!(
            "  {:<18} {} {}",
            style.cyan(t.key),
            t.detail,
            if t.privileged { style.dim("(root)") } else { String::new() }
        );
    }

    if execute {
        println!();
        for r in [
            optimize::rebuild_launch_services(false),
            optimize::flush_dns(false),
        ] {
            let mark = if r.ok { style.green("✓") } else { style.yellow("·") };
            println!(
                "  {} {} {}",
                mark,
                r.title,
                style.dim(r.detail.as_deref().unwrap_or(""))
            );
        }
    } else {
        println!("\n{}", style.dim("Run with --execute to apply."));
    }
    println!();
    Ok(())
}

fn cmd_status(cli: &Cli, style: &Style) -> anyhow::Result<()> {
    let s = status::collect();
    if cli.json {
        println!("{}", serde_json::to_string_pretty(&s)?);
        return Ok(());
    }

    println!("\n{}", style.bold(&format!("{} · {}", s.host, s.os)));
    println!(
        "{}\n",
        style.dim(&format!(
            "up {}h {}m · {} cores · load {:.2} {:.2} {:.2}",
            s.uptime_secs / 3600,
            (s.uptime_secs % 3600) / 60,
            s.cpu_count,
            s.load[0],
            s.load[1],
            s.load[2]
        ))
    );

    println!("  {:<10} {:.0}%", style.bold("CPU"), s.cpu_usage);
    println!(
        "  {:<10} {} / {}",
        style.bold("Memory"),
        human_bytes(s.mem_used),
        human_bytes(s.mem_total)
    );
    if s.swap_total > 0 {
        println!(
            "  {:<10} {} / {}",
            style.bold("Swap"),
            human_bytes(s.swap_used),
            human_bytes(s.swap_total)
        );
    }

    println!("\n{}", style.bold("Volumes"));
    for v in &s.volumes {
        println!(
            "  {:<28} {:>10} free {}",
            v.mount.display(),
            style.green(&human_bytes(v.available)),
            style.dim(&format!("({:.0}% used)", v.used_pct()))
        );
    }

    println!("\n{}", style.bold("Health"));
    for f in &s.health {
        let mark = match f.level {
            status::Level::Ok => style.green("✓"),
            status::Level::Warn => style.yellow("⚠"),
            status::Level::Critical => style.red("✗"),
        };
        println!("  {} {} {}", mark, f.subject, style.dim(&f.detail));
    }

    println!("\n{}", style.bold("Top processes"));
    for p in s.top_processes.iter().take(5) {
        println!(
            "  {:>6}  {:<28} {:>5.1}%  {}",
            p.pid,
            p.name,
            p.cpu,
            style.dim(&human_bytes(p.memory))
        );
    }
    println!();
    Ok(())
}

fn cmd_history(cli: &Cli, style: &Style, limit: usize) -> anyhow::Result<()> {
    let journal = Journal::open_default()?;
    let entries = journal.read_all()?;

    if cli.json {
        println!("{}", serde_json::to_string_pretty(&entries)?);
        return Ok(());
    }

    if entries.is_empty() {
        println!("\n{}\n", style.dim("eve has not deleted anything yet."));
        return Ok(());
    }

    println!("\n{}", style.bold("History"));
    let total: u64 = entries.iter().filter(|e| !e.dry_run).map(|e| e.bytes).sum();
    for e in entries.iter().rev().take(limit) {
        let mark = match (&e.error, e.dry_run) {
            (Some(_), _) => style.red("✗"),
            (None, true) => style.dim("·"),
            (None, false) => style.green("✓"),
        };
        println!(
            "  {} {} {:>10}  {:<18} {}",
            mark,
            style.dim(&e.timestamp()),
            human_bytes(e.bytes),
            e.category,
            style.dim(&e.path.display().to_string())
        );
    }
    println!(
        "\n  {} {} across {} entries",
        style.bold("Reclaimed to date:"),
        style.green(&human_bytes(total)),
        entries.len()
    );
    println!("  {}\n", style.dim(&journal.path().display().to_string()));
    Ok(())
}

fn cmd_whitelist(cli: &Cli, style: &Style) -> anyhow::Result<()> {
    let p = policy();
    let patterns = p.whitelist_patterns();

    if cli.json {
        let rows: Vec<_> = patterns
            .iter()
            .map(|(pat, src)| serde_json::json!({ "pattern": pat, "source": src }))
            .collect();
        println!("{}", serde_json::to_string_pretty(&rows)?);
        return Ok(());
    }

    println!("\n{}", style.bold("Protected by whitelist"));
    println!(
        "{}\n",
        style.dim("These are never deleted, regardless of category.")
    );
    for (pat, src) in patterns {
        println!("  {} {}", style.green("•"), pat);
        println!("    {}", style.dim(src));
    }
    println!();
    Ok(())
}
