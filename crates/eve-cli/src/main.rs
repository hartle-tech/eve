//! `eve` — macOS cleanup, analysis and maintenance.

mod autoclean;
mod render;
mod tui;

use std::io::{IsTerminal, Write};
use std::path::PathBuf;
use std::time::Duration;

use clap::{Parser, Subcommand};

use eve_core::journal::Journal;
use eve_core::liveness::Liveness;
use eve_core::policy::Policy;
use eve_core::privilege::{PrivilegeBroker, SudoWorker, WORKER_ARG};
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
    /// Remove an application and its leftovers.
    Uninstall {
        /// Application name. Omit to list what is installed.
        app: Option<String>,
        #[arg(long)]
        execute: bool,
        #[arg(long, short)]
        yes: bool,
    },
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
        /// Fire when free space drops below this many GB.
        #[arg(long, default_value_t = 5)]
        threshold_gb: u64,
        /// Minimum seconds between real runs.
        #[arg(long, default_value_t = 10800)]
        cooldown_sec: u64,
        /// Go through the motions without deleting.
        #[arg(long)]
        dry_run: bool,
    },
}

fn main() {
    // The privileged peer. Checked before clap so the hidden argument never
    // appears in help output or competes with a real subcommand.
    let argv: Vec<String> = std::env::args().collect();
    if argv.len() == 2 && argv[1] == WORKER_ARG {
        if let Err(e) = eve_core::privilege::worker_main(&CatalogAuthorizer::build()) {
            eprintln!("eve worker: {e}");
            std::process::exit(1);
        }
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
struct CatalogAuthorizer {
    /// category key -> the exact set of paths that category generates.
    allowed: std::collections::HashMap<String, std::collections::HashSet<PathBuf>>,
}

impl CatalogAuthorizer {
    fn build() -> Self {
        // Built from the *invoking* user's home, not root's. Under sudo,
        // dirs::home_dir() is /var/root and every category would resolve to
        // paths that do not exist, refusing everything.
        let home = eve_core::privilege::invoking_user_home();
        let mut allowed: std::collections::HashMap<String, std::collections::HashSet<PathBuf>> =
            std::collections::HashMap::new();

        for cat in eve_catalog::catalog_for(&home) {
            let entry = allowed.entry(cat.key.to_string()).or_default();
            for op in eve_engines::clean::build_operations(&cat, &home) {
                entry.insert(eve_core::path::normalize(&op.path));
            }
        }
        CatalogAuthorizer { allowed }
    }
}

impl eve_core::privilege::PlanAuthorizer for CatalogAuthorizer {
    fn authorizes(&self, op: &eve_core::Operation) -> bool {
        self.allowed
            .get(&op.category)
            .is_some_and(|paths| paths.contains(&eve_core::path::normalize(&op.path)))
    }
}

fn home() -> PathBuf {
    dirs::home_dir().unwrap_or_else(|| PathBuf::from("/"))
}

fn policy() -> Policy {
    Policy::current().with_default_whitelist()
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
        }) => cmd_clean(
            cli, style, *execute, *yes, only, skip, include, *privileged, *unattended,
        ),
        Some(Command::Categories) => cmd_categories(cli, style),
        Some(Command::Analyze {
            path,
            files,
            extensions,
            limit,
        }) => cmd_analyze(cli, style, path.clone(), *files, *extensions, *limit),
        Some(Command::Uninstall { app, execute, yes }) => {
            cmd_uninstall(cli, style, app.clone(), *execute, *yes)
        }
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
        }) => autoclean::run(&autoclean::Config {
            threshold_gb: *threshold_gb,
            cooldown_sec: *cooldown_sec,
            dry_run: *dry_run,
        }),
    }
}

#[allow(clippy::too_many_arguments)]
fn cmd_clean(
    cli: &Cli,
    style: &Style,
    execute: bool,
    yes: bool,
    only: &[String],
    skip: &[String],
    include: &[String],
    privileged: bool,
    unattended: bool,
) -> anyhow::Result<()> {
    let policy = policy();
    let liveness = Liveness::snapshot();
    let journal = Journal::open_default().ok();
    let catalog = eve_catalog::catalog();

    let sel = Selection {
        only: only.to_vec(),
        skip: skip.to_vec(),
        include: include.to_vec(),
        unattended,
        allow_privileged: privileged,
    };

    let mut cleaner = Cleaner::new(&policy, &liveness);
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
        if !confirm(style, preview.total_bytes())? {
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

    let report = match broker.as_deref_mut() {
        Some(b) => cleaner.execute(&catalog, &sel, Some(b)),
        None => cleaner.execute(&catalog, &sel, None),
    };

    if cli.json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        render::print_report(&report, style, cli.verbose);
        if report.categories.iter().any(|c| c.key == "siri_assets") {
            render::print_settings_hints(style);
        }
    }
    Ok(())
}

fn confirm(style: &Style, bytes: u64) -> anyhow::Result<bool> {
    if !std::io::stdin().is_terminal() {
        // No one is there to answer. Refusing is the only safe reading of
        // silence; --yes exists for exactly this case.
        eprintln!("Refusing to delete without a terminal to confirm on. Pass --yes.");
        return Ok(false);
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

fn cmd_uninstall(
    cli: &Cli,
    style: &Style,
    app: Option<String>,
    execute: bool,
    yes: bool,
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

    if !execute {
        println!("\n{}", style.dim("Run with --execute to remove."));
        return Ok(());
    }
    if !yes && !confirm(style, plan.total_bytes)? {
        println!("Aborted.");
        return Ok(());
    }

    let policy = policy();
    let liveness = Liveness::snapshot();
    let journal = Journal::open_default().ok();
    let executor = eve_core::executor::Executor::live();
    let mut funnel = eve_core::funnel::Funnel::new(&policy, &liveness, &executor);
    if let Some(j) = &journal {
        funnel = funnel.with_journal(j);
    }

    let mut freed = 0;
    for report in funnel.run_all(&uninstall::plan_to_operations(&plan)) {
        match &report.denial {
            Some(d) => println!("  {} {}", style.yellow("⊘"), d),
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
    if !yes && !confirm(style, total)? {
        println!("Aborted.");
        return Ok(());
    }

    let policy = policy();
    let liveness = Liveness::snapshot();
    let executor = eve_core::executor::Executor::live();
    let funnel = eve_core::funnel::Funnel::new(&policy, &liveness, &executor);
    let mut freed = 0;
    for r in funnel.run_all(&installer::to_operations(&found)) {
        match &r.denial {
            Some(d) => println!("  {} {}", style.yellow("⊘"), d),
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
