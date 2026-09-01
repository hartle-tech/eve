//! The interactive terminal interface.

use std::io::stdout;
use std::time::{Duration, Instant};

use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use ratatui::prelude::*;
use ratatui::widgets::{Block, Borders, Cell, Gauge, List, ListItem, Paragraph, Row, Table, Tabs};

use eve_core::journal::{Journal, JournalEntry};
use eve_core::liveness::Liveness;
use eve_core::policy::Policy;
use eve_core::prefs::{Preferences, TrashExclusions};
use eve_core::privilege::SudoWorker;
use eve_core::size::human_bytes;
use eve_engines::clean::{CategoryResult, CleanReport, Cleaner, Selection};
use eve_engines::status::{self, Level, Status};

const ACCENT: Color = Color::Rgb(126, 200, 227);
const GOOD: Color = Color::Rgb(126, 200, 140);
const WARN: Color = Color::Rgb(226, 190, 110);
const BAD: Color = Color::Rgb(226, 120, 120);
const MUTED: Color = Color::Rgb(120, 128, 140);

#[derive(Clone, Copy, PartialEq, Eq)]
enum Tab {
    Clean,
    Status,
    History,
    Settings,
}

impl Tab {
    const ALL: [Tab; 4] = [Tab::Clean, Tab::Status, Tab::History, Tab::Settings];
    fn title(self) -> &'static str {
        match self {
            Tab::Clean => "Clean",
            Tab::Status => "Status",
            Tab::History => "History",
            Tab::Settings => "Settings",
        }
    }
    fn index(self) -> usize {
        Tab::ALL.iter().position(|t| *t == self).unwrap_or(0)
    }
}

/// One line on the Settings tab.
#[derive(Debug, PartialEq, Eq)]
enum SettingsRow {
    DirectCleanup(bool),
    ThresholdGb(u64),
    CooldownSec(u64),
    /// A Trash entry that is kept rather than emptied. `source` records where
    /// it came from — eve's seed list, eve noticing something undeletable, or
    /// the user typing it — but never affects whether it can be removed.
    Exclusion {
        pattern: String,
        source: &'static str,
    },
}

/// The Settings tab as data, so what the user can act on is decided in one
/// place rather than inferred from a cursor position during a keypress.
fn settings_rows(prefs: &Preferences) -> Vec<SettingsRow> {
    let mut rows = vec![
        SettingsRow::DirectCleanup(prefs.direct_cleanup()),
        SettingsRow::ThresholdGb(prefs.threshold_gb),
        SettingsRow::CooldownSec(prefs.cooldown_sec),
    ];
    rows.extend(
        prefs
            .effective_trash_exclusions()
            .into_iter()
            .map(|(pattern, source)| SettingsRow::Exclusion { pattern, source }),
    );
    rows
}

struct App {
    tab: Tab,
    cursor: usize,
    report: Option<CleanReport>,
    /// Categories the user has turned off for this session.
    disabled: Vec<String>,
    privileged: bool,
    status: Option<Status>,
    history: Vec<JournalEntry>,
    message: Option<(String, Color)>,
    scanning: bool,
    /// Enter arms the clean; a second Enter fires it.
    ///
    /// Everywhere else in eve a deletion needs `--execute`. A TUI where one
    /// keypress silently deletes would be the single place that contract does
    /// not hold, and it is the place where a stray Enter is most likely.
    armed: bool,
    quit: bool,
    /// Settings that outlive the session, shared with the CLI and the app.
    prefs: Preferences,
    /// A pattern being typed on the Settings tab.
    input: Option<String>,
}

impl App {
    fn new() -> Self {
        // A settings file that will not parse is reported rather than silently
        // replaced with defaults — otherwise the user turns empty-trash on,
        // comes back, and finds it off with no explanation.
        let (prefs, message) = match Preferences::load_default() {
            Ok(p) => (p, None),
            Err(e) => (
                Preferences::default(),
                Some((format!("settings not applied — {e}"), BAD)),
            ),
        };

        App {
            tab: Tab::Clean,
            cursor: 0,
            report: None,
            disabled: Vec::new(),
            privileged: false,
            status: None,
            history: Vec::new(),
            message,
            scanning: false,
            armed: false,
            quit: false,
            prefs,
            input: None,
        }
    }

    fn selection(&self) -> Selection {
        Selection {
            skip: self.disabled.clone(),
            allow_privileged: self.privileged,
            empty_trash: self.prefs.empty_trash,
            empty_trash_at: self.prefs.empty_trash_at,
            permanent_delete: self.prefs.permanent_delete,
            ..Default::default()
        }
    }

    fn cleaner<'a>(&self, policy: &'a Policy, liveness: &'a Liveness) -> Cleaner<'a> {
        Cleaner::new(policy, liveness)
            .with_trash_exclusions(TrashExclusions::compile(&self.prefs))
    }

    /// Persist immediately. A setting that only takes effect when the TUI
    /// exits cleanly is not a setting the LaunchAgent can rely on.
    fn save_prefs(&mut self) {
        if let Err(e) = self.prefs.save_default() {
            self.message = Some((format!("could not save: {e}"), BAD));
        }
    }

    fn settings(&self) -> Vec<SettingsRow> {
        settings_rows(&self.prefs)
    }

    /// Act on the Settings row under the cursor.
    fn activate_setting(&mut self) {
        match self.settings().get(self.cursor) {
            Some(SettingsRow::DirectCleanup(on)) => {
                let now = !on;
                self.prefs.set_direct_cleanup(now);
                self.save_prefs();
                self.message = Some((
                    if now {
                        "Cleanups now free the space — and none of it is recoverable".into()
                    } else {
                        "Everything goes to the Trash; eve will not empty it".to_string()
                    },
                    if now { WARN } else { MUTED },
                ));
            }
            // Numbers are typed, not toggled — space would need a direction
            // and a step, and both are guesses.
            Some(SettingsRow::ThresholdGb(_)) | Some(SettingsRow::CooldownSec(_)) => {
                self.input = Some(String::new());
                self.message = Some(("type a number, enter to set".into(), ACCENT));
            }
            Some(SettingsRow::Exclusion { .. }) => {
                self.message = Some(("a to add an exclusion, d to remove one".into(), MUTED));
            }
            None => {}
        }
    }

    /// Remove the exclusion under the cursor — any exclusion, including one eve
    /// seeded or added itself.
    ///
    /// There used to be a class that refused to go, on the theory that macOS
    /// would never delete those entries anyway. That made the list a place
    /// where eve overrode the user for their own good, and the reasoning was
    /// not even reliably true. If an entry really is undeletable the sweep
    /// finds that out and puts it back; that is a fact eve discovers, not a
    /// rule it imposes.
    fn remove_setting(&mut self) {
        let rows = self.settings();
        let Some(SettingsRow::Exclusion { pattern, .. }) = rows.get(self.cursor) else {
            return;
        };
        let pattern = pattern.clone();
        self.prefs.unexclude_trash(&pattern);
        self.save_prefs();
        self.cursor = self.cursor.min(self.settings().len().saturating_sub(1));
        self.message = Some((format!("removed {pattern}"), MUTED));
    }

    fn commit_input(&mut self) {
        let Some(typed) = self.input.take() else {
            return;
        };
        let typed = typed.trim().to_string();
        if typed.is_empty() {
            return;
        }

        // The same input line serves both, so the row under the cursor decides
        // what the text means.
        match self.settings().get(self.cursor) {
            Some(SettingsRow::ThresholdGb(_)) => {
                self.message = Some(match typed.parse::<u64>() {
                    Ok(0) => ("a 0 GB threshold would never fire".into(), BAD),
                    Ok(gb) => {
                        self.prefs.threshold_gb = gb;
                        self.save_prefs();
                        (format!("unattended runs fire below {gb} GB"), GOOD)
                    }
                    Err(_) => (format!("{typed:?} is not a number"), BAD),
                });
                return;
            }
            Some(SettingsRow::CooldownSec(_)) => {
                self.message = Some(match typed.parse::<u64>() {
                    Ok(secs) => {
                        self.prefs.cooldown_sec = secs;
                        self.save_prefs();
                        (format!("at most one real run every {secs}s"), GOOD)
                    }
                    Err(_) => (format!("{typed:?} is not a number"), BAD),
                });
                return;
            }
            _ => {}
        }

        let pattern = typed;
        match self.prefs.exclude_trash(&pattern) {
            Ok(true) => {
                self.save_prefs();
                self.message = Some((format!("excluded {pattern}"), GOOD));
            }
            Ok(false) => self.message = Some((format!("{pattern} was already excluded"), MUTED)),
            Err(e) => self.message = Some((format!("not a valid pattern: {e}"), BAD)),
        }
    }

    fn visible(&self) -> Vec<&CategoryResult> {
        self.report
            .as_ref()
            .map(|r| {
                let mut v: Vec<&CategoryResult> =
                    r.categories.iter().filter(|c| !c.is_empty()).collect();
                v.sort_by(|a, b| b.bytes().cmp(&a.bytes()));
                v
            })
            .unwrap_or_default()
    }

    fn scan(&mut self) {
        let policy = Policy::current().with_default_whitelist();
        let liveness = Liveness::snapshot();
        let cleaner = self.cleaner(&policy, &liveness);
        let catalog = eve_catalog::catalog();
        self.report = Some(cleaner.scan(&catalog, &self.selection()));
        self.cursor = 0;
        self.scanning = false;
    }

    fn execute(&mut self) {
        let policy = Policy::current().with_default_whitelist();
        let liveness = Liveness::snapshot();
        let journal = Journal::open_default().ok();
        let mut cleaner = self.cleaner(&policy, &liveness);
        if let Some(j) = &journal {
            cleaner = cleaner.with_journal(j);
        }
        let catalog = eve_catalog::catalog();

        let mut broker = self.privileged.then(SudoWorker::interactive);
        let mut report = match broker.as_mut() {
            Some(b) => cleaner.execute(&catalog, &self.selection(), Some(b)),
            None => cleaner.execute(&catalog, &self.selection(), None),
        };
        report.newly_excluded = eve_engines::clean::learn_undeletable(&report);
        if !report.newly_excluded.is_empty() {
            // The exclusion list just changed under the user; the Settings tab
            // reads it from `self.prefs`, which is now a stale copy.
            self.prefs = Preferences::load_default().unwrap_or_else(|_| self.prefs.clone());
        }

        let freed = report.total_bytes();
        self.message = Some((format!("Reclaimed {}", human_bytes(freed)), GOOD));
        self.report = Some(report);
        self.reload_history();
    }

    fn reload_history(&mut self) {
        if let Ok(j) = Journal::open_default() {
            self.history = j.read_all().unwrap_or_default();
        }
    }

    fn toggle_current(&mut self) {
        let keys: Vec<String> = self.visible().iter().map(|c| c.key.clone()).collect();
        if let Some(key) = keys.get(self.cursor) {
            if let Some(pos) = self.disabled.iter().position(|k| k == key) {
                self.disabled.remove(pos);
            } else {
                self.disabled.push(key.clone());
            }
            self.message = Some((format!("{} categories skipped", self.disabled.len()), MUTED));
        }
    }
}

pub fn run() -> anyhow::Result<()> {
    enable_raw_mode()?;
    let mut out = stdout();
    execute!(out, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(out);
    let mut term = Terminal::new(backend)?;

    let result = event_loop(&mut term);

    disable_raw_mode()?;
    execute!(term.backend_mut(), LeaveAlternateScreen)?;
    term.show_cursor()?;
    result
}

fn event_loop<B: Backend>(term: &mut Terminal<B>) -> anyhow::Result<()> {
    let mut app = App::new();

    // Draw once before the first scan so the UI appears immediately rather
    // than after a multi-second filesystem walk.
    app.scanning = true;
    term.draw(|f| draw(f, &app))?;
    app.scan();
    app.reload_history();

    let mut last_status = Instant::now() - Duration::from_secs(10);

    while !app.quit {
        if app.tab == Tab::Status && last_status.elapsed() > Duration::from_secs(3) {
            app.status = Some(status::collect());
            last_status = Instant::now();
        }

        term.draw(|f| draw(f, &app))?;

        if !event::poll(Duration::from_millis(400))? {
            continue;
        }
        let Event::Key(key) = event::read()? else {
            continue;
        };
        if key.kind != KeyEventKind::Press {
            continue;
        }

        // While typing a pattern, every key belongs to the buffer. Otherwise
        // 'q' in the middle of an exclusion would quit the program.
        if app.input.is_some() {
            match key.code {
                KeyCode::Esc => {
                    app.input = None;
                    app.message = Some(("cancelled".into(), MUTED));
                }
                KeyCode::Enter => app.commit_input(),
                KeyCode::Backspace => {
                    if let Some(buf) = app.input.as_mut() {
                        buf.pop();
                    }
                }
                KeyCode::Char(c) => {
                    if let Some(buf) = app.input.as_mut() {
                        buf.push(c);
                    }
                }
                _ => {}
            }
            continue;
        }

        match key.code {
            KeyCode::Char('q') | KeyCode::Esc => app.quit = true,
            KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => app.quit = true,
            KeyCode::Tab | KeyCode::Right => {
                let i = (app.tab.index() + 1) % Tab::ALL.len();
                app.tab = Tab::ALL[i];
            }
            KeyCode::BackTab | KeyCode::Left => {
                let i = (app.tab.index() + Tab::ALL.len() - 1) % Tab::ALL.len();
                app.tab = Tab::ALL[i];
            }
            KeyCode::Down | KeyCode::Char('j') => {
                let n = rows_for(&app);
                if n > 0 {
                    app.cursor = (app.cursor + 1).min(n - 1);
                }
            }
            KeyCode::Up | KeyCode::Char('k') => app.cursor = app.cursor.saturating_sub(1),
            KeyCode::Char(' ') if app.tab == Tab::Clean => {
                app.toggle_current();
                app.scan();
            }
            KeyCode::Char(' ') | KeyCode::Enter if app.tab == Tab::Settings => {
                app.activate_setting();
            }
            KeyCode::Char('a') if app.tab == Tab::Settings => {
                app.input = Some(String::new());
            }
            KeyCode::Char('d') if app.tab == Tab::Settings => app.remove_setting(),
            KeyCode::Char('t') if app.tab == Tab::Clean => {
                app.prefs.empty_trash = !app.prefs.empty_trash;
                app.save_prefs();
                app.scanning = true;
                term.draw(|f| draw(f, &app))?;
                app.scan();
                app.message = Some((
                    if app.prefs.empty_trash {
                        "Emptying the Trash — permanent, and remembered".into()
                    } else {
                        "Leaving the Trash alone".to_string()
                    },
                    if app.prefs.empty_trash { WARN } else { MUTED },
                ));
            }
            KeyCode::Char('r') => {
                app.scanning = true;
                term.draw(|f| draw(f, &app))?;
                app.scan();
                app.message = Some(("Rescanned".into(), MUTED));
            }
            KeyCode::Char('p') if app.tab == Tab::Clean => {
                app.privileged = !app.privileged;
                app.scanning = true;
                term.draw(|f| draw(f, &app))?;
                app.scan();
                app.message = Some((
                    if app.privileged {
                        "Root categories included".into()
                    } else {
                        "Root categories excluded".to_string()
                    },
                    ACCENT,
                ));
            }
            KeyCode::Enter if app.tab == Tab::Clean => {
                let total = app.report.as_ref().map(|r| r.total_bytes()).unwrap_or(0);
                if total == 0 {
                    app.message = Some(("Nothing to clean".into(), MUTED));
                } else if app.armed {
                    app.armed = false;
                    app.message = Some(("Cleaning…".into(), ACCENT));
                    term.draw(|f| draw(f, &app))?;
                    app.execute();
                } else {
                    app.armed = true;
                    app.message = Some((
                        format!("Press enter again to delete {}", human_bytes(total)),
                        WARN,
                    ));
                }
            }
            _ => {}
        }

        // Anything other than a second Enter disarms. An armed state that
        // survives navigation is exactly the trap this gate exists to prevent.
        if !matches!(key.code, KeyCode::Enter) {
            app.armed = false;
        }
    }
    Ok(())
}

fn rows_for(app: &App) -> usize {
    match app.tab {
        Tab::Clean => app.visible().len(),
        Tab::History => app.history.len(),
        Tab::Settings => app.settings().len(),
        Tab::Status => 0,
    }
}

fn draw(f: &mut Frame, app: &App) {
    let chunks = Layout::vertical([
        Constraint::Length(3),
        Constraint::Min(5),
        Constraint::Length(1),
    ])
    .split(f.area());

    let titles: Vec<Line> = Tab::ALL
        .iter()
        .map(|t| Line::from(format!(" {} ", t.title())))
        .collect();
    f.render_widget(
        Tabs::new(titles)
            .select(app.tab.index())
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(Span::styled(" eve ", Style::default().fg(ACCENT).bold())),
            )
            .highlight_style(Style::default().fg(ACCENT).bold())
            .style(Style::default().fg(MUTED)),
        chunks[0],
    );

    match app.tab {
        Tab::Clean => draw_clean(f, chunks[1], app),
        Tab::Status => draw_status(f, chunks[1], app),
        Tab::History => draw_history(f, chunks[1], app),
        Tab::Settings => draw_settings(f, chunks[1], app),
    }

    if let Some(buf) = &app.input {
        let line = Line::from(vec![
            Span::styled(" exclude: ", Style::default().fg(ACCENT).bold()),
            Span::raw(buf.clone()),
            Span::styled("▏", Style::default().fg(ACCENT)),
            Span::styled("  enter to add · esc to cancel", Style::default().fg(MUTED)),
        ]);
        f.render_widget(Paragraph::new(line), chunks[2]);
        return;
    }

    let help = match app.tab {
        Tab::Clean => {
            " ↑↓ move · space skip · t trash · p root · enter clean (twice) · r rescan · q quit "
        }
        Tab::Status => " ↑↓ move · tab switch · q quit ",
        Tab::History => " ↑↓ move · tab switch · q quit ",
        Tab::Settings => " ↑↓ move · space toggle · a add · d remove · q quit ",
    };
    let footer = match &app.message {
        Some((m, c)) => Line::from(vec![
            Span::styled(format!(" {m} "), Style::default().fg(*c).bold()),
            Span::styled(help, Style::default().fg(MUTED)),
        ]),
        None => Line::from(Span::styled(help, Style::default().fg(MUTED))),
    };
    f.render_widget(Paragraph::new(footer), chunks[2]);
}

fn draw_clean(f: &mut Frame, area: Rect, app: &App) {
    if app.scanning {
        f.render_widget(
            Paragraph::new("\n  Scanning…")
                .style(Style::default().fg(MUTED))
                .block(Block::default().borders(Borders::ALL)),
            area,
        );
        return;
    }

    let split = Layout::vertical([Constraint::Min(3), Constraint::Length(4)]).split(area);
    let cats = app.visible();

    let rows: Vec<Row> = cats
        .iter()
        .enumerate()
        .map(|(i, c)| {
            let skipped = app.disabled.contains(&c.key);
            let mark = if skipped { "○" } else { "●" };
            let base = if skipped {
                Style::default().fg(MUTED).add_modifier(Modifier::CROSSED_OUT)
            } else if i == app.cursor {
                Style::default().fg(ACCENT).bold()
            } else {
                Style::default()
            };
            let tier = if c.needs_root { "root" } else { c.tier.as_str() };
            Row::new(vec![
                Cell::from(mark),
                Cell::from(c.title.clone()),
                Cell::from(human_bytes(c.bytes())).style(Style::default().fg(GOOD)),
                Cell::from(format!("{} items", c.items())).style(Style::default().fg(MUTED)),
                Cell::from(tier).style(Style::default().fg(MUTED)),
            ])
            .style(base)
        })
        .collect();

    let total = app.report.as_ref().map(|r| r.total_bytes()).unwrap_or(0);
    f.render_widget(
        Table::new(
            rows,
            [
                Constraint::Length(2),
                Constraint::Min(24),
                Constraint::Length(12),
                Constraint::Length(12),
                Constraint::Length(11),
            ],
        )
        .block(
            Block::default().borders(Borders::ALL).title(Span::styled(
                format!(" Reclaimable: {} ", human_bytes(total)),
                Style::default().fg(GOOD).bold(),
            )),
        ),
        split[0],
    );

    let detail = cats
        .get(app.cursor)
        .map(|c| {
            let denials = c.notable_denials();
            let mut text = vec![Line::from(Span::styled(
                c.description.clone(),
                Style::default().fg(MUTED),
            ))];
            if !denials.is_empty() {
                text.push(Line::from(Span::styled(
                    format!("  {} refused: {}", denials.len(), denials[0]),
                    Style::default().fg(WARN),
                )));
            }
            text
        })
        .unwrap_or_else(|| vec![Line::from("Nothing to clean.")]);

    f.render_widget(
        Paragraph::new(detail)
            .block(Block::default().borders(Borders::ALL).title(" Detail "))
            .wrap(ratatui::widgets::Wrap { trim: true }),
        split[1],
    );
}

fn draw_settings(f: &mut Frame, area: Rect, app: &App) {
    let split = Layout::vertical([Constraint::Min(3), Constraint::Length(5)]).split(area);

    let rows: Vec<Row> = app
        .settings()
        .iter()
        .enumerate()
        .map(|(i, row)| {
            let selected = i == app.cursor;
            let base = if selected {
                Style::default().fg(ACCENT).bold()
            } else {
                Style::default()
            };
            match row {
                SettingsRow::DirectCleanup(on) => Row::new(vec![
                    Cell::from(if *on { "●" } else { "○" }),
                    Cell::from("Actually free the space"),
                    Cell::from(if *on { "on" } else { "off" })
                        .style(Style::default().fg(if *on { WARN } else { MUTED })),
                ])
                .style(base),
                SettingsRow::ThresholdGb(gb) => Row::new(vec![
                    Cell::from(" "),
                    Cell::from("  Run unattended below"),
                    Cell::from(format!("{gb} GB")).style(Style::default().fg(ACCENT)),
                ])
                .style(base),
                SettingsRow::CooldownSec(secs) => Row::new(vec![
                    Cell::from(" "),
                    Cell::from("  At most one run every"),
                    Cell::from(format!("{secs} s")).style(Style::default().fg(ACCENT)),
                ])
                .style(base),
                SettingsRow::Exclusion { pattern, source } => Row::new(vec![
                    Cell::from(" "),
                    Cell::from(format!("  keep {pattern}")),
                    Cell::from(*source).style(Style::default().fg(MUTED)),
                ])
                .style(base),
            }
        })
        .collect();

    f.render_widget(
        Table::new(
            rows,
            [
                Constraint::Length(2),
                Constraint::Min(30),
                Constraint::Length(10),
            ],
        )
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(Span::styled(" Settings ", Style::default().fg(ACCENT).bold())),
        ),
        split[0],
    );

    let detail = match app.settings().get(app.cursor) {
        Some(SettingsRow::DirectCleanup(true)) => vec![
            Line::from("A cleanup frees what it reports. Regenerable caches are deleted outright and the Trash is emptied afterwards."),
            Line::from(Span::styled("None of it can be recovered. Anything next to your own files still goes to the Trash.", Style::default().fg(WARN))),
        ],
        Some(SettingsRow::DirectCleanup(false)) => vec![
            Line::from("Everything eve removes goes to the Trash, and eve never empties it — so nothing it does is irreversible."),
            Line::from(Span::styled("Nothing is actually freed until you empty the Trash yourself.", Style::default().fg(MUTED))),
        ],
        Some(SettingsRow::ThresholdGb(gb)) => vec![
            Line::from(format!("The unattended run fires when free space drops below {gb} GB.")),
            Line::from(Span::styled("Press space to type a new number.", Style::default().fg(MUTED))),
        ],
        Some(SettingsRow::CooldownSec(secs)) => vec![
            Line::from(format!("At most one real unattended run every {secs} seconds ({} h).", secs / 3600)),
            Line::from(Span::styled("Stops a persistent problem re-firing every poll. Press space to type a new number.", Style::default().fg(MUTED))),
        ],
        Some(SettingsRow::Exclusion { pattern, source }) => vec![
            Line::from(format!("Trash entries matching {pattern} are left where they are.")),
            Line::from(Span::styled(
                format!("{source} — press d to remove it. If a sweep then finds it really cannot be deleted, eve adds it back."),
                Style::default().fg(MUTED),
            )),
        ],
        None => vec![Line::from("")],
    };

    f.render_widget(
        Paragraph::new(detail)
            .block(Block::default().borders(Borders::ALL).title(" Detail "))
            .wrap(ratatui::widgets::Wrap { trim: true }),
        split[1],
    );
}

fn draw_status(f: &mut Frame, area: Rect, app: &App) {
    let Some(s) = &app.status else {
        f.render_widget(
            Paragraph::new("\n  Collecting…").block(Block::default().borders(Borders::ALL)),
            area,
        );
        return;
    };

    let split =
        Layout::vertical([Constraint::Length(7), Constraint::Min(4), Constraint::Min(4)]).split(area);

    let mem_pct = if s.mem_total > 0 {
        (s.mem_used as f64 / s.mem_total as f64 * 100.0) as u16
    } else {
        0
    };
    let inner = Layout::vertical([Constraint::Length(1); 5]).split(
        Block::default()
            .borders(Borders::ALL)
            .title(format!(" {} · {} ", s.host, s.os))
            .inner(split[0]),
    );
    f.render_widget(
        Block::default()
            .borders(Borders::ALL)
            .title(format!(" {} · {} ", s.host, s.os)),
        split[0],
    );
    f.render_widget(
        Gauge::default()
            .label(format!("CPU {:.0}%", s.cpu_usage))
            .ratio((s.cpu_usage as f64 / 100.0).clamp(0.0, 1.0))
            .gauge_style(Style::default().fg(ACCENT)),
        inner[0],
    );
    f.render_widget(
        Gauge::default()
            .label(format!(
                "Memory {} / {}",
                human_bytes(s.mem_used),
                human_bytes(s.mem_total)
            ))
            .percent(mem_pct.min(100))
            .gauge_style(Style::default().fg(if mem_pct > 90 { WARN } else { ACCENT })),
        inner[1],
    );
    f.render_widget(
        Paragraph::new(format!(
            "load {:.2} {:.2} {:.2} · {} cores · up {}h",
            s.load[0],
            s.load[1],
            s.load[2],
            s.cpu_count,
            s.uptime_secs / 3600
        ))
        .style(Style::default().fg(MUTED)),
        inner[3],
    );

    let vols: Vec<ListItem> = s
        .volumes
        .iter()
        .map(|v| {
            let colour = if v.available < 5 * 1024 * 1024 * 1024 {
                BAD
            } else if v.available < 15 * 1024 * 1024 * 1024 {
                WARN
            } else {
                GOOD
            };
            ListItem::new(Line::from(vec![
                Span::raw(format!("{:<26}", v.mount.display())),
                Span::styled(format!("{:>10} free", human_bytes(v.available)), Style::default().fg(colour)),
                Span::styled(format!("  {:.0}% used", v.used_pct()), Style::default().fg(MUTED)),
            ]))
        })
        .collect();
    f.render_widget(
        List::new(vols).block(Block::default().borders(Borders::ALL).title(" Volumes ")),
        split[1],
    );

    let findings: Vec<ListItem> = s
        .health
        .iter()
        .map(|h| {
            let (mark, colour) = match h.level {
                Level::Ok => ("✓", GOOD),
                Level::Warn => ("⚠", WARN),
                Level::Critical => ("✗", BAD),
            };
            ListItem::new(Line::from(vec![
                Span::styled(format!("{mark} "), Style::default().fg(colour)),
                Span::raw(format!("{:<22}", h.subject)),
                Span::styled(h.detail.clone(), Style::default().fg(MUTED)),
            ]))
        })
        .collect();
    f.render_widget(
        List::new(findings).block(Block::default().borders(Borders::ALL).title(" Health ")),
        split[2],
    );
}

fn draw_history(f: &mut Frame, area: Rect, app: &App) {
    let rows: Vec<Row> = app
        .history
        .iter()
        .rev()
        .take(500)
        .map(|e| {
            let (mark, colour) = match (&e.error, e.dry_run) {
                (Some(_), _) => ("✗", BAD),
                (None, true) => ("·", MUTED),
                (None, false) => ("✓", GOOD),
            };
            Row::new(vec![
                Cell::from(mark).style(Style::default().fg(colour)),
                Cell::from(e.timestamp()).style(Style::default().fg(MUTED)),
                Cell::from(human_bytes(e.bytes)).style(Style::default().fg(GOOD)),
                Cell::from(e.category.clone()),
                Cell::from(e.path.display().to_string()).style(Style::default().fg(MUTED)),
            ])
        })
        .collect();

    let total: u64 = app
        .history
        .iter()
        .filter(|e| !e.dry_run && e.error.is_none())
        .map(|e| e.bytes)
        .sum();

    f.render_widget(
        Table::new(
            rows,
            [
                Constraint::Length(2),
                Constraint::Length(20),
                Constraint::Length(11),
                Constraint::Length(20),
                Constraint::Min(20),
            ],
        )
        .block(Block::default().borders(Borders::ALL).title(Span::styled(
            format!(" Reclaimed to date: {} ", human_bytes(total)),
            Style::default().fg(GOOD).bold(),
        ))),
        area,
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The one question comes first, and an older file with only the Trash
    /// half set still reads as on — a switch that says off while eve empties
    /// the Trash would be a lie.
    #[test]
    fn the_first_settings_row_is_the_one_question() {
        let prefs = Preferences {
            empty_trash: true,
            ..Preferences::default()
        };
        assert_eq!(settings_rows(&prefs)[0], SettingsRow::DirectCleanup(true));
        assert_eq!(
            settings_rows(&Preferences::default())[0],
            SettingsRow::DirectCleanup(false)
        );
    }

    /// Every exclusion can be removed, including the ones eve put there.
    ///
    /// This is the inverse of the rule it replaced. The seeded entries used to
    /// be permanent, which made the one list in eve the user could not fully
    /// control — and eve's own guess about what macOS refuses is not good
    /// enough to justify that.
    #[test]
    fn every_exclusion_can_be_removed() {
        let mut prefs = Preferences::default();
        prefs.seed_trash_exclusions();
        prefs.exclude_trash("mine*").unwrap();

        let rows = settings_rows(&prefs);
        let patterns: Vec<&str> = rows
            .iter()
            .filter_map(|r| match r {
                SettingsRow::Exclusion { pattern, .. } => Some(pattern.as_str()),
                _ => None,
            })
            .collect();
        assert!(patterns.contains(&"mine*"));
        assert!(
            patterns
                .iter()
                .any(|p| p.starts_with("com.apple.siriactionsd")),
            "the seeded entries should be listed: {patterns:?}"
        );

        // The row carries where it came from, and nothing else. There is no
        // longer a flag `remove_setting` can consult to refuse.
        assert!(rows.iter().any(|r| matches!(
            r,
            SettingsRow::Exclusion { source, .. } if *source == "suggested by eve"
        )));
        assert!(rows.iter().any(|r| matches!(
            r,
            SettingsRow::Exclusion { source, .. } if *source == "yours"
        )));
    }

    /// The exclusions are the tail, so adding a setting never renumbers them
    /// and `remove_setting` cannot end up deleting the wrong one.
    #[test]
    fn the_settings_come_first_and_the_exclusions_are_the_tail() {
        let mut prefs = Preferences::default();
        prefs.exclude_trash("a*").unwrap();
        let rows = settings_rows(&prefs);

        let first_exclusion = rows
            .iter()
            .position(|r| matches!(r, SettingsRow::Exclusion { .. }))
            .expect("no exclusions rendered");

        assert!(
            rows[..first_exclusion]
                .iter()
                .all(|r| !matches!(r, SettingsRow::Exclusion { .. })),
            "a setting appeared after the exclusions began"
        );
        assert_eq!(
            rows.len() - first_exclusion,
            prefs.effective_trash_exclusions().len(),
            "every exclusion should be reachable"
        );
    }

    #[test]
    fn the_schedule_is_shown_and_therefore_editable() {
        let prefs = Preferences::default();
        let rows = settings_rows(&prefs);
        assert!(rows.contains(&SettingsRow::ThresholdGb(5)));
        assert!(rows.contains(&SettingsRow::CooldownSec(10800)));
        assert!(rows.contains(&SettingsRow::DirectCleanup(false)));
    }
}
