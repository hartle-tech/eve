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
}

impl Tab {
    const ALL: [Tab; 3] = [Tab::Clean, Tab::Status, Tab::History];
    fn title(self) -> &'static str {
        match self {
            Tab::Clean => "Clean",
            Tab::Status => "Status",
            Tab::History => "History",
        }
    }
    fn index(self) -> usize {
        Tab::ALL.iter().position(|t| *t == self).unwrap_or(0)
    }
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
}

impl App {
    fn new() -> Self {
        App {
            tab: Tab::Clean,
            cursor: 0,
            report: None,
            disabled: Vec::new(),
            privileged: false,
            status: None,
            history: Vec::new(),
            message: None,
            scanning: false,
            armed: false,
            quit: false,
        }
    }

    fn selection(&self) -> Selection {
        Selection {
            skip: self.disabled.clone(),
            allow_privileged: self.privileged,
            ..Default::default()
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
        let cleaner = Cleaner::new(&policy, &liveness);
        let catalog = eve_catalog::catalog();
        self.report = Some(cleaner.scan(&catalog, &self.selection()));
        self.cursor = 0;
        self.scanning = false;
    }

    fn execute(&mut self) {
        let policy = Policy::current().with_default_whitelist();
        let liveness = Liveness::snapshot();
        let journal = Journal::open_default().ok();
        let mut cleaner = Cleaner::new(&policy, &liveness);
        if let Some(j) = &journal {
            cleaner = cleaner.with_journal(j);
        }
        let catalog = eve_catalog::catalog();

        let mut broker = self.privileged.then(SudoWorker::interactive);
        let report = match broker.as_mut() {
            Some(b) => cleaner.execute(&catalog, &self.selection(), Some(b)),
            None => cleaner.execute(&catalog, &self.selection(), None),
        };

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
    }

    let help = match app.tab {
        Tab::Clean => " ↑↓ move · space skip · p root · enter clean (twice) · r rescan · q quit ",
        Tab::Status => " ↑↓ move · tab switch · q quit ",
        Tab::History => " ↑↓ move · tab switch · q quit ",
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
