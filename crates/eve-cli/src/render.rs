//! Terminal output.

use std::io::IsTerminal;

use eve_core::size::human_bytes;
use eve_engines::clean::{CategoryResult, CleanReport};

pub struct Style {
    color: bool,
}

impl Style {
    pub fn detect() -> Self {
        // NO_COLOR is a de-facto standard and cheap to honour.
        let disabled = std::env::var_os("NO_COLOR").is_some();
        Style {
            color: std::io::stdout().is_terminal() && !disabled,
        }
    }

    pub fn plain() -> Self {
        Style { color: false }
    }

    fn wrap(&self, code: &str, s: &str) -> String {
        if self.color {
            format!("\x1b[{code}m{s}\x1b[0m")
        } else {
            s.to_string()
        }
    }

    pub fn bold(&self, s: &str) -> String {
        self.wrap("1", s)
    }
    pub fn dim(&self, s: &str) -> String {
        self.wrap("2", s)
    }
    pub fn green(&self, s: &str) -> String {
        self.wrap("32", s)
    }
    pub fn yellow(&self, s: &str) -> String {
        self.wrap("33", s)
    }
    pub fn red(&self, s: &str) -> String {
        self.wrap("31", s)
    }
    pub fn cyan(&self, s: &str) -> String {
        self.wrap("36", s)
    }
}

/// An OSC 8 terminal hyperlink.
///
/// Cmd-click opens the URI via the system handler in iTerm2, Kitty, WezTerm,
/// Ghostty and Terminal.app. This is how the SIP-safe Settings routes become
/// clickable rather than something to copy by hand.
pub fn osc8(uri: &str, text: &str) -> String {
    format!("\x1b]8;;{uri}\x07{text}\x1b]8;;\x07")
}

pub fn print_report(report: &CleanReport, style: &Style, verbose: bool) {
    println!();
    if report.dry_run {
        println!(
            "{}",
            style.bold(&style.cyan("Preview — nothing will be deleted"))
        );
    } else {
        println!("{}", style.bold("Cleaning"));
    }

    if let Some(free) = report.free_before {
        println!("{}", style.dim(&format!("  {} free", human_bytes(free))));
    }
    println!();

    for (group, cats) in report.by_group() {
        let visible: Vec<&&CategoryResult> =
            cats.iter().filter(|c| verbose || !c.is_empty()).collect();
        if visible.is_empty() {
            continue;
        }

        println!("{}", style.bold(group.title()));
        for cat in visible {
            print_category(cat, style, verbose);
        }
        println!();
    }

    print_summary(report, style);
}

fn print_category(cat: &CategoryResult, style: &Style, verbose: bool) {
    let bytes = cat.bytes();
    let items = cat.items();

    if bytes > 0 {
        println!(
            "  {} {} {}",
            style.green("→"),
            cat.title,
            style.dim(&format!("{} · {} items", human_bytes(bytes), items))
        );
    } else if !cat.commands.is_empty() {
        for c in &cat.commands {
            let state = match (c.ran, c.ok, &c.detail) {
                (false, _, Some(d)) => style.dim(d),
                (false, _, None) => style.dim("would run"),
                (true, true, _) => style.green("done"),
                (true, false, Some(d)) => style.yellow(d),
                (true, false, None) => style.yellow("failed"),
            };
            println!("  {} {} {}", style.cyan("$"), c.note, state);
        }
    } else if verbose {
        println!("  {} {} {}", style.dim("·"), cat.title, style.dim("nothing"));
    }

    // Refusals are the interesting part of a cleaner's output: they are where
    // it declined to do damage.
    for denial in cat.notable_denials() {
        println!("  {} {}", style.yellow("⊘"), style.dim(&denial.to_string()));
    }
}

fn print_summary(report: &CleanReport, style: &Style) {
    let total = report.total_bytes();
    let line = "─".repeat(56);
    println!("{}", style.dim(&line));

    if report.dry_run {
        println!(
            "  {} {} across {} items",
            style.bold("Reclaimable:"),
            style.bold(&style.green(&human_bytes(total))),
            report.total_items()
        );
        println!("  {}", style.dim("Run with --execute to apply."));
    } else {
        println!(
            "  {} {}",
            style.bold("Reclaimed:"),
            style.bold(&style.green(&human_bytes(total)))
        );
        if let (Some(before), Some(after)) = (report.free_before, report.free_after) {
            println!(
                "  {}",
                style.dim(&format!(
                    "{} free → {} free",
                    human_bytes(before),
                    human_bytes(after)
                ))
            );
            // The number that matters is the delta on the volume, not the sum
            // of what we measured. APFS purgeable space and still-open file
            // handles routinely make the two disagree.
            if after <= before && total > 0 {
                println!(
                    "  {}",
                    style.dim(
                        "Free space did not rise by the full amount — APFS may still be \
                         releasing purgeable space. A reboot settles it."
                    )
                );
            }
        }
    }

    if !report.privileged_available && report.categories.iter().any(|c| c.needs_root) {
        println!(
            "  {}",
            style.yellow("Some categories need root — re-run with --privileged.")
        );
    }
    println!("{}", style.dim(&line));
}

/// The SIP-safe routes for evicting system assets.
pub fn print_settings_hints(style: &Style) {
    println!();
    println!("{}", style.bold("SIP-safe ways to reclaim system assets"));
    println!(
        "{}",
        style.dim("SIP blocks deleting these directly. These panes make macOS evict them itself.")
    );
    println!();
    for (label, nav, uri) in eve_catalog::SETTINGS_HINTS {
        println!("  {} {}", style.green("•"), style.bold(label));
        println!("    {}", style.dim(nav));
        println!("    {}", osc8(uri, &style.cyan("open this pane")));
    }
    println!();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_style_emits_no_escape_codes() {
        let s = Style::plain();
        assert_eq!(s.bold("x"), "x");
        assert_eq!(s.green("x"), "x");
        assert!(!s.red("danger").contains('\x1b'));
    }

    #[test]
    fn osc8_wraps_the_uri_and_text() {
        let link = osc8("https://example.com", "click");
        assert!(link.contains("https://example.com"));
        assert!(link.contains("click"));
        assert!(link.starts_with('\x1b'));
    }
}
