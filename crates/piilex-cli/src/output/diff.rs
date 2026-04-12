use console::style;
use piilex_core::baseline::{ChangeKind, DiffResult};
use piilex_core::severity::Severity;

pub fn print_diff(diff: &DiffResult) {
    let summary = &diff.summary;

    eprintln!();
    eprintln!(
        "  {} (baseline: {} → current: {})",
        style("Diff Scan Results").bold(),
        summary.total_baseline,
        summary.total_current,
    );
    eprintln!();

    // Filter out unchanged for display (show only changes)
    let changes: Vec<_> = diff
        .entries
        .iter()
        .filter(|e| e.change != ChangeKind::Unchanged)
        .collect();

    if changes.is_empty() {
        eprintln!("  {} No changes from baseline.", style("✓").green().bold());
        eprintln!();
        print_diff_summary(diff);
        return;
    }

    // Header
    eprintln!(
        "  {:<8} {:<10} {:<16} {:<36} {:<6} {}",
        style("CHANGE").underlined(),
        style("SEVERITY").underlined(),
        style("TYPE").underlined(),
        style("FILE").underlined(),
        style("LINE").underlined(),
        style("DETAILS").underlined(),
    );
    eprintln!("  {}", style("─".repeat(105)).dim());

    for entry in &changes {
        let change_styled = match entry.change {
            ChangeKind::Added => style(format!("{:<8}", "+ADD")).green().bold(),
            ChangeKind::Removed => style(format!("{:<8}", "-DEL")).red().bold(),
            ChangeKind::Modified => style(format!("{:<8}", "~MOD")).yellow().bold(),
            ChangeKind::Unchanged => style(format!("{:<8}", "=")).dim(),
        };

        let severity_styled = match entry.finding.severity {
            Severity::Critical => style(format!("{:<10}", "critical")).red().bold(),
            Severity::High => style(format!("{:<10}", "high")).yellow().bold(),
            Severity::Medium => style(format!("{:<10}", "medium")).yellow(),
            Severity::Low => style(format!("{:<10}", "low")).dim(),
        };

        let file_display = entry.finding.location.file.display().to_string();
        let file_truncated = if file_display.len() > 34 {
            format!("…{}", &file_display[file_display.len() - 33..])
        } else {
            file_display
        };

        let details = if entry.changes.is_empty() {
            match entry.change {
                ChangeKind::Added => "new finding".to_string(),
                ChangeKind::Removed => "finding resolved".to_string(),
                _ => String::new(),
            }
        } else {
            entry
                .changes
                .iter()
                .map(|c| format!("{}: {} → {}", c.field, c.old_value, c.new_value))
                .collect::<Vec<_>>()
                .join(", ")
        };

        eprintln!(
            "  {} {} {:<16} {:<36} {:<6} {}",
            change_styled,
            severity_styled,
            entry.finding.pii_type.as_str(),
            file_truncated,
            entry.finding.location.line,
            style(details).dim(),
        );
    }

    eprintln!();
    print_diff_summary(diff);
}

pub fn print_diff_summary(diff: &DiffResult) {
    let s = &diff.summary;
    eprintln!("  {}", style("Diff Summary:").bold());
    eprintln!(
        "    {}: {}  {}: {}  {}: {}  {}: {}",
        style("+added").green(),
        s.added,
        style("-removed").red(),
        s.removed,
        style("~modified").yellow(),
        s.modified,
        style("=unchanged").dim(),
        s.unchanged,
    );
    eprintln!();
}

pub fn print_diff_json(diff: &DiffResult) -> anyhow::Result<()> {
    let json = serde_json::to_string_pretty(diff)?;
    println!("{}", json);
    Ok(())
}
