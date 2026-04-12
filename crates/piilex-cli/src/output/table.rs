use console::style;
use piilex_core::finding::FindingSet;
use piilex_core::severity::Severity;

pub fn print_findings(finding_set: &FindingSet) {
    let meta = &finding_set.metadata;
    let findings = &finding_set.findings;

    // Header
    eprintln!();
    eprintln!(
        "  {} {} finding(s) in {} file(s) ({:.1}s)",
        style("PII Scan Results —").bold(),
        findings.len(),
        meta.files_scanned,
        meta.duration.as_secs_f64(),
    );
    eprintln!();

    if findings.is_empty() {
        eprintln!("  {} No PII findings detected.", style("✓").green().bold());
        eprintln!();
        return;
    }

    // Column headers
    eprintln!(
        "  {:<10} {:<16} {:<40} {:<6} {}",
        style("SEVERITY").underlined(),
        style("TYPE").underlined(),
        style("FILE").underlined(),
        style("LINE").underlined(),
        style("DATA FLOW").underlined(),
    );
    eprintln!("  {}", style("─".repeat(100)).dim());

    for finding in findings {
        let severity_styled = match finding.severity {
            Severity::Critical => style(format!("{:<10}", "critical")).red().bold(),
            Severity::High => style(format!("{:<10}", "high")).yellow().bold(),
            Severity::Medium => style(format!("{:<10}", "medium")).yellow(),
            Severity::Low => style(format!("{:<10}", "low")).dim(),
        };

        let flow_info = finding
            .data_flow
            .as_ref()
            .map(|df| format!("{} → {}", df.source.kind.as_str(), df.sink.kind.as_str()))
            .unwrap_or_else(|| "—".to_string());

        let file_display = finding.location.file.display().to_string();
        let file_truncated = if file_display.len() > 38 {
            format!("…{}", &file_display[file_display.len() - 37..])
        } else {
            file_display
        };

        let framework_info = if finding.framework_mappings.is_empty() {
            String::new()
        } else {
            let articles: Vec<String> = finding
                .framework_mappings
                .iter()
                .map(|m| m.article.clone())
                .collect();
            format!(" [{}]", articles.join(", "))
        };

        eprintln!(
            "  {} {:<16} {:<40} {:<6} {}{}",
            severity_styled,
            finding.pii_type.as_str(),
            file_truncated,
            finding.location.line,
            flow_info,
            style(framework_info).dim(),
        );
    }

    eprintln!();
    print_summary(finding_set);
}

pub fn print_summary(finding_set: &FindingSet) {
    let findings = &finding_set.findings;

    let critical = findings
        .iter()
        .filter(|f| f.severity == Severity::Critical)
        .count();
    let high = findings
        .iter()
        .filter(|f| f.severity == Severity::High)
        .count();
    let medium = findings
        .iter()
        .filter(|f| f.severity == Severity::Medium)
        .count();
    let low = findings
        .iter()
        .filter(|f| f.severity == Severity::Low)
        .count();

    eprintln!("  {}", style("Summary:").bold());
    eprintln!(
        "    {}: {}  {}: {}  {}: {}  {}: {}",
        style("critical").red(),
        critical,
        style("high").yellow(),
        high,
        style("medium").yellow(),
        medium,
        style("low").dim(),
        low,
    );

    if !finding_set.metadata.frameworks.is_empty() {
        let fw_names: Vec<String> = finding_set
            .metadata
            .frameworks
            .iter()
            .map(|f| f.as_str().to_uppercase())
            .collect();
        eprintln!("    Frameworks: {}", fw_names.join(", "));
    }

    eprintln!();
}
