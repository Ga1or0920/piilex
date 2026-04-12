use anyhow::{Context, Result};
use clap::Args;
use console::style;
use std::path::PathBuf;
use std::time::Instant;

use piilex_core::config::Config;
use piilex_core::detector::DetectorPipeline;
use piilex_core::discovery::{detect_language, FileDiscovery};
use piilex_core::finding::{FindingSet, Framework, ScanMetadata};
use piilex_core::parser::{parse_file, ParsedFile};
use piilex_core::severity::Severity;
use piilex_license::{require_pro, resolve_license, ProFeature};

use crate::output;

#[derive(Args)]
pub struct ScanArgs {
    /// Path to scan (directory or file) [default: current directory]
    #[arg(default_value = ".")]
    pub path: PathBuf,

    /// Regulatory framework for article mapping [Pro]
    #[arg(
        short,
        long,
        value_delimiter = ',',
        value_name = "FRAMEWORK",
        help = "Regulatory framework (gdpr, ccpa). Comma-separated for multiple [Pro]"
    )]
    pub framework: Vec<String>,

    /// Output format: table (human), json (machine), sarif (GitHub)
    #[arg(short, long, default_value = "table", value_name = "FORMAT")]
    pub output: OutputFormat,

    /// Minimum severity to include in results
    #[arg(
        long,
        default_value = "low",
        value_name = "LEVEL",
        help = "Minimum severity to display (low, medium, high, critical)"
    )]
    pub severity: String,

    /// Glob patterns to exclude from scan
    #[arg(
        long,
        value_name = "PATTERN",
        help = "Exclude glob pattern (repeatable). Example: --exclude '**/*.test.ts'"
    )]
    pub exclude: Vec<String>,

    /// Fail with exit code 1 if findings at this severity or above
    #[arg(
        long,
        value_name = "LEVEL",
        help = "CI gate: exit 1 if findings >= LEVEL (low, medium, high, critical)"
    )]
    pub fail_on: Option<String>,

    /// Skip cross-file data flow analysis for faster scanning
    #[arg(
        long,
        help = "Disable cross-file import/export tracking (faster, less thorough)"
    )]
    pub no_flow: bool,

    /// Path to .piilex.yml configuration file
    #[arg(long, default_value = ".piilex.yml", value_name = "PATH")]
    pub config: PathBuf,

    /// Show only the summary line (no finding table)
    #[arg(short, long)]
    pub quiet: bool,

    /// Compare against a previous scan baseline [Pro]
    #[arg(
        long,
        value_name = "FILE",
        help = "Path to baseline JSON for diff scanning (shows added/removed/modified) [Pro]"
    )]
    pub baseline: Option<PathBuf>,

    /// Save current scan results as a new baseline
    #[arg(
        long,
        value_name = "FILE",
        help = "Save scan results as baseline JSON for future diff comparisons"
    )]
    pub save_baseline: Option<PathBuf>,
}

#[derive(Clone, Debug, clap::ValueEnum)]
pub enum OutputFormat {
    Table,
    Json,
    Sarif,
}

pub fn execute(args: ScanArgs) -> Result<()> {
    let start = Instant::now();

    // Resolve license
    let license = resolve_license(None);

    // Load config
    let mut config = Config::load(&args.config).unwrap_or_else(|e| {
        eprintln!("{} {}", style("Warning:").yellow(), e);
        Config::default()
    });

    // Merge CLI args into config
    for fw_str in &args.framework {
        if let Ok(fw) = fw_str.parse::<Framework>() {
            if !config.frameworks.contains(&fw) {
                config.frameworks.push(fw);
            }
        } else {
            eprintln!(
                "{} Unknown framework: '{}' (expected: gdpr, ccpa)",
                style("Warning:").yellow(),
                fw_str
            );
        }
    }

    // Gate: --framework requires Pro
    if !config.frameworks.is_empty() {
        if let Err(e) = require_pro(&license, ProFeature::FrameworkMapping) {
            eprintln!("{} {}", style("Pro required:").red().bold(), e);
            std::process::exit(1);
        }
    }

    // Gate: --baseline requires Pro
    if args.baseline.is_some() {
        if let Err(e) = require_pro(&license, ProFeature::BaselineDiff) {
            eprintln!("{} {}", style("Pro required:").red().bold(), e);
            std::process::exit(1);
        }
    }

    for excl in &args.exclude {
        config.scan.exclude.push(excl.clone());
    }

    // Discover files
    let scan_path = args
        .path
        .canonicalize()
        .unwrap_or_else(|_| args.path.clone());

    let discovery =
        FileDiscovery::new(&config.scan).context("Failed to initialize file discovery")?;
    let result = discovery.discover(&scan_path);

    if result.files.is_empty() {
        if !args.quiet {
            eprintln!(
                "{} No supported files found in {}",
                style("Warning:").yellow(),
                scan_path.display()
            );
        }
        return Ok(());
    }

    // ─── Phase 1: Parse all files ───────────────────────────────────
    let file_count = result.files.len();
    let use_progress = file_count >= 20 && !args.quiet && console::Term::stderr().is_term();

    let progress = if use_progress {
        let pb = indicatif::ProgressBar::new(file_count as u64);
        pb.set_style(
            indicatif::ProgressStyle::with_template(
                "  {spinner:.cyan} Parsing [{bar:30.cyan/dim}] {pos}/{len} files ({eta})",
            )
            .unwrap()
            .progress_chars("##-"),
        );
        pb.enable_steady_tick(std::time::Duration::from_millis(120));
        Some(pb)
    } else {
        None
    };

    let mut parsed_files: Vec<ParsedFile> = Vec::new();
    let mut parse_skipped = 0;
    let mut all_warnings = Vec::new();

    for file_path in &result.files {
        if let Some(ref pb) = progress {
            let name = file_path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("?");
            pb.set_message(name.to_string());
        }

        let source = match std::fs::read_to_string(file_path) {
            Ok(s) => s,
            Err(e) => {
                all_warnings.push(format!("{}: failed to read: {}", file_path.display(), e));
                parse_skipped += 1;
                if let Some(ref pb) = progress {
                    pb.inc(1);
                }
                continue;
            }
        };

        let language = match detect_language(file_path) {
            Some(l) => l,
            None => {
                if let Some(ref pb) = progress {
                    pb.inc(1);
                }
                continue;
            }
        };

        let parsed = parse_file(file_path, &source, language);

        // Collect parse warnings
        for w in &parsed.warnings {
            all_warnings.push(format!("{}", w));
        }

        parsed_files.push(parsed);

        if let Some(ref pb) = progress {
            pb.inc(1);
        }
    }

    if let Some(pb) = progress {
        pb.finish_and_clear();
    }

    // Display parse warnings (after progress bar is cleared)
    if !all_warnings.is_empty() && !args.quiet {
        let shown = all_warnings.len().min(10);
        eprintln!(
            "\n  {} {} parse warning(s):",
            style("!").yellow().bold(),
            all_warnings.len()
        );
        for w in all_warnings.iter().take(shown) {
            eprintln!("    {}", style(w).yellow());
        }
        if all_warnings.len() > shown {
            eprintln!(
                "    {} ... and {} more",
                style("").dim(),
                all_warnings.len() - shown
            );
        }
        eprintln!();
    }

    // ─── Phase 2: Analyze (intra-file + cross-file) ─────────────────
    let pipeline = DetectorPipeline::with_config(&config);

    let is_multi_file = parsed_files.len() > 1 && !args.no_flow;

    let mut all_findings = if is_multi_file {
        pipeline.analyze_project(&parsed_files, &config, &scan_path)
    } else {
        // Single file or --no-flow: skip cross-file analysis
        let mut findings = Vec::new();
        for file in &parsed_files {
            findings.extend(pipeline.analyze(file, &config));
        }
        findings
    };

    let duration = start.elapsed();

    // Make paths relative for display
    for finding in &mut all_findings {
        if let Ok(rel) = finding.location.file.strip_prefix(&scan_path) {
            finding.location.file = rel.to_path_buf();
        }
        // Also relativize data flow paths
        if let Some(ref mut df) = finding.data_flow {
            if let Ok(rel) = df.source.location.file.strip_prefix(&scan_path) {
                df.source.location.file = rel.to_path_buf();
            }
            if let Ok(rel) = df.sink.location.file.strip_prefix(&scan_path) {
                df.sink.location.file = rel.to_path_buf();
            }
            for loc in &mut df.path {
                if let Ok(rel) = loc.file.strip_prefix(&scan_path) {
                    loc.file = rel.to_path_buf();
                }
            }
        }
    }

    // Apply severity filter
    let min_severity: Severity = args.severity.parse().unwrap_or(Severity::Low);
    all_findings.retain(|f| f.severity >= min_severity);

    // Sort by severity (descending), then file, then line
    all_findings.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then(a.location.file.cmp(&b.location.file))
            .then(a.location.line.cmp(&b.location.line))
    });

    // Build FindingSet
    let finding_set = FindingSet {
        findings: all_findings,
        metadata: ScanMetadata {
            path: scan_path.clone(),
            files_scanned: parsed_files.len(),
            files_skipped: result.skipped + parse_skipped,
            duration,
            frameworks: config.frameworks.clone(),
            tool_version: env!("CARGO_PKG_VERSION").to_string(),
        },
    };

    // ─── Telemetry ───────────────────────────────────────────────────
    {
        use std::collections::HashMap;
        let mut pii_counts: HashMap<String, usize> = HashMap::new();
        let mut lang_counts: HashMap<String, usize> = HashMap::new();
        for f in &finding_set.findings {
            *pii_counts
                .entry(f.pii_type.as_str().to_string())
                .or_default() += 1;
        }
        for pf in &parsed_files {
            *lang_counts
                .entry(pf.language.as_str().to_string())
                .or_default() += 1;
        }
        let fw_names: Vec<String> = config
            .frameworks
            .iter()
            .map(|f| f.as_str().to_string())
            .collect();
        piilex_core::telemetry::record_scan_event(&piilex_core::telemetry::ScanEventParams {
            files_scanned: parsed_files.len(),
            findings_count: finding_set.findings.len(),
            pii_type_counts: &pii_counts,
            language_counts: &lang_counts,
            duration_ms: duration.as_millis() as u64,
            frameworks: &fw_names,
            used_baseline: args.baseline.is_some(),
            used_crossfile: is_multi_file,
        });
    }

    // ─── Save baseline if requested ─────────────────────────────────
    if let Some(ref save_path) = args.save_baseline {
        piilex_core::baseline::save_baseline(&finding_set, save_path).context(format!(
            "Failed to save baseline to {}",
            save_path.display()
        ))?;
        eprintln!(
            "{} Baseline saved to {}",
            style("✓").green().bold(),
            save_path.display()
        );
    }

    // ─── Baseline diff mode ─────────────────────────────────────────
    if let Some(ref baseline_path) = args.baseline {
        let baseline = piilex_core::baseline::load_baseline(baseline_path).context(format!(
            "Failed to load baseline from {}",
            baseline_path.display()
        ))?;

        let diff = piilex_core::baseline::compute_diff(&baseline, &finding_set);

        match args.output {
            OutputFormat::Table => {
                if args.quiet {
                    output::diff::print_diff_summary(&diff);
                } else {
                    output::diff::print_diff(&diff);
                }
            }
            OutputFormat::Json => {
                output::diff::print_diff_json(&diff)?;
            }
            OutputFormat::Sarif => {
                // SARIF doesn't have a native diff format; output current findings
                output::sarif::print_findings(&finding_set)?;
            }
        }

        // In diff mode, exit code 1 if there are new findings at fail_on level
        if let Some(ref fail_on_str) = args.fail_on {
            let fail_severity: Severity = fail_on_str.parse().unwrap_or(Severity::High);
            let has_new_critical = diff.entries.iter().any(|e| {
                e.change == piilex_core::baseline::ChangeKind::Added
                    && e.finding.severity >= fail_severity
            });
            if has_new_critical {
                std::process::exit(1);
            }
        }

        return Ok(());
    }

    // ─── Normal output (no baseline) ────────────────────────────────
    match args.output {
        OutputFormat::Table => {
            if args.quiet {
                output::table::print_summary(&finding_set);
            } else {
                output::table::print_findings(&finding_set);
            }
        }
        OutputFormat::Json => {
            output::json::print_findings(&finding_set)?;
        }
        OutputFormat::Sarif => {
            output::sarif::print_findings(&finding_set)?;
        }
    }

    // Determine exit code
    if let Some(fail_on_str) = &args.fail_on {
        let fail_severity: Severity = fail_on_str.parse().unwrap_or(Severity::High);
        if finding_set
            .findings
            .iter()
            .any(|f| f.severity >= fail_severity)
        {
            std::process::exit(1);
        }
    }

    Ok(())
}
