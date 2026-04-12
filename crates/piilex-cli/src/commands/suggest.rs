use anyhow::{Context, Result};
use clap::Args;
use console::style;
use std::io::Write;
use std::path::PathBuf;

use piilex_core::finding::FindingSet;
use piilex_core::suggest::{
    apply_suggestion, generate_suggestion, generate_suggestion_from_snippet, SuggestContext,
    Suggestion,
};
use piilex_license::{check_suggest_limit, record_suggest_usage, resolve_license};

#[derive(Args)]
#[command(
    long_about = "Generate concrete code fix suggestions for PII findings.\n\n\
                  Reads the source files to produce real unified diffs showing\n\
                  exactly which line to change and what to replace it with.\n\n\
                  Free tier: 3 suggestions per day. Pro: unlimited.",
    after_long_help = "\
EXAMPLES:
  Show suggestions for all findings:
    piilex suggest -i scan.json

  Single finding:
    piilex suggest -i scan.json --finding PII-001

  Auto-fix with confirmation:
    piilex suggest -i scan.json --auto-fix

  JSON output:
    piilex suggest -i scan.json -o json"
)]
pub struct SuggestArgs {
    /// Input scan results JSON file
    #[arg(short, long)]
    pub input: PathBuf,

    /// Filter to a specific finding ID (e.g., PII-001)
    #[arg(long, value_name = "ID")]
    pub finding: Option<String>,

    /// Output format
    #[arg(short, long, default_value = "diff")]
    pub output: SuggestFormat,

    /// Automatically apply fixes (with confirmation prompt for each)
    #[arg(
        long,
        help = "Apply suggested fixes to source files (prompts for confirmation)"
    )]
    pub auto_fix: bool,

    /// Apply all fixes without prompting (use with --auto-fix)
    #[arg(
        long,
        requires = "auto_fix",
        help = "Skip confirmation prompts (use with --auto-fix)"
    )]
    pub yes: bool,
}

#[derive(Clone, Debug, clap::ValueEnum)]
pub enum SuggestFormat {
    Diff,
    Json,
}

pub fn execute(args: SuggestArgs) -> Result<()> {
    // Gate: Free tier has daily limit
    let license = resolve_license(None);
    let (allowed, remaining) = check_suggest_limit(&license);

    if !allowed {
        eprintln!(
            "{} Daily suggest limit reached (3/day on Free tier).",
            style("Limit:").red().bold()
        );
        eprintln!("  Upgrade to Pro for unlimited suggestions: https://piilex.dev/pricing");
        eprintln!("  Or run: piilex license activate <key>");
        std::process::exit(1);
    }

    let content = std::fs::read_to_string(&args.input).context(format!(
        "Failed to read input file: {}",
        args.input.display()
    ))?;

    let finding_set: FindingSet =
        serde_json::from_str(&content).context("Failed to parse scan results JSON")?;

    let findings: Vec<_> = if let Some(ref id) = args.finding {
        finding_set
            .findings
            .iter()
            .filter(|f| &f.id == id)
            .collect()
    } else {
        finding_set.findings.iter().collect()
    };

    if findings.is_empty() {
        if let Some(id) = &args.finding {
            eprintln!("{} No finding with ID '{}'", style("Error:").red(), id);
        } else {
            eprintln!("No findings to suggest fixes for.");
        }
        return Ok(());
    }

    // Build suggest context
    let ctx = SuggestContext {
        project_root: finding_set.metadata.path.to_str().map(|s| s.to_string()),
    };

    // Generate suggestions (try file-based first, fall back to snippet)
    let suggestions: Vec<Suggestion> = findings
        .iter()
        .filter_map(|f| {
            generate_suggestion(f, &ctx).or_else(|| generate_suggestion_from_snippet(f))
        })
        .collect();

    // Record usage for Free tier tracking
    record_suggest_usage();

    if args.auto_fix {
        return execute_auto_fix(&suggestions, args.yes, &license, remaining);
    }

    match args.output {
        SuggestFormat::Diff => {
            print_diff_suggestions(&suggestions);
            print_footer(&suggestions, &license, remaining);
        }
        SuggestFormat::Json => {
            print_json_suggestions(&suggestions)?;
        }
    }

    Ok(())
}

fn print_diff_suggestions(suggestions: &[Suggestion]) {
    for suggestion in suggestions {
        // Header
        eprintln!(
            "{} {} {} {}:{}",
            style("---").dim(),
            style(&suggestion.finding_id).cyan().bold(),
            style(&suggestion.description).white(),
            style(&suggestion.file).dim(),
            style(suggestion.line).dim(),
        );
        eprintln!();

        // Unified diff
        for line in suggestion.unified_diff.lines() {
            if line.starts_with("---") || line.starts_with("+++") {
                println!("  {}", style(line).bold());
            } else if line.starts_with("@@") {
                println!("  {}", style(line).cyan());
            } else if line.starts_with('-') {
                println!("  {}", style(line).red());
            } else if line.starts_with('+') {
                println!("  {}", style(line).green());
            } else {
                println!("  {}", line);
            }
        }
        eprintln!();
    }
}

fn print_footer(
    suggestions: &[Suggestion],
    license: &piilex_license::LicenseInfo,
    remaining: usize,
) {
    eprintln!(
        "{} {} suggestion(s) generated",
        style("Total:").bold(),
        suggestions.len()
    );

    if !suggestions.is_empty() {
        eprintln!(
            "  {} Apply with: piilex suggest -i <scan.json> --auto-fix",
            style("Tip:").dim()
        );
    }

    if !license.is_pro() {
        let new_remaining = remaining.saturating_sub(1);
        eprintln!(
            "  {} {}/3 suggestions remaining today (Free tier)",
            style("Limit:").dim(),
            new_remaining
        );
    }
}

fn print_json_suggestions(suggestions: &[Suggestion]) -> Result<()> {
    let json: Vec<serde_json::Value> = suggestions
        .iter()
        .map(|s| {
            serde_json::json!({
                "finding_id": s.finding_id,
                "file": s.file,
                "line": s.line,
                "description": s.description,
                "original_line": s.original_line,
                "replacement_line": s.replacement_line,
                "unified_diff": s.unified_diff,
            })
        })
        .collect();
    println!("{}", serde_json::to_string_pretty(&json)?);
    Ok(())
}

fn execute_auto_fix(
    suggestions: &[Suggestion],
    skip_prompt: bool,
    license: &piilex_license::LicenseInfo,
    remaining: usize,
) -> Result<()> {
    let mut applied = 0;
    let mut skipped = 0;
    let mut failed = 0;

    for suggestion in suggestions {
        eprintln!(
            "\n{} {} {}:{}",
            style("Fix:").cyan().bold(),
            suggestion.description,
            style(&suggestion.file).dim(),
            style(suggestion.line).dim(),
        );

        // Show the diff
        for line in suggestion.unified_diff.lines() {
            if line.starts_with('-') {
                eprintln!("  {}", style(line).red());
            } else if line.starts_with('+') {
                eprintln!("  {}", style(line).green());
            } else if line.starts_with("@@") {
                eprintln!("  {}", style(line).cyan());
            }
        }

        let should_apply = if skip_prompt {
            true
        } else {
            prompt_yes_no("  Apply this fix?")
        };

        if should_apply {
            match apply_suggestion(suggestion) {
                Ok(true) => {
                    eprintln!("  {} Applied", style("OK").green().bold());
                    applied += 1;
                }
                Ok(false) => {
                    eprintln!(
                        "  {} Source line has changed since scan (stale); skipped",
                        style("SKIP").yellow()
                    );
                    failed += 1;
                }
                Err(e) => {
                    eprintln!("  {} {}", style("ERR").red(), e);
                    failed += 1;
                }
            }
        } else {
            eprintln!("  {} Skipped", style("--").dim());
            skipped += 1;
        }
    }

    eprintln!();
    eprintln!(
        "{} applied: {}  skipped: {}  failed: {}",
        style("Auto-fix summary:").bold(),
        style(applied).green(),
        style(skipped).dim(),
        if failed > 0 {
            style(failed).red().to_string()
        } else {
            style(failed).dim().to_string()
        },
    );

    if !license.is_pro() {
        let new_remaining = remaining.saturating_sub(1);
        eprintln!(
            "  {} {}/3 suggestions remaining today (Free tier)",
            style("Limit:").dim(),
            new_remaining
        );
    }

    Ok(())
}

fn prompt_yes_no(message: &str) -> bool {
    eprint!("{} [Y/n] ", message);
    std::io::stderr().flush().ok();

    let mut input = String::new();
    if std::io::stdin().read_line(&mut input).is_err() {
        return false;
    }

    let trimmed = input.trim().to_lowercase();
    trimmed.is_empty() || trimmed == "y" || trimmed == "yes"
}
