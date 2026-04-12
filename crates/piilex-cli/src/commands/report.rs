use anyhow::{Context, Result};
use clap::Args;
use console::style;
use std::path::PathBuf;

use piilex_core::finding::{FindingSet, Framework};
use piilex_license::{require_pro, resolve_license, ProFeature};

use crate::output;

#[derive(Args)]
pub struct ReportArgs {
    /// Input scan results JSON file
    #[arg(short, long)]
    pub input: PathBuf,

    /// Regulatory framework for report
    #[arg(short, long)]
    pub framework: String,

    /// Output format
    #[arg(short, long, default_value = "markdown")]
    pub output: ReportFormat,

    /// Output file (default: stdout)
    #[arg(long)]
    pub out_file: Option<PathBuf>,
}

#[derive(Clone, Debug, clap::ValueEnum)]
pub enum ReportFormat {
    Markdown,
    Html,
    Json,
}

pub fn execute(args: ReportArgs) -> Result<()> {
    // Gate: report requires Pro
    let license = resolve_license(None);
    if let Err(e) = require_pro(&license, ProFeature::Report) {
        eprintln!("{} {}", style("Pro required:").red().bold(), e);
        std::process::exit(1);
    }

    let content = std::fs::read_to_string(&args.input).context(format!(
        "Failed to read input file: {}",
        args.input.display()
    ))?;

    let finding_set: FindingSet =
        serde_json::from_str(&content).context("Failed to parse scan results JSON")?;

    let framework: Framework = args
        .framework
        .parse()
        .map_err(|e: String| anyhow::anyhow!(e))?;

    let report = match args.output {
        ReportFormat::Markdown => output::markdown::generate_report(&finding_set, framework),
        ReportFormat::Html => {
            let md = output::markdown::generate_report(&finding_set, framework);
            format!("<html><head><meta charset='utf-8'><title>PII Compliance Report</title>\
                     <style>body{{font-family:sans-serif;max-width:900px;margin:0 auto;padding:20px}}\
                     table{{border-collapse:collapse;width:100%}}th,td{{border:1px solid #ddd;padding:8px;text-align:left}}\
                     th{{background:#f5f5f5}}.critical{{color:#d32f2f}}.high{{color:#f57c00}}\
                     .medium{{color:#fbc02d}}.low{{color:#388e3c}}</style></head>\
                     <body><pre>{}</pre></body></html>", md)
        }
        ReportFormat::Json => serde_json::to_string_pretty(&finding_set)?,
    };

    if let Some(out_path) = &args.out_file {
        std::fs::write(out_path, &report)
            .context(format!("Failed to write report to {}", out_path.display()))?;
        eprintln!("Report written to {}", out_path.display());
    } else {
        println!("{}", report);
    }

    Ok(())
}
