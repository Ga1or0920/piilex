use anyhow::Result;
use clap::{Parser, Subcommand};

use crate::commands;

#[derive(Parser)]
#[command(
    name = "piilex",
    version,
    about = "PII Lexical Analyzer -- Detect PII in source code and map to regulatory frameworks",
    long_about = "piilex statically analyzes TypeScript, JavaScript, and Python source code\n\
                  to detect personally identifiable information (PII), trace data flows,\n\
                  and map findings to regulatory frameworks such as GDPR and CCPA.\n\n\
                  Free tier includes basic PII detection.\n\
                  Pro tier adds --framework mapping, reports, and baseline diff scanning.",
    after_long_help = "\
EXAMPLES:
  Basic scan:
    piilex scan ./src

  Scan with GDPR mapping (Pro):
    piilex scan ./src --framework gdpr

  JSON output for CI pipelines:
    piilex scan ./src -o json --fail-on high

  SARIF for GitHub Code Scanning:
    piilex scan ./src -o sarif > results.sarif

  Generate compliance report (Pro):
    piilex report -i scan.json --framework gdpr -o html --out-file report.html

  Baseline diff (Pro):
    piilex scan ./src --save-baseline baseline.json
    piilex scan ./src --baseline baseline.json

  Check license:
    piilex license status

ENVIRONMENT VARIABLES:
  PIILEX_LICENSE_KEY   Pro license JWT token (for CI/CD)

CONFIGURATION:
  .piilex.yml          Project config (create with: piilex init)

MORE INFO:
  https://piilex.dev/docs"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand)]
#[allow(clippy::large_enum_variant)]
pub enum Command {
    /// Scan source code for PII and data flow risks
    #[command(
        long_about = "Scan source code files for PII (personally identifiable information).\n\n\
                      Detects 20+ PII types including email, phone, SSN, credit card, passwords,\n\
                      and health data. Traces data flows from source to sink (logs, databases,\n\
                      APIs, HTTP responses). Supports TypeScript, JavaScript, and Python.",
        after_long_help = "\
EXAMPLES:
  Scan current directory:
    piilex scan

  Scan specific path:
    piilex scan ./src/api

  Filter by severity:
    piilex scan --severity high

  CI gate (exit 1 on high+):
    piilex scan --fail-on high -o sarif

  Skip cross-file analysis:
    piilex scan --no-flow

  Exclude test files:
    piilex scan --exclude '**/*.test.ts'"
    )]
    Scan(commands::scan::ScanArgs),

    /// Generate compliance report from scan results [Pro]
    #[command(
        long_about = "Generate a formatted compliance report from scan results.\n\n\
                      Maps findings to specific regulatory articles and produces\n\
                      an article-by-article assessment suitable for auditors.\n\n\
                      Requires a Pro license.",
        after_long_help = "\
EXAMPLES:
  Save scan results first:
    piilex scan ./src -o json > scan.json

  GDPR markdown report:
    piilex report -i scan.json -f gdpr

  HTML report to file:
    piilex report -i scan.json -f gdpr -o html --out-file report.html

  CCPA report:
    piilex report -i scan.json -f ccpa -o markdown"
    )]
    Report(commands::report::ReportArgs),

    /// Generate fix suggestions for detected PII issues
    #[command(
        long_about = "Generate concrete code fix suggestions for PII findings.\n\n\
                      Provides masking functions, redaction patterns, and best-practice\n\
                      recommendations for each finding type.\n\n\
                      Free tier: 3 suggestions per day. Pro: unlimited.",
        after_long_help = "\
EXAMPLES:
  Save scan results first:
    piilex scan ./src -o json > scan.json

  Show all suggestions:
    piilex suggest -i scan.json

  Suggest for a specific finding:
    piilex suggest -i scan.json --finding PII-001

  JSON output:
    piilex suggest -i scan.json -o json"
    )]
    Suggest(commands::suggest::SuggestArgs),

    /// Initialize project configuration (.piilex.yml)
    #[command(
        long_about = "Create a .piilex.yml configuration file in the current directory.\n\n\
                      Configures language targets, exclude patterns, severity thresholds,\n\
                      and framework selections for your project.",
        after_long_help = "\
EXAMPLES:
  Default config:
    piilex init

  With GDPR framework:
    piilex init --framework gdpr

  TypeScript only:
    piilex init --lang typescript"
    )]
    Init(commands::init::InitArgs),

    /// Manage Pro license (activate, deactivate, status)
    #[command(
        long_about = "Manage your piilex Pro license.\n\n\
                      Pro features include --framework regulatory mapping,\n\
                      compliance reports, unlimited suggestions, and baseline diff.",
        after_long_help = "\
EXAMPLES:
  Check current license:
    piilex license status

  Activate a Pro key:
    piilex license activate <JWT_TOKEN>

  Deactivate:
    piilex license deactivate

CI/CD USAGE:
  Set PIILEX_LICENSE_KEY environment variable instead of activating."
    )]
    License(commands::license::LicenseArgs),

    /// Manage anonymous usage telemetry (on/off/status)
    #[command(long_about = "Manage anonymous usage telemetry.\n\n\
                      piilex can collect anonymous, bucketed statistics to improve\n\
                      the product. No file paths, code, or PII values are collected.\n\
                      Telemetry is opt-in only.")]
    Telemetry(commands::telemetry::TelemetryArgs),

    /// Start the Language Server Protocol server (for IDE integration)
    #[command(long_about = "Start the piilex LSP server for IDE integration.\n\n\
                      Communicates via stdin/stdout using the Language Server Protocol.\n\
                      Designed to be launched by VS Code, IntelliJ, or other LSP clients.")]
    Lsp,

    /// Manage git pre-commit hooks
    Hook(commands::hook::HookArgs),
}

pub fn run() -> Result<()> {
    let cli = Cli::parse();

    // Check for first-run telemetry consent (only for interactive commands)
    match &cli.command {
        Command::Scan(_) | Command::Init(_) => {
            commands::telemetry::maybe_prompt_consent();
        }
        _ => {}
    }

    // Record command usage (if telemetry enabled)
    let cmd_name = match &cli.command {
        Command::Scan(_) => "scan",
        Command::Report(_) => "report",
        Command::Suggest(_) => "suggest",
        Command::Init(_) => "init",
        Command::License(_) => "license",
        Command::Telemetry(_) => "telemetry",
        Command::Lsp => "lsp",
        Command::Hook(_) => "hook",
    };
    piilex_core::telemetry::record_command(cmd_name);

    match cli.command {
        Command::Scan(args) => commands::scan::execute(args),
        Command::Report(args) => commands::report::execute(args),
        Command::Suggest(args) => commands::suggest::execute(args),
        Command::Init(args) => commands::init::execute(args),
        Command::License(args) => commands::license::execute(args),
        Command::Telemetry(args) => commands::telemetry::execute(args),
        Command::Lsp => {
            piilex_lsp::run_server().map_err(|e| anyhow::anyhow!("LSP server error: {}", e))
        }
        Command::Hook(args) => commands::hook::execute(args),
    }
}
