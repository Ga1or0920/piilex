use anyhow::Result;
use clap::{Args, Subcommand};
use console::style;

use piilex_core::telemetry;

#[derive(Args)]
#[command(
    long_about = "Manage anonymous usage telemetry.\n\n\
                  piilex collects anonymous, bucketed statistics (scan counts,\n\
                  PII type distribution, language distribution) to improve the\n\
                  product. No file paths, source code, or PII values are ever\n\
                  collected.\n\n\
                  Telemetry is opt-in only. Set PIILEX_TELEMETRY=0 to disable.",
    after_long_help = "\
EXAMPLES:
  Check status:
    piilex telemetry status

  Enable:
    piilex telemetry on

  Disable:
    piilex telemetry off

  Disable via environment:
    PIILEX_TELEMETRY=0 piilex scan ./src"
)]
pub struct TelemetryArgs {
    #[command(subcommand)]
    pub command: TelemetryCommand,
}

#[derive(Subcommand)]
pub enum TelemetryCommand {
    /// Enable anonymous telemetry
    On,
    /// Disable anonymous telemetry
    Off,
    /// Show current telemetry status and stored events
    Status,
}

pub fn execute(args: TelemetryArgs) -> Result<()> {
    match args.command {
        TelemetryCommand::On => enable(),
        TelemetryCommand::Off => disable(),
        TelemetryCommand::Status => status(),
    }
}

fn enable() -> Result<()> {
    telemetry::set_consent(telemetry::ConsentStatus::Enabled);
    eprintln!("{} Telemetry enabled", style("OK").green().bold());
    eprintln!();
    eprintln!("What we collect (anonymous, bucketed):");
    eprintln!("  - Scan count and duration bucket");
    eprintln!("  - PII type distribution (e.g., email: 5, password: 2)");
    eprintln!("  - Language distribution (e.g., typescript: 80%%)");
    eprintln!("  - Platform (e.g., x86_64-linux)");
    eprintln!();
    eprintln!("What we {} collect:", style("never").red().bold());
    eprintln!("  - File paths or names");
    eprintln!("  - Source code or snippets");
    eprintln!("  - PII values");
    eprintln!("  - IP addresses or user identity");
    eprintln!();
    eprintln!("Disable anytime: piilex telemetry off");
    Ok(())
}

fn disable() -> Result<()> {
    telemetry::set_consent(telemetry::ConsentStatus::Disabled);
    // Clear any stored events
    if let Some(path) = piilex_core::telemetry::events_path_public() {
        let _ = std::fs::remove_file(&path);
    }
    eprintln!(
        "{} Telemetry disabled. Stored events cleared.",
        style("OK").green().bold()
    );
    Ok(())
}

fn status() -> Result<()> {
    let consent = telemetry::get_consent();
    let effective = telemetry::is_enabled();
    let event_count = telemetry::stored_event_count();

    eprintln!("{}", style("Telemetry Status").bold());
    eprintln!(
        "  Consent:    {}",
        match consent {
            telemetry::ConsentStatus::Enabled => style("enabled").green().bold().to_string(),
            telemetry::ConsentStatus::Disabled => style("disabled").dim().to_string(),
            telemetry::ConsentStatus::Pending => style("not yet set").yellow().to_string(),
        }
    );
    eprintln!(
        "  Effective:  {}",
        if effective {
            style("active").green().to_string()
        } else {
            style("inactive").dim().to_string()
        }
    );

    if let Ok(val) = std::env::var("PIILEX_TELEMETRY") {
        eprintln!("  Env override: PIILEX_TELEMETRY={}", val);
    }

    eprintln!("  Stored events: {}", event_count);
    eprintln!();

    if consent == telemetry::ConsentStatus::Pending {
        eprintln!("  Enable:  piilex telemetry on");
        eprintln!("  Disable: piilex telemetry off");
    }

    Ok(())
}

/// Show the opt-in prompt on first run (if consent is pending).
/// Returns true if user opted in.
pub fn maybe_prompt_consent() -> bool {
    if telemetry::get_consent() != telemetry::ConsentStatus::Pending {
        return telemetry::is_enabled();
    }

    // Check if running in a CI/non-interactive environment
    if !console::Term::stderr().is_term() || std::env::var("CI").is_ok() {
        // Don't prompt in CI; default to disabled
        telemetry::set_consent(telemetry::ConsentStatus::Disabled);
        return false;
    }

    eprintln!();
    eprintln!(
        "{} Help improve piilex with anonymous usage statistics?",
        style("?").cyan().bold()
    );
    eprintln!("  We collect only bucketed counts (scan count, PII type distribution).");
    eprintln!("  No file paths, code, or PII values. Disable anytime: piilex telemetry off");
    eprint!("  Enable telemetry? [y/N] ");

    use std::io::Write;
    std::io::stderr().flush().ok();

    let mut input = String::new();
    if std::io::stdin().read_line(&mut input).is_err() {
        telemetry::set_consent(telemetry::ConsentStatus::Disabled);
        return false;
    }

    let opted_in = matches!(input.trim().to_lowercase().as_str(), "y" | "yes");

    if opted_in {
        telemetry::set_consent(telemetry::ConsentStatus::Enabled);
        eprintln!("  {} Telemetry enabled. Thank you!", style("OK").green());
    } else {
        telemetry::set_consent(telemetry::ConsentStatus::Disabled);
        eprintln!("  {} Telemetry disabled.", style("OK").dim());
    }
    eprintln!();

    opted_in
}
