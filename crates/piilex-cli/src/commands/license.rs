use anyhow::{Context, Result};
use clap::{Args, Subcommand};
use console::style;

#[derive(Args)]
pub struct LicenseArgs {
    #[command(subcommand)]
    pub command: LicenseCommand,
}

#[derive(Subcommand)]
pub enum LicenseCommand {
    /// Activate a Pro license key
    Activate(ActivateArgs),
    /// Deactivate the current license
    Deactivate,
    /// Show current license status
    Status,
}

#[derive(Args)]
pub struct ActivateArgs {
    /// License key (JWT token)
    pub key: String,
}

pub fn execute(args: LicenseArgs) -> Result<()> {
    match args.command {
        LicenseCommand::Activate(a) => activate(a),
        LicenseCommand::Deactivate => deactivate(),
        LicenseCommand::Status => status(),
    }
}

fn activate(args: ActivateArgs) -> Result<()> {
    // Validate first
    let info =
        piilex_license::validate_token(&args.key).context("License key validation failed")?;

    // Save to file
    let path = piilex_license::save_license_key(&args.key).context("Failed to save license key")?;

    eprintln!("{} Pro license activated", style("✓").green().bold());
    eprintln!("  Email:   {}", info.email);
    if let Some(exp) = info.expires_at {
        eprintln!("  Expires: {}", format_ts(exp));
    }
    eprintln!("  Saved:   {}", path.display());
    eprintln!();
    eprintln!("Pro features are now available:");
    eprintln!("  - piilex scan --framework gdpr,ccpa");
    eprintln!("  - piilex report");
    eprintln!("  - piilex suggest (unlimited)");
    eprintln!("  - piilex scan --baseline");

    Ok(())
}

fn deactivate() -> Result<()> {
    piilex_license::remove_license_key().context("Failed to remove license key")?;

    eprintln!(
        "{} License deactivated. Reverted to Free tier.",
        style("✓").green().bold()
    );

    Ok(())
}

fn status() -> Result<()> {
    let info = piilex_license::resolve_license(None);

    eprintln!("{}", style("License Status").bold());
    eprintln!(
        "  Tier:    {}",
        match info.tier {
            piilex_license::LicenseTier::Pro => style("Pro").green().bold().to_string(),
            piilex_license::LicenseTier::Free => style("Free").dim().to_string(),
        }
    );

    if !info.email.is_empty() {
        eprintln!("  Email:   {}", info.email);
    }

    if let Some(exp) = info.expires_at {
        eprintln!("  Expires: {}", format_ts(exp));
    }

    if info.is_expired {
        eprintln!("  {}", style("LICENSE EXPIRED — please renew").red().bold());
    }

    eprintln!();

    let features = [
        ("scan (basic PII detection)", true),
        ("scan --framework (regulatory mapping)", info.is_pro()),
        ("report (compliance reports)", info.is_pro()),
        ("suggest (unlimited)", info.is_pro()),
        ("scan --baseline (diff scanning)", info.is_pro()),
    ];

    for (name, available) in &features {
        let icon = if *available {
            style("[x]").green().to_string()
        } else {
            style("[ ]").dim().to_string()
        };
        eprintln!("  {} {}", icon, name);
    }

    if !info.is_pro() {
        eprintln!();
        eprintln!("  Upgrade: https://piilex.dev/pricing");
        eprintln!("  Activate: piilex license activate <key>");
    }

    Ok(())
}

fn format_ts(ts: u64) -> String {
    let days_since_epoch = ts / 86400;
    let mut y = 1970u64;
    let mut remaining = days_since_epoch;
    loop {
        let diy = if y % 4 == 0 && (y % 100 != 0 || y % 400 == 0) {
            366
        } else {
            365
        };
        if remaining < diy {
            break;
        }
        remaining -= diy;
        y += 1;
    }
    let months = [
        31,
        if y % 4 == 0 && (y % 100 != 0 || y % 400 == 0) {
            29
        } else {
            28
        },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    let mut m = 0;
    for dim in months {
        if remaining < dim {
            break;
        }
        remaining -= dim;
        m += 1;
    }
    format!("{}-{:02}-{:02}", y, m + 1, remaining + 1)
}
