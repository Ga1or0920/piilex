use anyhow::Result;
use clap::Args;
use console::style;
use std::path::Path;

use piilex_core::config::Config;

#[derive(Args)]
pub struct InitArgs {
    /// Default regulatory framework
    #[arg(short, long)]
    pub framework: Option<String>,

    /// Target language
    #[arg(short, long)]
    pub lang: Option<String>,
}

pub fn execute(args: InitArgs) -> Result<()> {
    let config_path = Path::new(".piilex.yml");

    if config_path.exists() {
        eprintln!(
            "{} {} already exists. Use --force to overwrite.",
            style("Error:").red(),
            config_path.display()
        );
        std::process::exit(1);
    }

    let mut content = Config::default_config_yaml().to_string();

    // Customize based on args
    if let Some(fw) = &args.framework {
        content = content.replace(
            "frameworks: []\n  # - gdpr",
            &format!("frameworks:\n  - {}", fw),
        );
    }

    if let Some(lang) = &args.lang {
        content = content.replace(
            "languages: [typescript, javascript, python]",
            &format!("languages: [{}]", lang),
        );
    }

    std::fs::write(config_path, &content)?;

    println!(
        "{} Created {}",
        style("✓").green().bold(),
        config_path.display()
    );
    println!();
    println!("Next steps:");
    println!(
        "  1. Edit {} to customize scan settings",
        config_path.display()
    );
    println!("  2. Run {} to scan your code", style("piilex scan").cyan());
    println!(
        "  3. Run {} for compliance reports",
        style("piilex scan --framework gdpr").cyan()
    );

    Ok(())
}
