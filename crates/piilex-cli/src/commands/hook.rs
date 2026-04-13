use anyhow::Result;
use clap::{Args, Subcommand};
use console::style;
use std::path::Path;

#[derive(Args)]
#[command(
    long_about = "Manage git pre-commit hooks for automatic PII scanning.\n\n\
                  Installs a pre-commit hook that runs piilex on staged files\n\
                  before each commit. Blocks the commit if findings exceed\n\
                  the configured severity threshold.",
    after_long_help = "\
EXAMPLES:
  Install hook:
    piilex hook install

  Install with custom threshold:
    piilex hook install --fail-on critical

  Remove hook:
    piilex hook uninstall

  Use with husky:
    npx husky add .husky/pre-commit 'piilex scan --staged --fail-on high'

  Use with lefthook:
    # lefthook.yml
    pre-commit:
      commands:
        pii-scan:
          run: piilex scan --staged --fail-on high"
)]
pub struct HookArgs {
    #[command(subcommand)]
    pub command: HookCommand,
}

#[derive(Subcommand)]
pub enum HookCommand {
    /// Install the pre-commit hook
    Install(InstallArgs),
    /// Remove the pre-commit hook
    Uninstall,
    /// Show hook status
    Status,
}

#[derive(Args)]
pub struct InstallArgs {
    /// Minimum severity to block commit
    #[arg(long, default_value = "high", value_name = "LEVEL")]
    pub fail_on: String,
}

pub fn execute(args: HookArgs) -> Result<()> {
    match args.command {
        HookCommand::Install(a) => install(a),
        HookCommand::Uninstall => uninstall(),
        HookCommand::Status => status(),
    }
}

const HOOK_MARKER: &str = "# piilex pre-commit hook";

fn git_hooks_dir() -> Option<std::path::PathBuf> {
    let output = std::process::Command::new("git")
        .args(["rev-parse", "--git-dir"])
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let git_dir = String::from_utf8_lossy(&output.stdout).trim().to_string();
    Some(Path::new(&git_dir).join("hooks"))
}

fn install(args: InstallArgs) -> Result<()> {
    let hooks_dir = git_hooks_dir()
        .ok_or_else(|| anyhow::anyhow!("Not a git repository. Run this from inside a git repo."))?;

    std::fs::create_dir_all(&hooks_dir)?;
    let hook_path = hooks_dir.join("pre-commit");

    let hook_script = format!(
        r#"#!/bin/sh
{HOOK_MARKER}
# Automatically installed by piilex. Remove with: piilex hook uninstall

# Run piilex on staged files
piilex scan --staged --fail-on {fail_on} --quiet

if [ $? -ne 0 ]; then
    echo ""
    echo "piilex: PII findings detected. Commit blocked."
    echo "  Review:  piilex scan --staged"
    echo "  Skip:    git commit --no-verify"
    echo ""
    exit 1
fi
"#,
        HOOK_MARKER = HOOK_MARKER,
        fail_on = args.fail_on,
    );

    // Check if hook already exists
    if hook_path.exists() {
        let existing = std::fs::read_to_string(&hook_path)?;
        if existing.contains(HOOK_MARKER) {
            // Replace existing piilex hook
            std::fs::write(&hook_path, &hook_script)?;
            eprintln!(
                "{} Pre-commit hook updated (--fail-on {})",
                style("OK").green().bold(),
                args.fail_on
            );
        } else {
            // Append to existing hook
            let combined = format!("{}\n\n{}", existing.trim(), hook_script);
            std::fs::write(&hook_path, combined)?;
            eprintln!(
                "{} piilex added to existing pre-commit hook (--fail-on {})",
                style("OK").green().bold(),
                args.fail_on
            );
        }
    } else {
        std::fs::write(&hook_path, &hook_script)?;
        eprintln!(
            "{} Pre-commit hook installed (--fail-on {})",
            style("OK").green().bold(),
            args.fail_on
        );
    }

    // Make executable on Unix
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&hook_path)?.permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&hook_path, perms)?;
    }

    eprintln!("  Path: {}", hook_path.display());
    eprintln!();
    eprintln!("How it works:");
    eprintln!("  1. On each `git commit`, piilex scans staged files");
    eprintln!(
        "  2. If {} or higher findings are detected, the commit is blocked",
        args.fail_on
    );
    eprintln!("  3. Use `git commit --no-verify` to bypass");

    Ok(())
}

fn uninstall() -> Result<()> {
    let hooks_dir = git_hooks_dir().ok_or_else(|| anyhow::anyhow!("Not a git repository."))?;

    let hook_path = hooks_dir.join("pre-commit");

    if !hook_path.exists() {
        eprintln!("No pre-commit hook found.");
        return Ok(());
    }

    let content = std::fs::read_to_string(&hook_path)?;

    if !content.contains(HOOK_MARKER) {
        eprintln!("Pre-commit hook exists but was not installed by piilex.");
        return Ok(());
    }

    // If the entire file is the piilex hook, remove it
    // If it's appended to another hook, remove just the piilex section
    let lines: Vec<&str> = content.lines().collect();
    let mut new_lines = Vec::new();
    let mut in_piilex_section = false;

    for line in &lines {
        if line.contains(HOOK_MARKER) {
            in_piilex_section = true;
            continue;
        }
        if in_piilex_section {
            // Skip until we find an empty line or end of file
            if line.trim().is_empty() && !new_lines.is_empty() {
                in_piilex_section = false;
            }
            continue;
        }
        new_lines.push(*line);
    }

    let remaining = new_lines.join("\n").trim().to_string();

    if remaining.is_empty() || remaining == "#!/bin/sh" {
        std::fs::remove_file(&hook_path)?;
        eprintln!("{} Pre-commit hook removed", style("OK").green().bold());
    } else {
        std::fs::write(&hook_path, remaining + "\n")?;
        eprintln!(
            "{} piilex section removed from pre-commit hook",
            style("OK").green().bold()
        );
    }

    Ok(())
}

fn status() -> Result<()> {
    let hooks_dir = match git_hooks_dir() {
        Some(d) => d,
        None => {
            eprintln!("Not a git repository.");
            return Ok(());
        }
    };

    let hook_path = hooks_dir.join("pre-commit");

    if !hook_path.exists() {
        eprintln!("{} No pre-commit hook installed", style("Status:").bold());
        eprintln!("  Install: piilex hook install");
        return Ok(());
    }

    let content = std::fs::read_to_string(&hook_path)?;

    if content.contains(HOOK_MARKER) {
        // Extract fail-on level
        let fail_on = content
            .lines()
            .find(|l| l.contains("--fail-on"))
            .and_then(|l| l.split("--fail-on").nth(1))
            .and_then(|s| s.split_whitespace().next())
            .unwrap_or("unknown");

        eprintln!(
            "{} piilex pre-commit hook is {}",
            style("Status:").bold(),
            style("active").green().bold()
        );
        eprintln!("  Threshold: --fail-on {}", fail_on);
        eprintln!("  Path: {}", hook_path.display());
    } else {
        eprintln!(
            "{} Pre-commit hook exists but is not managed by piilex",
            style("Status:").bold()
        );
        eprintln!("  Path: {}", hook_path.display());
    }

    Ok(())
}
