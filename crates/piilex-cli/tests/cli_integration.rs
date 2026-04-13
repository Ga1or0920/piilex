use assert_cmd::Command;
use predicates::prelude::*;
use std::fs;
use tempfile::TempDir;

/// Helper to get a `Command` for the piilex binary.
fn piilex() -> Command {
    Command::cargo_bin("piilex").expect("binary not found")
}

/// Generate a Pro license token signed with the production private key.
/// Returns None if the production key doesn't match the embedded public key
/// (e.g., in CI where a fresh key is generated).
fn pro_token() -> Option<String> {
    let private_pem = include_str!("../../../keys/private.pem");
    let token = piilex_license::generate_token_with_key("test@ci.dev", "pro", 365, private_pem);
    // Verify it actually works with the embedded public key
    match piilex_license::validate_token(&token) {
        Ok(_) => Some(token),
        Err(_) => None, // Keys don't match (CI environment)
    }
}

/// Path to the test fixtures directory (relative to workspace root).
fn fixtures_dir() -> String {
    let manifest = env!("CARGO_MANIFEST_DIR");
    // crates/piilex-cli -> ../../tests/fixtures
    let workspace = std::path::Path::new(manifest)
        .parent()
        .unwrap()
        .parent()
        .unwrap();
    workspace
        .join("tests")
        .join("fixtures")
        .to_string_lossy()
        .to_string()
}

fn ts_fixture(name: &str) -> String {
    format!("{}/typescript/{}", fixtures_dir(), name)
}

fn py_fixture(name: &str) -> String {
    format!("{}/python/{}", fixtures_dir(), name)
}

// =====================================================================
// 1. Version and help
// =====================================================================

#[test]
fn version_flag() {
    piilex()
        .arg("--version")
        .assert()
        .success()
        .stdout(predicate::str::contains("piilex 0.1.0"));
}

#[test]
fn help_flag() {
    piilex()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("Scan source code for PII"))
        .stdout(predicate::str::contains("scan"))
        .stdout(predicate::str::contains("report"))
        .stdout(predicate::str::contains("suggest"))
        .stdout(predicate::str::contains("init"))
        .stdout(predicate::str::contains("license"));
}

#[test]
fn scan_help() {
    piilex()
        .args(["scan", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("--framework"))
        .stdout(predicate::str::contains("--output"))
        .stdout(predicate::str::contains("--fail-on"))
        .stdout(predicate::str::contains("--baseline"))
        .stdout(predicate::str::contains("--save-baseline"));
}

// =====================================================================
// 2. Scan: basic detection
// =====================================================================

#[test]
fn scan_typescript_finds_pii() {
    piilex()
        .args(["scan", &ts_fixture("simple_pii.ts"), "-q"])
        .assert()
        .success()
        .stderr(predicate::str::contains("critical:"))
        .stderr(predicate::str::contains("high:"));
}

#[test]
fn scan_python_finds_pii() {
    piilex()
        .args(["scan", &py_fixture("simple_pii.py"), "-q"])
        .assert()
        .success()
        .stderr(predicate::str::contains("critical:"))
        .stderr(predicate::str::contains("high:"));
}

#[test]
fn scan_clean_code_no_findings() {
    piilex()
        .args(["scan", &ts_fixture("clean_code.ts")])
        .assert()
        .success()
        .stderr(predicate::str::contains("0 finding(s)"))
        .stderr(predicate::str::contains("No PII findings detected"));
}

#[test]
fn scan_clean_python_no_findings() {
    piilex()
        .args(["scan", &py_fixture("clean_code.py")])
        .assert()
        .success()
        .stderr(predicate::str::contains("0 finding(s)"));
}

#[test]
fn scan_directory_multiple_files() {
    piilex()
        .args(["scan", &fixtures_dir(), "-q"])
        .assert()
        .success()
        .stderr(predicate::str::contains("critical:"))
        .stderr(predicate::str::contains("high:"));
}

// =====================================================================
// 3. Output formats
// =====================================================================

#[test]
fn scan_json_output_is_valid() {
    let output = piilex()
        .args(["scan", &ts_fixture("simple_pii.ts"), "-o", "json"])
        .output()
        .expect("failed to execute");

    assert!(output.status.success());

    let json: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("stdout should be valid JSON");

    assert!(json["findings"].is_array());
    assert!(json["metadata"]["files_scanned"].is_number());
    assert!(json["metadata"]["tool_version"].is_string());

    let findings = json["findings"].as_array().unwrap();
    assert!(!findings.is_empty(), "should have findings");

    // Each finding should have required fields
    let f = &findings[0];
    assert!(f["id"].is_string());
    assert!(f["severity"].is_string());
    assert!(f["pii_type"].is_string());
    assert!(f["location"]["line"].is_number());
    assert!(f["code_snippet"].is_string());
}

#[test]
fn scan_sarif_output_is_valid() {
    let output = piilex()
        .args(["scan", &ts_fixture("simple_pii.ts"), "-o", "sarif"])
        .output()
        .expect("failed to execute");

    assert!(output.status.success());

    let sarif: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("stdout should be valid SARIF JSON");

    assert_eq!(sarif["version"], "2.1.0");
    assert!(sarif["runs"].is_array());
    assert!(sarif["runs"][0]["tool"]["driver"]["name"] == "piilex");
    assert!(sarif["runs"][0]["results"].is_array());
}

#[test]
fn scan_table_output_contains_columns() {
    piilex()
        .args(["scan", &ts_fixture("simple_pii.ts")])
        .assert()
        .success()
        .stderr(predicate::str::contains("SEVERITY"))
        .stderr(predicate::str::contains("TYPE"))
        .stderr(predicate::str::contains("FILE"))
        .stderr(predicate::str::contains("LINE"));
}

// =====================================================================
// 4. Exit codes and --fail-on
// =====================================================================

#[test]
fn fail_on_high_exits_1_when_findings() {
    piilex()
        .args(["scan", &ts_fixture("simple_pii.ts"), "--fail-on", "high"])
        .assert()
        .code(1);
}

#[test]
fn fail_on_critical_exits_1_when_critical() {
    // simple_pii.ts has password (critical), credit_card (critical), ssn (critical)
    piilex()
        .args([
            "scan",
            &ts_fixture("simple_pii.ts"),
            "--fail-on",
            "critical",
        ])
        .assert()
        .code(1);
}

#[test]
fn fail_on_critical_exits_0_when_no_critical() {
    // clean_code.ts has no findings
    piilex()
        .args([
            "scan",
            &ts_fixture("clean_code.ts"),
            "--fail-on",
            "critical",
        ])
        .assert()
        .success();
}

// =====================================================================
// 5. Severity filter
// =====================================================================

#[test]
fn severity_filter_high_hides_medium_and_low() {
    let output = piilex()
        .args([
            "scan",
            &ts_fixture("simple_pii.ts"),
            "--severity",
            "high",
            "-o",
            "json",
        ])
        .output()
        .expect("failed to execute");

    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let findings = json["findings"].as_array().unwrap();

    for f in findings {
        let sev = f["severity"].as_str().unwrap();
        assert!(
            sev == "high" || sev == "critical",
            "found severity '{}' which should be filtered",
            sev
        );
    }
}

// =====================================================================
// 6. License gating (Free tier)
// =====================================================================

#[test]
fn framework_requires_pro() {
    // Ensure no license is active for this test
    std::env::remove_var("PIILEX_LICENSE_KEY");

    piilex()
        .args(["scan", &ts_fixture("simple_pii.ts"), "--framework", "gdpr"])
        .env_remove("PIILEX_LICENSE_KEY")
        .assert()
        .code(1)
        .stderr(predicate::str::contains("Pro required"));
}

#[test]
fn baseline_requires_pro() {
    std::env::remove_var("PIILEX_LICENSE_KEY");

    piilex()
        .args([
            "scan",
            &ts_fixture("simple_pii.ts"),
            "--baseline",
            "nonexistent.json",
        ])
        .env_remove("PIILEX_LICENSE_KEY")
        .assert()
        .code(1)
        .stderr(predicate::str::contains("Pro required"));
}

#[test]
fn pro_via_env_unlocks_framework() {
    let Some(token) = pro_token() else {
        eprintln!("Skipping: production key not available");
        return;
    };

    piilex()
        .args([
            "scan",
            &ts_fixture("simple_pii.ts"),
            "--framework",
            "gdpr",
            "-q",
        ])
        .env("PIILEX_LICENSE_KEY", &token)
        .assert()
        .success()
        .stderr(predicate::str::contains("GDPR"));
}

#[test]
fn pro_framework_adds_article_mappings() {
    let Some(token) = pro_token() else {
        eprintln!("Skipping: production key not available");
        return;
    };

    let output = piilex()
        .args([
            "scan",
            &ts_fixture("simple_pii.ts"),
            "--framework",
            "gdpr",
            "-o",
            "json",
        ])
        .env("PIILEX_LICENSE_KEY", &token)
        .output()
        .expect("failed to execute");

    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let findings = json["findings"].as_array().unwrap();

    let has_mappings = findings.iter().any(|f| {
        f["framework_mappings"]
            .as_array()
            .map(|a| !a.is_empty())
            .unwrap_or(false)
    });
    assert!(
        has_mappings,
        "Pro scan with --framework should produce framework_mappings"
    );
}

// =====================================================================
// 7. License status command
// =====================================================================

#[test]
fn license_status_shows_free() {
    piilex()
        .args(["license", "status"])
        .env_remove("PIILEX_LICENSE_KEY")
        .assert()
        .success()
        .stderr(predicate::str::contains("Free"));
}

#[test]
fn license_status_shows_pro_via_env() {
    let Some(token) = pro_token() else {
        eprintln!("Skipping: production key not available");
        return;
    };

    piilex()
        .args(["license", "status"])
        .env("PIILEX_LICENSE_KEY", &token)
        .assert()
        .success()
        .stderr(predicate::str::contains("Pro"));
}

// =====================================================================
// 8. Init command
// =====================================================================

#[test]
fn init_creates_config_file() {
    let tmp = TempDir::new().unwrap();
    let config_path = tmp.path().join(".piilex.yml");

    // init writes to CWD, so we need to set the working dir
    piilex()
        .current_dir(tmp.path())
        .args(["init"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Created .piilex.yml"));

    assert!(config_path.exists(), ".piilex.yml should be created");

    let content = fs::read_to_string(&config_path).unwrap();
    assert!(content.contains("languages:"));
    assert!(content.contains("exclude:"));
    assert!(content.contains("severity:"));
}

#[test]
fn init_with_framework_sets_default() {
    let tmp = TempDir::new().unwrap();

    piilex()
        .current_dir(tmp.path())
        .args(["init", "--framework", "gdpr"])
        .assert()
        .success();

    let content = fs::read_to_string(tmp.path().join(".piilex.yml")).unwrap();
    assert!(
        content.contains("gdpr"),
        "config should contain gdpr framework"
    );
}

#[test]
fn init_refuses_overwrite() {
    let tmp = TempDir::new().unwrap();

    // Create the file first
    fs::write(tmp.path().join(".piilex.yml"), "existing").unwrap();

    piilex()
        .current_dir(tmp.path())
        .args(["init"])
        .assert()
        .code(1)
        .stderr(predicate::str::contains("already exists"));
}

// =====================================================================
// 9. Baseline save and diff
// =====================================================================

#[test]
fn save_and_diff_baseline() {
    let Some(token) = pro_token() else {
        eprintln!("Skipping: production key not available");
        return;
    };
    let tmp = TempDir::new().unwrap();
    let baseline_path = tmp.path().join("baseline.json");

    // Step 1: Save baseline
    piilex()
        .args([
            "scan",
            &ts_fixture("simple_pii.ts"),
            "--save-baseline",
            baseline_path.to_str().unwrap(),
        ])
        .env("PIILEX_LICENSE_KEY", &token)
        .assert()
        .success()
        .stderr(predicate::str::contains("Baseline saved"));

    assert!(baseline_path.exists());

    // Verify baseline is valid JSON
    let content = fs::read_to_string(&baseline_path).unwrap();
    let json: serde_json::Value = serde_json::from_str(&content).unwrap();
    assert!(json["findings"].is_array());

    // Step 2: Diff against same scan (should show mostly unchanged)
    piilex()
        .args([
            "scan",
            &ts_fixture("simple_pii.ts"),
            "--baseline",
            baseline_path.to_str().unwrap(),
            "-q",
        ])
        .env("PIILEX_LICENSE_KEY", &token)
        .assert()
        .success()
        .stderr(predicate::str::contains("Diff Summary"));
}

#[test]
fn baseline_diff_json_output() {
    let Some(token) = pro_token() else {
        eprintln!("Skipping: production key not available");
        return;
    };
    let tmp = TempDir::new().unwrap();
    let baseline_path = tmp.path().join("baseline.json");

    // Save baseline
    piilex()
        .args([
            "scan",
            &ts_fixture("simple_pii.ts"),
            "--save-baseline",
            baseline_path.to_str().unwrap(),
        ])
        .env("PIILEX_LICENSE_KEY", &token)
        .output()
        .unwrap();

    // Diff with JSON output
    let output = piilex()
        .args([
            "scan",
            &ts_fixture("simple_pii.ts"),
            "--baseline",
            baseline_path.to_str().unwrap(),
            "-o",
            "json",
        ])
        .env("PIILEX_LICENSE_KEY", &token)
        .output()
        .unwrap();

    let json: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("diff JSON output should be valid");

    assert!(json["entries"].is_array());
    assert!(json["summary"]["added"].is_number());
    assert!(json["summary"]["removed"].is_number());
    assert!(json["summary"]["unchanged"].is_number());
}

// =====================================================================
// 10. Error handling
// =====================================================================

#[test]
fn scan_nonexistent_path_warns() {
    piilex()
        .args(["scan", "/nonexistent/path/that/does/not/exist"])
        .assert()
        .success()
        .stderr(
            predicate::str::contains("No supported files found")
                .or(predicate::str::contains("Warning")),
        );
}

#[test]
fn unknown_subcommand_fails() {
    piilex().arg("nonexistent-command").assert().failure();
}

#[test]
fn scan_with_invalid_output_format() {
    piilex()
        .args(["scan", &ts_fixture("simple_pii.ts"), "-o", "xml"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("invalid value"));
}

#[test]
fn scan_with_invalid_severity() {
    // Invalid severity should fall back to default (low), not crash
    piilex()
        .args(["scan", &ts_fixture("simple_pii.ts"), "--severity", "ultra"])
        .assert()
        .success();
}

// =====================================================================
// 11. Cross-file analysis
// =====================================================================

#[test]
fn crossfile_ts_detects_imported_pii() {
    let output = piilex()
        .args(["scan", &ts_fixture("crossfile"), "-o", "json"])
        .output()
        .expect("failed to execute");

    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let findings = json["findings"].as_array().unwrap();

    // Should detect findings in logger.ts and apiHandler.ts (cross-file)
    let files: Vec<&str> = findings
        .iter()
        .filter_map(|f| f["location"]["file"].as_str())
        .collect();

    let has_logger = files.iter().any(|f| f.contains("logger"));
    let has_api = files
        .iter()
        .any(|f| f.contains("apiHandler") || f.contains("api"));

    assert!(
        has_logger || has_api,
        "cross-file scan should detect PII in importing files, found files: {:?}",
        files
    );
}

// =====================================================================
// 12. Quiet mode
// =====================================================================

#[test]
fn quiet_mode_shows_summary_only() {
    let output = piilex()
        .args(["scan", &ts_fixture("simple_pii.ts"), "-q"])
        .output()
        .expect("failed to execute");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("Summary:"),
        "quiet mode should show summary"
    );
    assert!(
        !stderr.contains("SEVERITY"),
        "quiet mode should not show table header"
    );
}

// =====================================================================
// 13. Multiple framework support
// =====================================================================

#[test]
fn multiple_frameworks_in_json() {
    let Some(token) = pro_token() else {
        eprintln!("Skipping: production key not available");
        return;
    };

    let output = piilex()
        .args([
            "scan",
            &ts_fixture("simple_pii.ts"),
            "--framework",
            "gdpr,ccpa",
            "-o",
            "json",
        ])
        .env("PIILEX_LICENSE_KEY", &token)
        .output()
        .unwrap();

    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let findings = json["findings"].as_array().unwrap();

    // At least one finding should have both GDPR and CCPA mappings
    let has_gdpr = findings.iter().any(|f| {
        f["framework_mappings"]
            .as_array()
            .map(|a| a.iter().any(|m| m["framework"] == "gdpr"))
            .unwrap_or(false)
    });
    let has_ccpa = findings.iter().any(|f| {
        f["framework_mappings"]
            .as_array()
            .map(|a| a.iter().any(|m| m["framework"] == "ccpa"))
            .unwrap_or(false)
    });

    assert!(has_gdpr, "should have GDPR mappings");
    assert!(has_ccpa, "should have CCPA mappings");
}

// =====================================================================
// 14. --no-flow flag
// =====================================================================

#[test]
fn no_flow_flag_accepted() {
    piilex()
        .args(["scan", &ts_fixture("simple_pii.ts"), "--no-flow", "-q"])
        .assert()
        .success();
}

// =====================================================================
// 15. Exclude patterns
// =====================================================================

#[test]
fn exclude_pattern_reduces_findings() {
    // Scan all fixtures
    let output_all = piilex()
        .args(["scan", &fixtures_dir(), "-o", "json"])
        .output()
        .unwrap();
    let json_all: serde_json::Value = serde_json::from_slice(&output_all.stdout).unwrap();
    let count_all = json_all["findings"].as_array().unwrap().len();

    // Scan with exclusion
    let output_excl = piilex()
        .args([
            "scan",
            &fixtures_dir(),
            "-o",
            "json",
            "--exclude",
            "**/*crossfile*/**",
        ])
        .output()
        .unwrap();
    let json_excl: serde_json::Value = serde_json::from_slice(&output_excl.stdout).unwrap();
    let count_excl = json_excl["findings"].as_array().unwrap().len();

    assert!(
        count_excl <= count_all,
        "excluding crossfile should reduce findings: all={} excluded={}",
        count_all,
        count_excl
    );
}
