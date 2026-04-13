use crate::finding::Framework;
use crate::severity::Severity;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Config {
    #[serde(default)]
    pub scan: ScanConfig,
    #[serde(default)]
    pub frameworks: Vec<Framework>,
    #[serde(default)]
    pub severity: SeverityConfig,
    #[serde(default)]
    pub rules: RulesConfig,
    #[serde(default)]
    pub pii_types: PiiTypesConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanConfig {
    #[serde(default = "default_languages")]
    pub languages: Vec<String>,
    #[serde(default = "default_excludes")]
    pub exclude: Vec<String>,
    #[serde(default)]
    pub include: Vec<String>,
    #[serde(default = "default_max_file_size")]
    pub max_file_size: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SeverityConfig {
    #[serde(default = "default_fail_on")]
    pub fail_on: Severity,
    #[serde(default = "default_min_display")]
    pub min_display: Severity,
}

// ---------------------------------------------------------------------------
// Rules: custom sinks, allow/deny, exceptions
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RulesConfig {
    /// Paths where PII in logs is allowed (audit log sinks, etc.)
    #[serde(default)]
    pub allow_log: Vec<String>,

    /// Finding IDs or patterns to suppress permanently
    #[serde(default)]
    pub ignore_findings: Vec<String>,

    /// Custom sink definitions (extend built-in log/db/api/response sinks)
    #[serde(default)]
    pub custom_sinks: Vec<CustomSink>,

    /// Allow-list: identifiers that should never be flagged as PII
    #[serde(default)]
    pub allow_identifiers: Vec<String>,

    /// Deny-list: identifiers that should always be flagged (force detection)
    #[serde(default)]
    pub deny_identifiers: Vec<DenyRule>,

    /// Path-based exceptions: skip scanning for certain directories/patterns
    #[serde(default)]
    pub exceptions: Vec<ExceptionRule>,
}

/// A custom sink pattern: callee name/regex mapped to a sink type.
///
/// ```yaml
/// rules:
///   custom_sinks:
///     - pattern: "analyticsClient.track"
///       kind: third_party_api
///     - pattern: "auditLog.*"
///       kind: log_output
///       allowed: true   # suppress findings for this sink
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomSink {
    /// Regex or literal pattern matching the callee (e.g., "myLogger.send")
    pub pattern: String,
    /// Sink kind: log_output, database, third_party_api, response, file_system
    pub kind: String,
    /// If true, findings flowing to this sink are suppressed
    #[serde(default)]
    pub allowed: bool,
}

/// Force-flag an identifier as PII, overriding the dictionary.
///
/// ```yaml
/// rules:
///   deny_identifiers:
///     - pattern: "(?i)^customer[-_]?ref$"
///       pii_type: national_id
///       severity: critical
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DenyRule {
    /// Regex pattern matching the identifier
    pub pattern: String,
    /// PII type to assign (e.g., "email", "national_id", or custom)
    #[serde(default = "default_deny_pii_type")]
    pub pii_type: String,
    /// Severity override
    #[serde(default)]
    pub severity: Option<String>,
}

fn default_deny_pii_type() -> String {
    "custom".to_string()
}

/// Path-based exception: skip or modify scanning for matching paths.
///
/// ```yaml
/// rules:
///   exceptions:
///     - paths: ["generated/**", "proto/**"]
///       action: skip
///     - paths: ["**/migrations/**"]
///       action: skip
///     - paths: ["**/test/**", "**/__tests__/**"]
///       action: reduce_severity
///       max_severity: medium
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExceptionRule {
    /// Glob patterns for file paths
    pub paths: Vec<String>,
    /// Action: "skip" (no scan), "reduce_severity", "suppress_low"
    #[serde(default = "default_exception_action")]
    pub action: String,
    /// For "reduce_severity": cap findings at this level
    #[serde(default)]
    pub max_severity: Option<String>,
}

fn default_exception_action() -> String {
    "skip".to_string()
}

// ---------------------------------------------------------------------------
// PII types config
// ---------------------------------------------------------------------------

/// A user-defined custom PII type from .piilex.yml.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomPiiType {
    pub name: String,
    pub patterns: Vec<String>,
    #[serde(default)]
    pub severity: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PiiTypesConfig {
    #[serde(default)]
    pub custom: Vec<CustomPiiType>,
    #[serde(default)]
    pub ignore: Vec<String>,
}

// ---------------------------------------------------------------------------
// Defaults
// ---------------------------------------------------------------------------

fn default_languages() -> Vec<String> {
    vec!["typescript".into(), "javascript".into(), "python".into()]
}

fn default_excludes() -> Vec<String> {
    vec![
        "node_modules/**".into(),
        "**/*.test.ts".into(),
        "**/*.test.js".into(),
        "**/*.spec.ts".into(),
        "**/*.spec.js".into(),
        "**/test_*.py".into(),
        "**/*_test.py".into(),
        "dist/**".into(),
        "build/**".into(),
        ".git/**".into(),
        "__pycache__/**".into(),
        "*.min.js".into(),
    ]
}

fn default_max_file_size() -> usize {
    1_048_576
}

fn default_fail_on() -> Severity {
    Severity::High
}

fn default_min_display() -> Severity {
    Severity::Low
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            languages: default_languages(),
            exclude: default_excludes(),
            include: Vec::new(),
            max_file_size: default_max_file_size(),
        }
    }
}

impl Default for SeverityConfig {
    fn default() -> Self {
        Self {
            fail_on: default_fail_on(),
            min_display: default_min_display(),
        }
    }
}

impl Config {
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        if !path.exists() {
            return Ok(Config::default());
        }
        let content =
            std::fs::read_to_string(path).map_err(|e| ConfigError::Io(path.to_path_buf(), e))?;
        let config: Config = serde_yaml_ng::from_str(&content)
            .map_err(|e| ConfigError::Parse(path.to_path_buf(), e.to_string()))?;
        Ok(config)
    }

    pub fn default_config_yaml() -> &'static str {
        r#"# piilex configuration
version: "1"

scan:
  languages: [typescript, javascript, python]
  exclude:
    - "node_modules/**"
    - "**/*.test.ts"
    - "**/*.spec.ts"
    - "dist/**"
    - "build/**"
    - ".git/**"
    - "__pycache__/**"

frameworks: []
  # - gdpr
  # - ccpa
  # - appi

severity:
  fail_on: high
  min_display: low

rules:
  allow_log: []
  ignore_findings: []

  # Custom sink patterns (extend built-in detection)
  # custom_sinks:
  #   - pattern: "analyticsClient.track"
  #     kind: third_party_api
  #   - pattern: "auditLog.write"
  #     kind: log_output
  #     allowed: true    # suppress findings for audit logs

  # Identifiers that should never be flagged as PII
  # allow_identifiers:
  #   - "email_count"
  #   - "phone_validator"

  # Force-flag identifiers as PII (override dictionary)
  # deny_identifiers:
  #   - pattern: "(?i)^customer[-_]?ref$"
  #     pii_type: national_id
  #     severity: critical

  # Path-based exceptions
  # exceptions:
  #   - paths: ["generated/**", "proto/**"]
  #     action: skip
  #   - paths: ["**/test/**"]
  #     action: reduce_severity
  #     max_severity: medium

# pii_types:
#   custom:
#     - name: loyalty_card
#       patterns:
#         - "(?i)^loyalty[-_]?(card|id|number)$"
#       severity: high
#   ignore: []
"#
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("failed to read config file {0}: {1}")]
    Io(PathBuf, std::io::Error),
    #[error("failed to parse config file {0}: {1}")]
    Parse(PathBuf, String),
}
