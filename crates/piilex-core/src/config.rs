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

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RulesConfig {
    #[serde(default)]
    pub allow_log: Vec<String>,
    #[serde(default)]
    pub ignore_findings: Vec<String>,
}

/// A user-defined custom PII type from .piilex.yml.
///
/// Example in config:
/// ```yaml
/// pii_types:
///   custom:
///     - name: loyalty_card
///       patterns:
///         - "(?i)^loyalty[-_]?(card|id|number)$"
///       severity: high
/// ```
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
    1_048_576 // 1 MB
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
        let config: Config = serde_yml::from_str(&content)
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

severity:
  fail_on: high
  min_display: low

rules:
  allow_log: []
  ignore_findings: []

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
