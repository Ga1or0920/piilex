use crate::finding::{Confidence, Finding, SourceLocation};
use crate::parser::ParsedFile;
use crate::pii::dictionary::PiiDictionary;
use std::sync::atomic::{AtomicUsize, Ordering};

static FINDING_COUNTER: AtomicUsize = AtomicUsize::new(0);

fn next_finding_id() -> String {
    let n = FINDING_COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("PII-{:03}", n + 1)
}

pub fn reset_finding_counter() {
    FINDING_COUNTER.store(0, Ordering::Relaxed);
}

pub struct IdentifierDetector {
    dictionary: PiiDictionary,
}

impl Default for IdentifierDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl IdentifierDetector {
    pub fn new() -> Self {
        Self {
            dictionary: PiiDictionary::builtin(),
        }
    }

    pub fn load_custom(&mut self, custom_types: &[crate::config::CustomPiiType]) {
        self.dictionary.load_custom(custom_types);
    }

    pub fn detect(&self, file: &ParsedFile) -> Vec<Finding> {
        let mut findings = Vec::new();
        let is_test_file = is_test_context(&file.path, &file.source);

        for ident in &file.identifiers {
            // Skip common non-PII identifiers
            if is_safe_identifier(&ident.name) {
                continue;
            }

            if let Some(pii_match) = self.dictionary.match_identifier(&ident.name) {
                // Skip low-confidence matches in test files
                if is_test_file && pii_match.confidence == Confidence::Low {
                    continue;
                }

                let line_content = file
                    .source
                    .lines()
                    .nth(ident.line.saturating_sub(1))
                    .unwrap_or("")
                    .trim()
                    .to_string();

                // Skip findings in example/dummy data contexts
                if is_example_context(&line_content) {
                    continue;
                }

                findings.push(Finding {
                    id: next_finding_id(),
                    severity: pii_match.severity,
                    pii_type: pii_match.pii_type,
                    category: pii_match.category,
                    location: SourceLocation {
                        file: file.path.clone(),
                        line: ident.line,
                        column: ident.column,
                    },
                    code_snippet: line_content,
                    data_flow: None,
                    framework_mappings: Vec::new(),
                    confidence: pii_match.confidence,
                });
            }
        }

        findings
    }
}

/// Check if an identifier is a common programming term that should never be PII.
fn is_safe_identifier(name: &str) -> bool {
    let lower = name.to_lowercase();
    matches!(
        lower.as_str(),
        // Common method names that contain PII-like substrings
        "writeline"
            | "readline"
            | "deadline"
            | "pipeline"
            | "streamline"
            | "guideline"
            | "baseline"
            | "timeline"
            | "outline"
            | "online"
            | "offline"
            | "hotline"
            | "byline"
            | "headline"
            | "getline"
            | "cmdline"
            // Common programming terms
            | "telephone"  // as a class/module name, handled by High patterns
            | "controller"
            | "selector"
            | "delegate"
            | "template"
            | "throttle"
            | "channel"
            | "handler"
            | "listener"
            | "formatter"
            | "dispatcher"
            // Generic counter/flag names
            | "count"
            | "counter"
            | "total"
            | "length"
            | "size"
            | "index"
            | "offset"
    )
}

/// Check if a file is in a test context (test files, fixture files, etc.)
fn is_test_context(path: &std::path::Path, _source: &str) -> bool {
    let path_str = path.to_string_lossy().to_lowercase();
    path_str.contains("test")
        || path_str.contains("spec")
        || path_str.contains("fixture")
        || path_str.contains("mock")
        || path_str.contains("fake")
        || path_str.contains("stub")
        || path_str.contains("__tests__")
        || path_str.contains("__mocks__")
}

/// Check if a line contains example/dummy data patterns.
fn is_example_context(line: &str) -> bool {
    let lower = line.to_lowercase();
    // Common example/placeholder patterns
    lower.contains("example.com")
        && (lower.contains("\"test") || lower.contains("\"user@") || lower.contains("\"demo"))
        || lower.contains("// example")
        || lower.contains("# example")
        || lower.contains("// dummy")
        || lower.contains("# dummy")
        || lower.contains("// placeholder")
        || lower.contains("// mock")
        || lower.contains("todo!")
}
