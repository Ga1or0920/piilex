use crate::finding::{Confidence, Finding, PiiCategory, SourceLocation};
use crate::parser::ParsedFile;
use crate::pii::patterns::builtin_literal_patterns;
use crate::severity::Severity;

pub struct LiteralDetector;

impl Default for LiteralDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl LiteralDetector {
    pub fn new() -> Self {
        Self
    }

    pub fn detect(&self, file: &ParsedFile) -> Vec<Finding> {
        let patterns = builtin_literal_patterns();
        let mut findings = Vec::new();

        for lit in &file.string_literals {
            for pattern in &patterns {
                if pattern.regex.is_match(&lit.value) {
                    let line_content = file
                        .source
                        .lines()
                        .nth(lit.line.saturating_sub(1))
                        .unwrap_or("")
                        .trim()
                        .to_string();

                    findings.push(Finding {
                        id: format!("PII-LIT-{:03}", findings.len() + 1),
                        severity: Severity::Medium,
                        pii_type: pattern.pii_type.clone(),
                        category: PiiCategory::ContactInfo,
                        location: SourceLocation {
                            file: file.path.clone(),
                            line: lit.line,
                            column: lit.column,
                        },
                        code_snippet: line_content,
                        data_flow: None,
                        framework_mappings: Vec::new(),
                        confidence: Confidence::Medium,
                    });

                    break; // One match per literal is sufficient
                }
            }
        }

        findings
    }
}
