use crate::finding::{Finding, SourceLocation};
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

        for ident in &file.identifiers {
            if let Some(pii_match) = self.dictionary.match_identifier(&ident.name) {
                let line_content = file
                    .source
                    .lines()
                    .nth(ident.line.saturating_sub(1))
                    .unwrap_or("")
                    .trim()
                    .to_string();

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
