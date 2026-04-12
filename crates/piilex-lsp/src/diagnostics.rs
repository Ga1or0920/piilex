use lsp_types::{
    CodeAction, CodeActionKind, Diagnostic, DiagnosticSeverity, NumberOrString, Position, Range,
    TextEdit, Uri, WorkspaceEdit,
};
use piilex_core::config::Config;
use piilex_core::detector::DetectorPipeline;
use piilex_core::discovery::detect_language;
use piilex_core::finding::Finding;
use piilex_core::parser::parse_file;
use piilex_core::severity::Severity;
use piilex_core::suggest::generate_suggestion_from_snippet;
use std::collections::HashMap;
use std::path::Path;

/// Analyze a single document and return LSP diagnostics.
pub fn diagnose_document(uri: &Uri, text: &str) -> Vec<Diagnostic> {
    let path_str = uri.as_str();
    // Strip file:// prefix for path detection
    let clean_path = path_str
        .strip_prefix("file:///")
        .or_else(|| path_str.strip_prefix("file://"))
        .unwrap_or(path_str);
    let path = Path::new(clean_path);

    let language = match detect_language(path) {
        Some(l) => l,
        None => return vec![],
    };

    let config = Config::default();
    let pipeline = DetectorPipeline::new();
    let parsed = parse_file(path, text, language);
    let findings = pipeline.analyze(&parsed, &config);

    findings.iter().filter_map(finding_to_diagnostic).collect()
}

fn finding_to_diagnostic(finding: &Finding) -> Option<Diagnostic> {
    let line = finding.location.line.saturating_sub(1) as u32;
    let col = finding.location.column.saturating_sub(1) as u32;
    let end_col = col + finding.code_snippet.trim().len().min(80) as u32;

    let severity = match finding.severity {
        Severity::Critical => DiagnosticSeverity::ERROR,
        Severity::High => DiagnosticSeverity::WARNING,
        Severity::Medium => DiagnosticSeverity::INFORMATION,
        Severity::Low => DiagnosticSeverity::HINT,
    };

    let flow_info = finding
        .data_flow
        .as_ref()
        .map(|df| {
            format!(
                " (flow: {} -> {})",
                df.source.kind.as_str(),
                df.sink.kind.as_str()
            )
        })
        .unwrap_or_default();

    Some(Diagnostic {
        range: Range {
            start: Position::new(line, col),
            end: Position::new(line, end_col),
        },
        severity: Some(severity),
        code: Some(NumberOrString::String(format!(
            "piilex/{}",
            finding.pii_type.as_str()
        ))),
        code_description: None,
        source: Some("piilex".to_string()),
        message: format!(
            "PII detected: {} ({}){}",
            finding.pii_type.as_str(),
            finding.category.as_str(),
            flow_info,
        ),
        related_information: None,
        tags: None,
        data: Some(serde_json::to_value(&finding.id).unwrap_or_default()),
    })
}

/// Generate code actions (quick fixes) for diagnostics at a given position.
pub fn code_actions_for_diagnostics(
    uri: &Uri,
    text: &str,
    diagnostics: &[Diagnostic],
) -> Vec<CodeAction> {
    let path_str = uri.as_str();
    let clean_path = path_str
        .strip_prefix("file:///")
        .or_else(|| path_str.strip_prefix("file://"))
        .unwrap_or(path_str);
    let path = Path::new(clean_path);

    let language = match detect_language(path) {
        Some(l) => l,
        None => return vec![],
    };

    let config = Config::default();
    let pipeline = DetectorPipeline::new();
    let parsed = parse_file(path, text, language);
    let findings = pipeline.analyze(&parsed, &config);

    let mut actions = Vec::new();

    for diag in diagnostics {
        let line = diag.range.start.line as usize + 1;

        let matching = findings.iter().find(|f| f.location.line == line);

        if let Some(finding) = matching {
            if let Some(suggestion) = generate_suggestion_from_snippet(finding) {
                let edit = TextEdit {
                    range: Range {
                        start: Position::new(diag.range.start.line, 0),
                        end: Position::new(diag.range.end.line, diag.range.end.character),
                    },
                    new_text: suggestion.replacement_line.clone(),
                };

                let mut changes = HashMap::new();
                changes.insert(uri.clone(), vec![edit]);

                actions.push(CodeAction {
                    title: format!("Fix: {}", suggestion.description),
                    kind: Some(CodeActionKind::QUICKFIX),
                    diagnostics: Some(vec![diag.clone()]),
                    edit: Some(WorkspaceEdit {
                        changes: Some(changes),
                        ..Default::default()
                    }),
                    ..Default::default()
                });
            }
        }
    }

    actions
}
