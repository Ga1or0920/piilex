use crate::finding::{Finding, FlowNodeKind, PiiType};
use std::path::Path;

/// A concrete patch suggestion with real source lines.
#[derive(Debug, Clone)]
pub struct Suggestion {
    pub finding_id: String,
    pub file: String,
    pub line: usize,
    pub description: String,
    /// The original line from the source file.
    pub original_line: String,
    /// The proposed replacement line.
    pub replacement_line: String,
    /// Unified diff fragment (file header + hunk).
    pub unified_diff: String,
}

/// Context needed to generate real diffs.
#[derive(Default)]
pub struct SuggestContext {
    pub project_root: Option<String>,
}

/// Generate a concrete patch for a finding by reading the actual source file.
pub fn generate_suggestion(finding: &Finding, ctx: &SuggestContext) -> Option<Suggestion> {
    let file_path = resolve_file_path(finding, ctx)?;
    let source = std::fs::read_to_string(&file_path).ok()?;
    let lines: Vec<&str> = source.lines().collect();

    if finding.location.line == 0 || finding.location.line > lines.len() {
        return None;
    }

    let line_idx = finding.location.line - 1;
    let original = lines[line_idx];

    let sink_kind = finding.data_flow.as_ref().map(|df| df.sink.kind);
    let pii_name = &finding.pii_type;

    let (description, replacement) = match sink_kind {
        Some(FlowNodeKind::LogOutput) => generate_log_patch(original, pii_name),
        Some(FlowNodeKind::Response) => generate_response_patch(original, pii_name),
        Some(FlowNodeKind::Database) => generate_db_patch(original, pii_name),
        Some(FlowNodeKind::ThirdPartyApi) => generate_api_patch(original, pii_name),
        _ => generate_generic_patch(original, pii_name),
    };

    let file_display = finding.location.file.display().to_string();
    let unified = format_unified_diff(&file_display, finding.location.line, original, &replacement);

    Some(Suggestion {
        finding_id: finding.id.clone(),
        file: file_display,
        line: finding.location.line,
        description,
        original_line: original.to_string(),
        replacement_line: replacement,
        unified_diff: unified,
    })
}

/// Generate a suggestion without reading the file (uses code_snippet from finding).
/// Fallback for when the source file is not accessible.
pub fn generate_suggestion_from_snippet(finding: &Finding) -> Option<Suggestion> {
    let original = finding.code_snippet.as_str();
    if original.is_empty() {
        return None;
    }

    let sink_kind = finding.data_flow.as_ref().map(|df| df.sink.kind);
    let pii_name = &finding.pii_type;

    let (description, replacement) = match sink_kind {
        Some(FlowNodeKind::LogOutput) => generate_log_patch(original, pii_name),
        Some(FlowNodeKind::Response) => generate_response_patch(original, pii_name),
        Some(FlowNodeKind::Database) => generate_db_patch(original, pii_name),
        Some(FlowNodeKind::ThirdPartyApi) => generate_api_patch(original, pii_name),
        _ => generate_generic_patch(original, pii_name),
    };

    let file_display = finding.location.file.display().to_string();
    let unified = format_unified_diff(&file_display, finding.location.line, original, &replacement);

    Some(Suggestion {
        finding_id: finding.id.clone(),
        file: file_display,
        line: finding.location.line,
        description,
        original_line: original.to_string(),
        replacement_line: replacement,
        unified_diff: unified,
    })
}

// ---------------------------------------------------------------------------
// Patch generators — return (description, replacement_line)
// ---------------------------------------------------------------------------

fn generate_log_patch(original: &str, pii_type: &PiiType) -> (String, String) {
    let mask_fn = mask_function_name(pii_type);
    let pii_var = extract_pii_expression(original, pii_type);
    let indent = leading_whitespace(original);

    let replacement = if let Some(var) = &pii_var {
        // Replace the PII variable with a masked version in the log call
        let masked = format!("{}({})", mask_fn, var);
        original.replace(var.as_str(), &masked)
    } else {
        // Can't identify the exact variable; wrap the whole argument
        format!(
            "{}// TODO: mask PII ({}) before logging",
            indent,
            pii_type.as_str()
        )
    };

    (
        format!(
            "Mask {} before logging to prevent PII leakage",
            pii_type.as_str()
        ),
        replacement,
    )
}

fn generate_response_patch(original: &str, pii_type: &PiiType) -> (String, String) {
    let pii_var = extract_pii_expression(original, pii_type);
    let indent = leading_whitespace(original);

    let replacement = if let Some(var) = &pii_var {
        let redacted = "\"[REDACTED]\"".to_string();
        original.replace(var.as_str(), &redacted)
    } else {
        format!(
            "{}// TODO: redact {} from response",
            indent,
            pii_type.as_str()
        )
    };

    (
        format!("Redact {} from API response payload", pii_type.as_str()),
        replacement,
    )
}

fn generate_db_patch(original: &str, pii_type: &PiiType) -> (String, String) {
    let pii_var = extract_pii_expression(original, pii_type);
    let indent = leading_whitespace(original);

    let replacement = if let Some(var) = &pii_var {
        let encrypted = format!("encrypt({})", var);
        original.replace(var.as_str(), &encrypted)
    } else {
        format!(
            "{}// TODO: encrypt {} before database storage",
            indent,
            pii_type.as_str()
        )
    };

    (
        format!("Encrypt {} before storing in database", pii_type.as_str()),
        replacement,
    )
}

fn generate_api_patch(original: &str, pii_type: &PiiType) -> (String, String) {
    let pii_var = extract_pii_expression(original, pii_type);
    let indent = leading_whitespace(original);

    let replacement = if let Some(var) = &pii_var {
        let masked = format!("{}({})", mask_function_name(pii_type), var);
        original.replace(var.as_str(), &masked)
    } else {
        format!(
            "{}// TODO: mask or remove {} before sending to third-party API",
            indent,
            pii_type.as_str()
        )
    };

    (
        format!(
            "Mask {} before sending to third-party API",
            pii_type.as_str()
        ),
        replacement,
    )
}

fn generate_generic_patch(original: &str, pii_type: &PiiType) -> (String, String) {
    let indent = leading_whitespace(original);
    let replacement = format!(
        "{}// TODO: review handling of {} — ensure encryption at rest, minimize collection",
        indent,
        pii_type.as_str()
    );

    (
        format!(
            "Review handling of {} to ensure compliance",
            pii_type.as_str()
        ),
        replacement,
    )
}

// ---------------------------------------------------------------------------
// Unified diff formatting
// ---------------------------------------------------------------------------

fn format_unified_diff(
    file_path: &str,
    line_number: usize,
    original: &str,
    replacement: &str,
) -> String {
    let mut out = String::new();
    // File headers
    out.push_str(&format!("--- a/{}\n", file_path));
    out.push_str(&format!("+++ b/{}\n", file_path));
    // Hunk header
    out.push_str(&format!("@@ -{0},1 +{0},1 @@\n", line_number));
    // Lines
    out.push_str(&format!("-{}\n", original));
    out.push_str(&format!("+{}\n", replacement));
    out
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn resolve_file_path(finding: &Finding, ctx: &SuggestContext) -> Option<std::path::PathBuf> {
    let p = &finding.location.file;
    if p.is_absolute() && p.exists() {
        return Some(p.clone());
    }
    if let Some(root) = &ctx.project_root {
        let abs = Path::new(root).join(p);
        if abs.exists() {
            return Some(abs);
        }
    }
    // Try relative to CWD
    let cwd = std::env::current_dir().ok()?;
    let abs = cwd.join(p);
    if abs.exists() {
        return Some(abs);
    }
    None
}

/// Try to extract the PII-bearing expression from the source line.
fn extract_pii_expression(line: &str, pii_type: &PiiType) -> Option<String> {
    use regex::Regex;
    use std::sync::LazyLock;

    // Match member access: obj.email, user.phone_number, etc.
    static MEMBER: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"\b(\w+\.\w+(?:\.\w+)*)").unwrap());

    let pii_str = pii_type.as_str();

    // Look for member access patterns containing the PII name
    for cap in MEMBER.captures_iter(line) {
        let full = cap.get(1)?.as_str();
        let last_part = full.rsplit('.').next().unwrap_or("");
        if matches_pii_name(last_part, pii_str) {
            return Some(full.to_string());
        }
    }

    // Look for standalone variable matching the PII name
    static IDENT: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\b(\w+)\b").unwrap());

    for cap in IDENT.captures_iter(line) {
        let name = cap.get(1)?.as_str();
        if matches_pii_name(name, pii_str) {
            return Some(name.to_string());
        }
    }

    None
}

fn matches_pii_name(identifier: &str, pii_type_str: &str) -> bool {
    let lower = identifier.to_lowercase();
    let pii_lower = pii_type_str.to_lowercase();
    // Direct match or camelCase/snake_case variant
    lower == pii_lower
        || lower == pii_lower.replace('_', "")
        || lower.contains(&pii_lower)
        || lower.contains(&pii_lower.replace('_', ""))
}

fn leading_whitespace(line: &str) -> &str {
    let trimmed = line.trim_start();
    &line[..line.len() - trimmed.len()]
}

fn mask_function_name(pii_type: &PiiType) -> &'static str {
    match pii_type {
        PiiType::Email => "maskEmail",
        PiiType::PhoneNumber => "maskPhone",
        PiiType::CreditCard => "maskCreditCard",
        PiiType::IpAddress => "maskIpAddress",
        PiiType::FullName | PiiType::FirstName | PiiType::LastName => "maskName",
        PiiType::NationalId | PiiType::MyNumber | PiiType::Bsn | PiiType::Nhs => "maskId",
        PiiType::Iban | PiiType::BankAccount => "maskAccount",
        PiiType::Password | PiiType::ApiKey | PiiType::SecretKey | PiiType::PrivateKey => "redact",
        _ => "maskPii",
    }
}

/// Apply a suggestion to a file, replacing the original line.
/// Returns Ok(true) if applied, Ok(false) if line didn't match.
pub fn apply_suggestion(suggestion: &Suggestion) -> Result<bool, std::io::Error> {
    let path = Path::new(&suggestion.file);
    if !path.exists() {
        return Ok(false);
    }

    let content = std::fs::read_to_string(path)?;
    let lines: Vec<&str> = content.lines().collect();

    if suggestion.line == 0 || suggestion.line > lines.len() {
        return Ok(false);
    }

    let line_idx = suggestion.line - 1;

    // Verify the line still matches (guard against stale suggestions)
    if lines[line_idx].trim() != suggestion.original_line.trim() {
        return Ok(false);
    }

    // Build the new file content
    let mut new_lines: Vec<String> = lines.iter().map(|l| l.to_string()).collect();
    new_lines[line_idx] = suggestion.replacement_line.clone();

    let new_content = new_lines.join("\n");
    // Preserve trailing newline if original had one
    let new_content = if content.ends_with('\n') {
        format!("{}\n", new_content)
    } else {
        new_content
    };

    std::fs::write(path, new_content)?;
    Ok(true)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finding::*;

    fn make_log_finding(snippet: &str) -> Finding {
        Finding {
            id: "PII-001".into(),
            severity: crate::severity::Severity::High,
            pii_type: PiiType::Email,
            category: PiiCategory::ContactInfo,
            location: SourceLocation {
                file: "src/test.ts".into(),
                line: 5,
                column: 1,
            },
            code_snippet: snippet.into(),
            data_flow: Some(DataFlow {
                source: DataFlowNode {
                    kind: FlowNodeKind::UserInput,
                    label: "email".into(),
                    location: SourceLocation {
                        file: "src/test.ts".into(),
                        line: 1,
                        column: 1,
                    },
                },
                sink: DataFlowNode {
                    kind: FlowNodeKind::LogOutput,
                    label: "console.log".into(),
                    location: SourceLocation {
                        file: "src/test.ts".into(),
                        line: 5,
                        column: 1,
                    },
                },
                path: vec![],
            }),
            framework_mappings: vec![],
            confidence: Confidence::High,
        }
    }

    #[test]
    fn log_patch_replaces_member_access() {
        let snippet = "  console.log(user.email);";
        let (desc, replacement) = generate_log_patch(snippet, &PiiType::Email);
        assert!(desc.contains("Mask"));
        assert!(replacement.contains("maskEmail(user.email)"));
        assert!(!replacement.contains("user.email);")); // original should be gone
    }

    #[test]
    fn log_patch_replaces_standalone_variable() {
        let snippet = "  logger.info(email);";
        let (_, replacement) = generate_log_patch(snippet, &PiiType::Email);
        assert!(replacement.contains("maskEmail(email)"));
    }

    #[test]
    fn response_patch_redacts() {
        let snippet = "  res.json({ email: user.email });";
        let (desc, replacement) = generate_response_patch(snippet, &PiiType::Email);
        assert!(desc.contains("Redact"));
        assert!(replacement.contains("\"[REDACTED]\""));
    }

    #[test]
    fn db_patch_encrypts() {
        let snippet = "  db.save({ email: user.email });";
        let (desc, replacement) = generate_db_patch(snippet, &PiiType::Email);
        assert!(desc.contains("Encrypt"));
        assert!(replacement.contains("encrypt(user.email)"));
    }

    #[test]
    fn api_patch_masks() {
        let snippet = "  fetch(url, { body: JSON.stringify({ email: user.email }) });";
        let (desc, replacement) = generate_api_patch(snippet, &PiiType::Email);
        assert!(desc.contains("Mask"));
        assert!(replacement.contains("maskEmail(user.email)"));
    }

    #[test]
    fn unified_diff_format() {
        let diff = format_unified_diff("src/test.ts", 5, "  old line", "  new line");
        assert!(diff.contains("--- a/src/test.ts"));
        assert!(diff.contains("+++ b/src/test.ts"));
        assert!(diff.contains("@@ -5,1 +5,1 @@"));
        assert!(diff.contains("-  old line"));
        assert!(diff.contains("+  new line"));
    }

    #[test]
    fn extract_member_access() {
        let line = "console.log(user.email);";
        let result = extract_pii_expression(line, &PiiType::Email);
        assert_eq!(result, Some("user.email".to_string()));
    }

    #[test]
    fn extract_nested_member() {
        let line = "logger.info(request.body.phoneNumber);";
        let result = extract_pii_expression(line, &PiiType::PhoneNumber);
        assert_eq!(result, Some("request.body.phoneNumber".to_string()));
    }

    #[test]
    fn extract_standalone_var() {
        let line = "  print(email)";
        let result = extract_pii_expression(line, &PiiType::Email);
        assert_eq!(result, Some("email".to_string()));
    }

    #[test]
    fn preserves_indentation() {
        let line = "    console.log(user.email);";
        let (_, replacement) = generate_log_patch(line, &PiiType::Email);
        assert!(
            replacement.starts_with("    "),
            "should preserve 4-space indent"
        );
    }

    #[test]
    fn snippet_fallback_works() {
        let finding = make_log_finding("  console.log(user.email);");
        let suggestion = generate_suggestion_from_snippet(&finding).unwrap();
        assert!(suggestion.unified_diff.contains("--- a/"));
        assert!(suggestion.unified_diff.contains("+++ b/"));
        assert!(suggestion.replacement_line.contains("maskEmail"));
    }

    #[test]
    fn apply_suggestion_to_file() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), "line1\nline2\nline3\n").unwrap();

        let suggestion = Suggestion {
            finding_id: "test".into(),
            file: tmp.path().to_string_lossy().to_string(),
            line: 2,
            description: "test".into(),
            original_line: "line2".into(),
            replacement_line: "fixed_line2".into(),
            unified_diff: String::new(),
        };

        let applied = apply_suggestion(&suggestion).unwrap();
        assert!(applied);

        let content = std::fs::read_to_string(tmp.path()).unwrap();
        assert!(content.contains("fixed_line2"));
        assert!(!content.contains("\nline2\n"));
    }

    #[test]
    fn apply_rejects_stale_suggestion() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), "line1\nchanged\nline3\n").unwrap();

        let suggestion = Suggestion {
            finding_id: "test".into(),
            file: tmp.path().to_string_lossy().to_string(),
            line: 2,
            description: "test".into(),
            original_line: "line2".into(), // doesn't match "changed"
            replacement_line: "fixed".into(),
            unified_diff: String::new(),
        };

        let applied = apply_suggestion(&suggestion).unwrap();
        assert!(!applied, "should reject stale suggestion");
    }
}
