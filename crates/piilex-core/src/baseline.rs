use std::collections::HashMap;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::finding::{Finding, FindingSet};

// ─── Fingerprint ────────────────────────────────────────────────────

/// A content-based fingerprint that identifies a finding across scans.
///
/// Line numbers change as code is edited, so the fingerprint intentionally
/// ignores them. Two findings match if they concern the same PII type in
/// the same file with the same code snippet and data-flow sink.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct FindingFingerprint {
    /// Relative file path (normalized to forward slashes)
    pub file: String,
    /// PII type string (e.g., "email")
    pub pii_type: String,
    /// Trimmed code snippet (whitespace-normalized)
    pub code_snippet_norm: String,
    /// Sink kind if data flow exists (e.g., "log_output"), or empty
    pub sink_kind: String,
}

impl FindingFingerprint {
    pub fn from_finding(f: &Finding) -> Self {
        Self {
            file: normalize_path(&f.location.file),
            pii_type: f.pii_type.as_str().to_string(),
            code_snippet_norm: normalize_snippet(&f.code_snippet),
            sink_kind: f
                .data_flow
                .as_ref()
                .map(|df| df.sink.kind.as_str().to_string())
                .unwrap_or_default(),
        }
    }
}

fn normalize_path(p: &Path) -> String {
    p.to_string_lossy().replace('\\', "/")
}

fn normalize_snippet(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

// ─── Change classification ──────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ChangeKind {
    /// Finding exists in current scan but not in baseline
    Added,
    /// Finding exists in baseline but not in current scan
    Removed,
    /// Finding exists in both but severity or data-flow changed
    Modified,
    /// Finding is unchanged
    Unchanged,
}

impl ChangeKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            ChangeKind::Added => "added",
            ChangeKind::Removed => "removed",
            ChangeKind::Modified => "modified",
            ChangeKind::Unchanged => "unchanged",
        }
    }
}

impl std::fmt::Display for ChangeKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

// ─── DiffEntry ──────────────────────────────────────────────────────

/// A single entry in the diff result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiffEntry {
    pub change: ChangeKind,
    pub finding: Finding,
    /// For `Modified`: what changed
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub changes: Vec<FieldChange>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FieldChange {
    pub field: String,
    pub old_value: String,
    pub new_value: String,
}

// ─── DiffResult ─────────────────────────────────────────────────────

/// Complete diff between a baseline and current scan.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiffResult {
    pub entries: Vec<DiffEntry>,
    pub summary: DiffSummary,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiffSummary {
    pub added: usize,
    pub removed: usize,
    pub modified: usize,
    pub unchanged: usize,
    pub total_current: usize,
    pub total_baseline: usize,
}

// ─── Diff computation ───────────────────────────────────────────────

/// Compute the diff between a baseline FindingSet and the current one.
pub fn compute_diff(baseline: &FindingSet, current: &FindingSet) -> DiffResult {
    // Index baseline findings by fingerprint
    let mut baseline_map: HashMap<FindingFingerprint, Vec<&Finding>> = HashMap::new();
    for f in &baseline.findings {
        let fp = FindingFingerprint::from_finding(f);
        baseline_map.entry(fp).or_default().push(f);
    }

    // Track which baseline fingerprints were matched
    let mut matched_baseline: HashMap<FindingFingerprint, bool> =
        baseline_map.keys().map(|k| (k.clone(), false)).collect();

    let mut entries = Vec::new();

    // Process current findings
    for f in &current.findings {
        let fp = FindingFingerprint::from_finding(f);

        if let Some(baseline_findings) = baseline_map.get(&fp) {
            // Fingerprint match found — check for modifications
            matched_baseline.insert(fp.clone(), true);

            let base_f = baseline_findings[0];
            let changes = detect_changes(base_f, f);

            if changes.is_empty() {
                entries.push(DiffEntry {
                    change: ChangeKind::Unchanged,
                    finding: f.clone(),
                    changes: Vec::new(),
                });
            } else {
                entries.push(DiffEntry {
                    change: ChangeKind::Modified,
                    finding: f.clone(),
                    changes,
                });
            }
        } else {
            // No match in baseline — this is a new finding
            entries.push(DiffEntry {
                change: ChangeKind::Added,
                finding: f.clone(),
                changes: Vec::new(),
            });
        }
    }

    // Baseline findings not matched by any current finding → removed
    for (fp, was_matched) in &matched_baseline {
        if !was_matched {
            if let Some(baseline_findings) = baseline_map.get(fp) {
                for base_f in baseline_findings {
                    entries.push(DiffEntry {
                        change: ChangeKind::Removed,
                        finding: (*base_f).clone(),
                        changes: Vec::new(),
                    });
                }
            }
        }
    }

    // Sort: added first, then modified, then removed, then unchanged
    entries.sort_by(|a, b| {
        change_sort_key(a.change)
            .cmp(&change_sort_key(b.change))
            .then(b.finding.severity.cmp(&a.finding.severity))
            .then(a.finding.location.file.cmp(&b.finding.location.file))
            .then(a.finding.location.line.cmp(&b.finding.location.line))
    });

    let added = entries
        .iter()
        .filter(|e| e.change == ChangeKind::Added)
        .count();
    let removed = entries
        .iter()
        .filter(|e| e.change == ChangeKind::Removed)
        .count();
    let modified = entries
        .iter()
        .filter(|e| e.change == ChangeKind::Modified)
        .count();
    let unchanged = entries
        .iter()
        .filter(|e| e.change == ChangeKind::Unchanged)
        .count();

    DiffResult {
        entries,
        summary: DiffSummary {
            added,
            removed,
            modified,
            unchanged,
            total_current: current.findings.len(),
            total_baseline: baseline.findings.len(),
        },
    }
}

fn change_sort_key(kind: ChangeKind) -> u8 {
    match kind {
        ChangeKind::Added => 0,
        ChangeKind::Modified => 1,
        ChangeKind::Removed => 2,
        ChangeKind::Unchanged => 3,
    }
}

/// Detect which fields changed between the baseline and current version
/// of a finding that shares the same fingerprint.
fn detect_changes(baseline: &Finding, current: &Finding) -> Vec<FieldChange> {
    let mut changes = Vec::new();

    // Severity change
    if baseline.severity != current.severity {
        changes.push(FieldChange {
            field: "severity".to_string(),
            old_value: baseline.severity.to_string(),
            new_value: current.severity.to_string(),
        });
    }

    // Line number change (common when code is edited)
    if baseline.location.line != current.location.line {
        changes.push(FieldChange {
            field: "line".to_string(),
            old_value: baseline.location.line.to_string(),
            new_value: current.location.line.to_string(),
        });
    }

    // Data flow sink change
    let _old_sink = baseline
        .data_flow
        .as_ref()
        .map(|df| df.sink.kind.as_str())
        .unwrap_or("none");
    let _new_sink = current
        .data_flow
        .as_ref()
        .map(|df| df.sink.kind.as_str())
        .unwrap_or("none");

    // Note: sink_kind is part of the fingerprint, so if it truly changed
    // the findings wouldn't match. But data_flow presence can toggle.
    if (baseline.data_flow.is_none()) != (current.data_flow.is_none()) {
        changes.push(FieldChange {
            field: "data_flow".to_string(),
            old_value: if baseline.data_flow.is_some() {
                "present".to_string()
            } else {
                "none".to_string()
            },
            new_value: if current.data_flow.is_some() {
                "present".to_string()
            } else {
                "none".to_string()
            },
        });
    }

    // Framework mapping count change
    let old_fw_count = baseline.framework_mappings.len();
    let new_fw_count = current.framework_mappings.len();
    if old_fw_count != new_fw_count {
        changes.push(FieldChange {
            field: "framework_mappings".to_string(),
            old_value: format!("{} mapping(s)", old_fw_count),
            new_value: format!("{} mapping(s)", new_fw_count),
        });
    }

    // Confidence change
    if baseline.confidence != current.confidence {
        changes.push(FieldChange {
            field: "confidence".to_string(),
            old_value: format!("{:?}", baseline.confidence),
            new_value: format!("{:?}", current.confidence),
        });
    }

    changes
}

/// Load a baseline FindingSet from a JSON file.
pub fn load_baseline(path: &Path) -> Result<FindingSet, BaselineError> {
    let content =
        std::fs::read_to_string(path).map_err(|e| BaselineError::Io(path.to_path_buf(), e))?;
    let finding_set: FindingSet = serde_json::from_str(&content)
        .map_err(|e| BaselineError::Parse(path.to_path_buf(), e.to_string()))?;
    Ok(finding_set)
}

/// Save a FindingSet as a baseline JSON file.
pub fn save_baseline(finding_set: &FindingSet, path: &Path) -> Result<(), BaselineError> {
    let json = serde_json::to_string_pretty(finding_set)
        .map_err(|e| BaselineError::Parse(path.to_path_buf(), e.to_string()))?;
    std::fs::write(path, json).map_err(|e| BaselineError::Io(path.to_path_buf(), e))?;
    Ok(())
}

#[derive(Debug, thiserror::Error)]
pub enum BaselineError {
    #[error("failed to read baseline file {0}: {1}")]
    Io(std::path::PathBuf, std::io::Error),
    #[error("failed to parse baseline file {0}: {1}")]
    Parse(std::path::PathBuf, String),
}

// ─── Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finding::*;
    use crate::severity::Severity;
    use std::time::Duration;

    fn make_finding(
        file: &str,
        line: usize,
        pii: PiiType,
        sev: Severity,
        snippet: &str,
    ) -> Finding {
        Finding {
            id: "PII-TEST".into(),
            severity: sev,
            pii_type: pii,
            category: PiiCategory::ContactInfo,
            location: SourceLocation {
                file: file.into(),
                line,
                column: 1,
            },
            code_snippet: snippet.into(),
            data_flow: None,
            framework_mappings: Vec::new(),
            confidence: Confidence::High,
        }
    }

    fn make_finding_with_sink(
        file: &str,
        line: usize,
        pii: PiiType,
        sev: Severity,
        snippet: &str,
        sink: FlowNodeKind,
    ) -> Finding {
        let mut f = make_finding(file, line, pii, sev, snippet);
        f.data_flow = Some(DataFlow {
            source: DataFlowNode {
                kind: FlowNodeKind::UserInput,
                label: "input".into(),
                location: f.location.clone(),
            },
            sink: DataFlowNode {
                kind: sink,
                label: "console.log".into(),
                location: f.location.clone(),
            },
            path: vec![],
        });
        f
    }

    fn make_set(findings: Vec<Finding>) -> FindingSet {
        FindingSet {
            findings,
            metadata: ScanMetadata {
                path: ".".into(),
                files_scanned: 1,
                files_skipped: 0,
                duration: Duration::from_millis(100),
                frameworks: vec![],
                tool_version: "0.1.0".into(),
            },
        }
    }

    #[test]
    fn identical_scans_all_unchanged() {
        let f = make_finding(
            "src/a.ts",
            10,
            PiiType::Email,
            Severity::High,
            "const email = x;",
        );
        let baseline = make_set(vec![f.clone()]);
        let current = make_set(vec![f]);

        let diff = compute_diff(&baseline, &current);
        assert_eq!(diff.summary.unchanged, 1);
        assert_eq!(diff.summary.added, 0);
        assert_eq!(diff.summary.removed, 0);
        assert_eq!(diff.summary.modified, 0);
    }

    #[test]
    fn new_finding_is_added() {
        let baseline = make_set(vec![]);
        let f = make_finding(
            "src/a.ts",
            10,
            PiiType::Email,
            Severity::High,
            "const email = x;",
        );
        let current = make_set(vec![f]);

        let diff = compute_diff(&baseline, &current);
        assert_eq!(diff.summary.added, 1);
        assert_eq!(diff.summary.removed, 0);
    }

    #[test]
    fn removed_finding_detected() {
        let f = make_finding(
            "src/a.ts",
            10,
            PiiType::Email,
            Severity::High,
            "const email = x;",
        );
        let baseline = make_set(vec![f]);
        let current = make_set(vec![]);

        let diff = compute_diff(&baseline, &current);
        assert_eq!(diff.summary.removed, 1);
        assert_eq!(diff.summary.added, 0);
    }

    #[test]
    fn line_change_is_modified() {
        let old = make_finding(
            "src/a.ts",
            10,
            PiiType::Email,
            Severity::High,
            "const email = x;",
        );
        let mut new = old.clone();
        new.location.line = 15; // Line moved

        let diff = compute_diff(&make_set(vec![old]), &make_set(vec![new]));
        assert_eq!(diff.summary.modified, 1);
        assert!(diff.entries[0].changes.iter().any(|c| c.field == "line"));
    }

    #[test]
    fn severity_change_is_modified() {
        let old = make_finding(
            "src/a.ts",
            10,
            PiiType::Email,
            Severity::High,
            "const email = x;",
        );
        let mut new = old.clone();
        new.severity = Severity::Critical;

        let diff = compute_diff(&make_set(vec![old]), &make_set(vec![new]));
        assert_eq!(diff.summary.modified, 1);
        assert!(diff.entries[0]
            .changes
            .iter()
            .any(|c| c.field == "severity"));
    }

    #[test]
    fn different_pii_type_is_add_remove() {
        let old = make_finding(
            "src/a.ts",
            10,
            PiiType::Email,
            Severity::High,
            "const email = x;",
        );
        let new = make_finding(
            "src/a.ts",
            10,
            PiiType::Password,
            Severity::Critical,
            "const password = x;",
        );

        let diff = compute_diff(&make_set(vec![old]), &make_set(vec![new]));
        assert_eq!(diff.summary.added, 1);
        assert_eq!(diff.summary.removed, 1);
    }

    #[test]
    fn data_flow_added_is_modified() {
        let old = make_finding(
            "src/a.ts",
            10,
            PiiType::Email,
            Severity::High,
            "const email = x;",
        );
        let new = make_finding_with_sink(
            "src/a.ts",
            10,
            PiiType::Email,
            Severity::High,
            "const email = x;",
            FlowNodeKind::LogOutput,
        );

        // Different sink_kind in fingerprint → add + remove (different fingerprint)
        let diff = compute_diff(&make_set(vec![old]), &make_set(vec![new]));
        // Since sink_kind is part of fingerprint, these are different findings
        assert_eq!(diff.summary.added + diff.summary.removed, 2);
    }

    #[test]
    fn complex_diff() {
        let old_a = make_finding(
            "src/a.ts",
            10,
            PiiType::Email,
            Severity::High,
            "const email = x;",
        );
        let old_b = make_finding(
            "src/b.ts",
            5,
            PiiType::Password,
            Severity::Critical,
            "const pwd = x;",
        );
        let old_c = make_finding(
            "src/c.ts",
            20,
            PiiType::IpAddress,
            Severity::Medium,
            "const ip = x;",
        );

        let new_a = make_finding(
            "src/a.ts",
            12,
            PiiType::Email,
            Severity::High,
            "const email = x;",
        ); // line changed
           // old_b removed
        let new_d = make_finding(
            "src/d.ts",
            1,
            PiiType::CreditCard,
            Severity::Critical,
            "const cc = x;",
        ); // new file

        let diff = compute_diff(
            &make_set(vec![old_a, old_b, old_c]),
            &make_set(vec![new_a, new_d]),
        );

        assert_eq!(
            diff.summary.modified, 1,
            "a.ts email should be modified (line change)"
        );
        assert_eq!(diff.summary.added, 1, "d.ts creditcard should be added");
        assert_eq!(
            diff.summary.removed, 2,
            "b.ts password and c.ts ip should be removed"
        );
        assert_eq!(diff.summary.unchanged, 0);
        assert_eq!(diff.summary.total_baseline, 3);
        assert_eq!(diff.summary.total_current, 2);
    }

    #[test]
    fn fingerprint_ignores_line_number() {
        let a = make_finding(
            "src/a.ts",
            10,
            PiiType::Email,
            Severity::High,
            "const email = x;",
        );
        let b = make_finding(
            "src/a.ts",
            99,
            PiiType::Email,
            Severity::High,
            "const email = x;",
        );

        let fp_a = FindingFingerprint::from_finding(&a);
        let fp_b = FindingFingerprint::from_finding(&b);
        assert_eq!(
            fp_a, fp_b,
            "Fingerprints should match despite different line numbers"
        );
    }

    #[test]
    fn fingerprint_normalizes_whitespace() {
        let a = make_finding(
            "src/a.ts",
            10,
            PiiType::Email,
            Severity::High,
            "  const  email  =  x;  ",
        );
        let b = make_finding(
            "src/a.ts",
            10,
            PiiType::Email,
            Severity::High,
            "const email = x;",
        );

        let fp_a = FindingFingerprint::from_finding(&a);
        let fp_b = FindingFingerprint::from_finding(&b);
        assert_eq!(fp_a, fp_b);
    }

    #[test]
    fn fingerprint_normalizes_path_separators() {
        let a = make_finding(
            "src\\models\\user.ts",
            10,
            PiiType::Email,
            Severity::High,
            "email",
        );
        let b = make_finding(
            "src/models/user.ts",
            10,
            PiiType::Email,
            Severity::High,
            "email",
        );

        let fp_a = FindingFingerprint::from_finding(&a);
        let fp_b = FindingFingerprint::from_finding(&b);
        assert_eq!(fp_a, fp_b, "Paths should match across OS separators");
    }

    #[test]
    fn sort_order_added_first() {
        let old = make_finding("src/a.ts", 10, PiiType::Email, Severity::High, "email");
        let kept = make_finding("src/a.ts", 10, PiiType::Email, Severity::High, "email");
        let new = make_finding("src/b.ts", 5, PiiType::Password, Severity::Critical, "pwd");

        let diff = compute_diff(&make_set(vec![old]), &make_set(vec![kept, new]));
        assert_eq!(
            diff.entries[0].change,
            ChangeKind::Added,
            "Added should come first"
        );
    }
}
