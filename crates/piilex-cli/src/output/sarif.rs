use anyhow::Result;
use piilex_core::finding::FindingSet;
use serde_json::json;

pub fn print_findings(finding_set: &FindingSet) -> Result<()> {
    let results: Vec<serde_json::Value> = finding_set.findings.iter().map(|f| {
        json!({
            "ruleId": format!("piilex/{}", f.pii_type.as_str()),
            "level": match f.severity {
                piilex_core::severity::Severity::Critical => "error",
                piilex_core::severity::Severity::High => "error",
                piilex_core::severity::Severity::Medium => "warning",
                piilex_core::severity::Severity::Low => "note",
            },
            "message": {
                "text": format!("PII detected: {} ({})", f.pii_type.as_str(), f.category.as_str())
            },
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": f.location.file.display().to_string().replace('\\', "/")
                    },
                    "region": {
                        "startLine": f.location.line,
                        "startColumn": f.location.column
                    }
                }
            }]
        })
    }).collect();

    let sarif = json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "piilex",
                    "version": finding_set.metadata.tool_version,
                    "informationUri": "https://github.com/xxx/piilex"
                }
            },
            "results": results
        }]
    });

    println!("{}", serde_json::to_string_pretty(&sarif)?);
    Ok(())
}
