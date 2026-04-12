use anyhow::Result;
use piilex_core::finding::FindingSet;

pub fn print_findings(finding_set: &FindingSet) -> Result<()> {
    let json = serde_json::to_string_pretty(finding_set)?;
    println!("{}", json);
    Ok(())
}
