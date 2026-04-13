use crate::finding::FindingSet;
use serde::Serialize;
use std::collections::HashMap;

/// Upload payload sent to the SaaS API.
#[derive(Debug, Serialize)]
pub struct UploadPayload {
    pub project_name: String,
    pub files_scanned: usize,
    pub findings_count: usize,
    pub critical_count: usize,
    pub high_count: usize,
    pub medium_count: usize,
    pub low_count: usize,
    pub frameworks: Vec<String>,
    pub duration_ms: u64,
    pub pii_type_summary: HashMap<String, usize>,
    pub language_summary: HashMap<String, usize>,
    pub findings: Vec<UploadFinding>,
}

#[derive(Debug, Serialize)]
pub struct UploadFinding {
    pub pii_type: String,
    pub severity: String,
    pub file_path: String,
    pub line: usize,
    pub code_snippet: String,
    pub data_flow: Option<serde_json::Value>,
    pub framework_mappings: Option<serde_json::Value>,
}

impl UploadPayload {
    pub fn from_finding_set(
        finding_set: &FindingSet,
        project_name: &str,
        language_counts: &HashMap<String, usize>,
    ) -> Self {
        let mut pii_counts: HashMap<String, usize> = HashMap::new();
        let mut critical = 0usize;
        let mut high = 0usize;
        let mut medium = 0usize;
        let mut low = 0usize;

        let mut findings = Vec::new();

        for f in &finding_set.findings {
            *pii_counts
                .entry(f.pii_type.as_str().to_string())
                .or_default() += 1;

            match f.severity {
                crate::severity::Severity::Critical => critical += 1,
                crate::severity::Severity::High => high += 1,
                crate::severity::Severity::Medium => medium += 1,
                crate::severity::Severity::Low => low += 1,
            }

            findings.push(UploadFinding {
                pii_type: f.pii_type.as_str().to_string(),
                severity: f.severity.as_str().to_string(),
                file_path: f.location.file.display().to_string(),
                line: f.location.line,
                code_snippet: f.code_snippet.clone(),
                data_flow: f.data_flow.as_ref().map(|df| {
                    serde_json::json!({
                        "source": df.source.kind.as_str(),
                        "sink": df.sink.kind.as_str(),
                    })
                }),
                framework_mappings: if f.framework_mappings.is_empty() {
                    None
                } else {
                    Some(serde_json::to_value(&f.framework_mappings).unwrap_or_default())
                },
            });
        }

        let frameworks = finding_set
            .metadata
            .frameworks
            .iter()
            .map(|f| f.as_str().to_string())
            .collect();

        Self {
            project_name: project_name.to_string(),
            files_scanned: finding_set.metadata.files_scanned,
            findings_count: finding_set.findings.len(),
            critical_count: critical,
            high_count: high,
            medium_count: medium,
            low_count: low,
            frameworks,
            duration_ms: finding_set.metadata.duration.as_millis() as u64,
            pii_type_summary: pii_counts,
            language_summary: language_counts.clone(),
            findings,
        }
    }
}

/// Upload scan results to the SaaS API.
/// Returns the scan ID on success.
pub fn upload_sync(
    api_url: &str,
    api_key: &str,
    payload: &UploadPayload,
) -> Result<String, String> {
    // Use a simple blocking HTTP POST (no async runtime needed)
    // We build the request manually to avoid adding reqwest to piilex-core
    let body = serde_json::to_string(payload).map_err(|e| e.to_string())?;

    let url = format!("{}/api/scans", api_url.trim_end_matches('/'));
    let api_key = api_key.to_string();

    // Spawn a thread for the blocking HTTP call so it doesn't interfere with anything
    let result = std::thread::spawn(move || {
        use std::io::{Read, Write};
        use std::net::TcpStream;

        // Parse URL
        let url_without_scheme = url
            .strip_prefix("https://")
            .or_else(|| url.strip_prefix("http://"))
            .unwrap_or(&url);
        let (host_port, path) = url_without_scheme
            .split_once('/')
            .unwrap_or((url_without_scheme, "api/scans"));
        let path = format!("/{}", path);

        // For localhost/HTTP, use plain TCP
        let stream = TcpStream::connect(host_port);
        let mut stream = match stream {
            Ok(s) => s,
            Err(e) => return Err(format!("connection failed to {}: {}", host_port, e)),
        };

        let request = format!(
            "POST {} HTTP/1.1\r\n\
             Host: {}\r\n\
             Authorization: Bearer {}\r\n\
             Content-Type: application/json\r\n\
             Content-Length: {}\r\n\
             Connection: close\r\n\
             \r\n\
             {}",
            path,
            host_port,
            api_key,
            body.len(),
            body
        );

        stream
            .write_all(request.as_bytes())
            .map_err(|e| e.to_string())?;

        let mut response = String::new();
        stream
            .read_to_string(&mut response)
            .map_err(|e| e.to_string())?;

        // Parse status code from first line
        let status_line = response.lines().next().unwrap_or("");
        if status_line.contains("201") || status_line.contains("200") {
            // Try to extract scan ID from response body
            if let Some(body_start) = response.find("\r\n\r\n") {
                let resp_body = &response[body_start + 4..];
                if let Ok(json) = serde_json::from_str::<serde_json::Value>(resp_body) {
                    if let Some(id) = json["id"].as_str() {
                        return Ok(id.to_string());
                    }
                }
            }
            Ok("uploaded".to_string())
        } else {
            Err(format!("upload failed: {}", status_line))
        }
    })
    .join()
    .map_err(|_| "upload thread panicked".to_string())?;

    result
}
