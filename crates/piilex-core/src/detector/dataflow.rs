use crate::config::CustomSink;
use crate::finding::{DataFlow, DataFlowNode, Finding, FlowNodeKind, SourceLocation};
use crate::parser::ParsedFile;
use regex::Regex;

pub struct DataFlowAnalyzer {
    log_patterns: Vec<&'static str>,
    db_patterns: Vec<&'static str>,
    http_patterns: Vec<&'static str>,
    response_patterns: Vec<&'static str>,
    custom_sinks: Vec<CompiledCustomSink>,
}

struct CompiledCustomSink {
    regex: Regex,
    kind: FlowNodeKind,
    allowed: bool,
}

impl Default for DataFlowAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl DataFlowAnalyzer {
    pub fn new() -> Self {
        Self {
            log_patterns: vec![
                "console.log",
                "console.info",
                "console.warn",
                "console.error",
                "console.debug",
                "logger.log",
                "logger.info",
                "logger.warn",
                "logger.error",
                "logger.debug",
                "log.info",
                "log.warn",
                "log.error",
                "log.debug",
                "winston.log",
                "winston.info",
                "pino.info",
                "logging.info",
                "logging.warning",
                "logging.error",
                "logging.debug",
                "print",
            ],
            db_patterns: vec![
                "db.query",
                "db.execute",
                "db.insert",
                "db.update",
                "db.save",
                "db.create",
                "db.findOrCreate",
                "prisma.create",
                "prisma.update",
                "prisma.upsert",
                "knex.insert",
                "knex.update",
                "Model.create",
                "Model.save",
                "Model.update",
                "cursor.execute",
                "session.add",
                "session.commit",
                "collection.insert",
                "collection.save",
            ],
            http_patterns: vec![
                "fetch",
                "axios.get",
                "axios.post",
                "axios.put",
                "requests.get",
                "requests.post",
                "requests.put",
                "http.get",
                "http.post",
                "got",
                "superagent",
            ],
            response_patterns: vec![
                "res.json",
                "res.send",
                "res.write",
                "res.render",
                "response.json",
                "response.send",
                "ctx.json",
                "ctx.body",
                "JsonResponse",
                "jsonify",
            ],
            custom_sinks: Vec::new(),
        }
    }

    /// Load custom sink patterns from config.
    pub fn load_custom_sinks(&mut self, sinks: &[CustomSink]) {
        for sink in sinks {
            let regex = match Regex::new(&sink.pattern) {
                Ok(r) => r,
                Err(e) => {
                    eprintln!(
                        "Warning: invalid regex '{}' for custom sink: {}",
                        sink.pattern, e
                    );
                    continue;
                }
            };
            let kind = match sink.kind.as_str() {
                "log_output" | "log" => FlowNodeKind::LogOutput,
                "database" | "db" => FlowNodeKind::Database,
                "third_party_api" | "api" | "http" => FlowNodeKind::ThirdPartyApi,
                "response" | "res" => FlowNodeKind::Response,
                "file_system" | "file" => FlowNodeKind::FileSystem,
                _ => FlowNodeKind::ThirdPartyApi,
            };
            self.custom_sinks.push(CompiledCustomSink {
                regex,
                kind,
                allowed: sink.allowed,
            });
        }
    }

    pub fn trace(&self, file: &ParsedFile, finding: &Finding) -> Option<DataFlow> {
        let pii_name = extract_pii_variable_name(&finding.code_snippet);
        let pii_name = pii_name.as_deref()?;

        for call in &file.call_expressions {
            // Check if the PII variable is used in a call's arguments
            let pii_in_args = call
                .argument_identifiers
                .iter()
                .any(|arg| arg == pii_name || arg == finding.pii_type.as_str());

            // Also check if the callee contains the PII as member access
            let pii_in_callee = call.callee.contains(pii_name);

            if !pii_in_args && !pii_in_callee {
                continue;
            }

            let sink_kind = self.classify_sink(&call.callee);
            if let Some(kind) = sink_kind {
                return Some(DataFlow {
                    source: DataFlowNode {
                        kind: FlowNodeKind::UserInput,
                        label: pii_name.to_string(),
                        location: finding.location.clone(),
                    },
                    sink: DataFlowNode {
                        kind,
                        label: call.callee.clone(),
                        location: SourceLocation {
                            file: file.path.clone(),
                            line: call.line,
                            column: call.column,
                        },
                    },
                    path: vec![
                        finding.location.clone(),
                        SourceLocation {
                            file: file.path.clone(),
                            line: call.line,
                            column: call.column,
                        },
                    ],
                });
            }
        }

        None
    }

    /// Public wrapper for cross-file analysis.
    pub fn classify_sink_public(&self, callee: &str) -> Option<FlowNodeKind> {
        self.classify_sink(callee)
    }

    fn classify_sink(&self, callee: &str) -> Option<FlowNodeKind> {
        let callee_lower = callee.to_lowercase();

        for pattern in &self.log_patterns {
            if callee_lower == pattern.to_lowercase()
                || callee.ends_with(pattern.split('.').next_back().unwrap_or(""))
                    && callee_lower.contains("log")
            {
                return Some(FlowNodeKind::LogOutput);
            }
        }

        for pattern in &self.db_patterns {
            let parts: Vec<&str> = pattern.split('.').collect();
            if let Some(method) = parts.last() {
                if callee_lower.ends_with(&method.to_lowercase()) {
                    return Some(FlowNodeKind::Database);
                }
            }
        }

        for pattern in &self.http_patterns {
            if callee_lower.starts_with(&pattern.to_lowercase()) {
                return Some(FlowNodeKind::ThirdPartyApi);
            }
        }

        for pattern in &self.response_patterns {
            let parts: Vec<&str> = pattern.split('.').collect();
            if let Some(method) = parts.last() {
                if callee_lower.ends_with(&method.to_lowercase())
                    && (callee_lower.contains("res")
                        || callee_lower.contains("response")
                        || callee_lower.contains("ctx"))
                {
                    return Some(FlowNodeKind::Response);
                }
            }
        }

        // Check custom sinks
        for custom in &self.custom_sinks {
            if custom.regex.is_match(callee) {
                if custom.allowed {
                    return None; // Allowed sink: suppress the finding
                }
                return Some(custom.kind);
            }
        }

        None
    }

    /// Check if a callee matches an allowed custom sink.
    pub fn is_allowed_sink(&self, callee: &str) -> bool {
        self.custom_sinks
            .iter()
            .any(|s| s.allowed && s.regex.is_match(callee))
    }
}

fn extract_pii_variable_name(code_snippet: &str) -> Option<String> {
    use regex::Regex;
    use std::sync::LazyLock;

    static MEMBER_ACCESS: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(\w+)\.(\w+)").unwrap());

    // Try to extract from member access (e.g., "user.email" → "email")
    for cap in MEMBER_ACCESS.captures_iter(code_snippet) {
        if let Some(prop) = cap.get(2) {
            return Some(prop.as_str().to_string());
        }
    }

    // Try to extract from simple assignment (e.g., "const email = ..." → "email")
    static SIMPLE_VAR: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"(?:const|let|var|)\s*(\w+)\s*=").unwrap());

    if let Some(cap) = SIMPLE_VAR.captures(code_snippet) {
        if let Some(name) = cap.get(1) {
            return Some(name.as_str().to_string());
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_log_sinks() {
        let analyzer = DataFlowAnalyzer::new();
        assert_eq!(
            analyzer.classify_sink("console.log"),
            Some(FlowNodeKind::LogOutput)
        );
        assert_eq!(
            analyzer.classify_sink("logger.info"),
            Some(FlowNodeKind::LogOutput)
        );
    }

    #[test]
    fn classify_db_sinks() {
        let analyzer = DataFlowAnalyzer::new();
        assert_eq!(
            analyzer.classify_sink("db.query"),
            Some(FlowNodeKind::Database)
        );
        assert_eq!(
            analyzer.classify_sink("db.save"),
            Some(FlowNodeKind::Database)
        );
    }

    #[test]
    fn classify_http_sinks() {
        let analyzer = DataFlowAnalyzer::new();
        assert_eq!(
            analyzer.classify_sink("fetch"),
            Some(FlowNodeKind::ThirdPartyApi)
        );
        assert_eq!(
            analyzer.classify_sink("axios.post"),
            Some(FlowNodeKind::ThirdPartyApi)
        );
    }

    #[test]
    fn classify_unknown() {
        let analyzer = DataFlowAnalyzer::new();
        assert_eq!(analyzer.classify_sink("myFunc"), None);
        assert_eq!(analyzer.classify_sink("utils.format"), None);
    }

    #[test]
    fn extract_variable_from_member() {
        assert_eq!(
            extract_pii_variable_name("user.email"),
            Some("email".into())
        );
        assert_eq!(
            extract_pii_variable_name("request.body.phone"),
            Some("body".into())
        );
    }
}
