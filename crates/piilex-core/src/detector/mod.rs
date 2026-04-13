pub mod crossfile;
pub mod dataflow;
pub mod framework;
pub mod identifier;
pub mod literal;

use crate::config::Config;
use crate::finding::Finding;
use crate::parser::ParsedFile;

pub struct DetectorPipeline {
    identifier_detector: identifier::IdentifierDetector,
    literal_detector: literal::LiteralDetector,
    dataflow_analyzer: dataflow::DataFlowAnalyzer,
    framework_mapper: framework::FrameworkMapper,
}

impl DetectorPipeline {
    pub fn new() -> Self {
        Self {
            identifier_detector: identifier::IdentifierDetector::new(),
            literal_detector: literal::LiteralDetector::new(),
            dataflow_analyzer: dataflow::DataFlowAnalyzer::new(),
            framework_mapper: framework::FrameworkMapper::new(),
        }
    }

    /// Create a pipeline with custom PII types and rules loaded from config.
    pub fn with_config(config: &Config) -> Self {
        let mut pipeline = Self::new();
        if !config.pii_types.custom.is_empty() {
            pipeline
                .identifier_detector
                .load_custom(&config.pii_types.custom);
        }
        if !config.rules.custom_sinks.is_empty() {
            pipeline
                .dataflow_analyzer
                .load_custom_sinks(&config.rules.custom_sinks);
        }
        pipeline
    }

    /// Single-file analysis (intra-file data flow only).
    pub fn analyze(&self, file: &ParsedFile, config: &Config) -> Vec<Finding> {
        // Check path-based exceptions
        if should_skip_file(&file.path, &config.rules.exceptions) {
            return Vec::new();
        }

        let mut findings = self.identifier_detector.detect(file);
        findings.extend(self.literal_detector.detect(file));

        // Apply allow-list: remove findings whose identifier is explicitly allowed
        if !config.rules.allow_identifiers.is_empty() {
            findings.retain(|f| {
                !config
                    .rules
                    .allow_identifiers
                    .iter()
                    .any(|allowed| f.code_snippet.contains(allowed))
            });
        }

        // Apply ignore-list: remove findings matching ignore patterns (PII type names)
        if !config.pii_types.ignore.is_empty() {
            findings.retain(|f| {
                !config
                    .pii_types
                    .ignore
                    .iter()
                    .any(|ignored| f.pii_type.as_str() == ignored)
            });
        }

        // Apply severity cap from path-based exceptions
        apply_severity_exceptions(&file.path, &config.rules.exceptions, &mut findings);

        // Layer 3: Data flow analysis for each finding
        for finding in &mut findings {
            finding.data_flow = self.dataflow_analyzer.trace(file, finding);
        }

        // Remove findings whose data flow goes to an allowed sink
        findings.retain(|f| {
            if let Some(ref df) = f.data_flow {
                !self.dataflow_analyzer.is_allowed_sink(&df.sink.label)
            } else {
                true
            }
        });

        // Layer 4: Regulatory framework mapping
        for fw in &config.frameworks {
            self.framework_mapper.map_findings(&mut findings, *fw);
        }

        // Deduplicate by (file, line, pii_type)
        findings.sort_by(|a, b| {
            a.location
                .line
                .cmp(&b.location.line)
                .then(a.pii_type.as_str().cmp(b.pii_type.as_str()))
        });
        findings.dedup_by(|a, b| {
            a.location.line == b.location.line
                && a.location.file == b.location.file
                && a.pii_type == b.pii_type
        });

        findings
    }

    /// Multi-file analysis: runs intra-file analysis on all files, then
    /// builds a module graph and traces PII across file boundaries.
    pub fn analyze_project(
        &self,
        files: &[ParsedFile],
        config: &Config,
        project_root: &std::path::Path,
    ) -> Vec<Finding> {
        // Phase 1: Intra-file analysis on all files
        let mut all_findings: Vec<Finding> = Vec::new();
        for file in files {
            let findings = self.analyze(file, config);
            all_findings.extend(findings);
        }

        // Phase 2: Build module graph
        let graph = crossfile::build_module_graph(files, project_root);

        // Phase 3: Cross-file PII propagation
        let cross_findings = crossfile::analyze_cross_file(files, &graph, &all_findings);

        // Apply framework mappings to cross-file findings
        let mut cross_findings = cross_findings;
        for fw in &config.frameworks {
            self.framework_mapper.map_findings(&mut cross_findings, *fw);
        }

        all_findings.extend(cross_findings);

        // Final sort
        all_findings.sort_by(|a, b| {
            b.severity
                .cmp(&a.severity)
                .then(a.location.file.cmp(&b.location.file))
                .then(a.location.line.cmp(&b.location.line))
        });

        all_findings
    }
}

impl Default for DetectorPipeline {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Rule helpers
// ---------------------------------------------------------------------------

fn should_skip_file(path: &std::path::Path, exceptions: &[crate::config::ExceptionRule]) -> bool {
    let path_str = path.to_string_lossy();
    for rule in exceptions {
        if rule.action == "skip" && matches_any_glob(&path_str, &rule.paths) {
            return true;
        }
    }
    false
}

fn apply_severity_exceptions(
    path: &std::path::Path,
    exceptions: &[crate::config::ExceptionRule],
    findings: &mut Vec<Finding>,
) {
    let path_str = path.to_string_lossy();
    for rule in exceptions {
        if rule.action == "reduce_severity" && matches_any_glob(&path_str, &rule.paths) {
            if let Some(ref max_sev_str) = rule.max_severity {
                if let Ok(max_sev) = max_sev_str.parse::<crate::severity::Severity>() {
                    for f in findings.iter_mut() {
                        if f.severity > max_sev {
                            f.severity = max_sev;
                        }
                    }
                }
            }
        }
        if rule.action == "suppress_low" && matches_any_glob(&path_str, &rule.paths) {
            findings.retain(|f| f.severity > crate::severity::Severity::Low);
        }
    }
}

fn matches_any_glob(path: &str, patterns: &[String]) -> bool {
    let path_normalized = path.replace('\\', "/");
    for pattern in patterns {
        if let Ok(glob) = globset::Glob::new(pattern) {
            let matcher = glob.compile_matcher();
            if matcher.is_match(&path_normalized) {
                return true;
            }
        }
    }
    false
}
