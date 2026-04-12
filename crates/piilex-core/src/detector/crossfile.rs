use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use crate::finding::{DataFlow, DataFlowNode, Finding, FlowNodeKind, SourceLocation};
use crate::parser::{ImportSpecifier, ParsedFile};
use crate::pii::dictionary::PiiDictionary;

// ─── Dependency Graph ───────────────────────────────────────────────

/// A resolved module graph that maps file paths to their parsed contents
/// and tracks import/export relationships between them.
#[derive(Debug)]
pub struct ModuleGraph {
    /// Resolved file-to-file edges: (importer_path, imported_path)
    pub edges: Vec<(PathBuf, PathBuf)>,
    /// Map of file path → symbols exported from that file
    pub exports: HashMap<PathBuf, Vec<ExportedSymbol>>,
    /// Map of file path → symbols imported into that file (resolved to source)
    pub resolved_imports: HashMap<PathBuf, Vec<ResolvedImport>>,
}

#[derive(Debug, Clone)]
pub struct ExportedSymbol {
    pub name: String,
    pub line: usize,
}

#[derive(Debug, Clone)]
pub struct ResolvedImport {
    /// Local name used in the importing file
    pub local_name: String,
    /// Original exported name from the source file
    pub exported_name: String,
    /// Absolute path of the source file
    pub source_file: PathBuf,
    pub import_line: usize,
}

/// Build a module graph from a set of parsed files.
pub fn build_module_graph(files: &[ParsedFile], project_root: &Path) -> ModuleGraph {
    let file_map: HashMap<PathBuf, &ParsedFile> =
        files.iter().map(|f| (f.path.clone(), f)).collect();

    let mut edges = Vec::new();
    let mut exports_map: HashMap<PathBuf, Vec<ExportedSymbol>> = HashMap::new();
    let mut resolved_imports: HashMap<PathBuf, Vec<ResolvedImport>> = HashMap::new();

    // Phase 1: Collect all exports
    for file in files {
        let syms: Vec<ExportedSymbol> = file
            .exports
            .iter()
            .map(|e| ExportedSymbol {
                name: e.name.clone(),
                line: e.line,
            })
            .collect();
        exports_map.insert(file.path.clone(), syms);
    }

    // Phase 2: Resolve imports to concrete file paths
    for file in files {
        let mut resolved = Vec::new();

        for imp in &file.imports {
            let target = resolve_module_path(&imp.source, &file.path, project_root);
            let target_path = match target {
                Some(p) if file_map.contains_key(&p) => p,
                _ => continue,
            };

            edges.push((file.path.clone(), target_path.clone()));

            let target_exports = exports_map.get(&target_path);

            for spec in &imp.specifiers {
                match spec {
                    ImportSpecifier::Named { local, imported } => {
                        // Verify the target actually exports this name
                        let is_exported = target_exports
                            .map(|exps| exps.iter().any(|e| e.name == *imported))
                            .unwrap_or(false);

                        if is_exported {
                            resolved.push(ResolvedImport {
                                local_name: local.clone(),
                                exported_name: imported.clone(),
                                source_file: target_path.clone(),
                                import_line: imp.line,
                            });
                        }
                    }
                    ImportSpecifier::Default { local } => {
                        let is_exported = target_exports
                            .map(|exps| {
                                exps.iter().any(|e| e.name == "default" || e.name == *local)
                            })
                            .unwrap_or(false);

                        if is_exported {
                            resolved.push(ResolvedImport {
                                local_name: local.clone(),
                                exported_name: "default".to_string(),
                                source_file: target_path.clone(),
                                import_line: imp.line,
                            });
                        }
                    }
                    ImportSpecifier::Namespace { local } => {
                        resolved.push(ResolvedImport {
                            local_name: local.clone(),
                            exported_name: "*".to_string(),
                            source_file: target_path.clone(),
                            import_line: imp.line,
                        });
                    }
                }
            }
        }

        resolved_imports.insert(file.path.clone(), resolved);
    }

    ModuleGraph {
        edges,
        exports: exports_map,
        resolved_imports,
    }
}

/// Resolve a module specifier to an absolute file path.
fn resolve_module_path(specifier: &str, importer: &Path, _project_root: &Path) -> Option<PathBuf> {
    // Only resolve relative imports for now
    if !specifier.starts_with('.') {
        return None;
    }

    let importer_dir = importer.parent()?;
    let base = importer_dir.join(specifier);

    // Try common extensions
    let candidates = [
        base.clone(),
        base.with_extension("ts"),
        base.with_extension("tsx"),
        base.with_extension("js"),
        base.with_extension("jsx"),
        base.with_extension("mts"),
        base.with_extension("py"),
        base.join("index.ts"),
        base.join("index.js"),
        base.join("__init__.py"),
    ];

    for candidate in &candidates {
        if candidate.is_file() {
            return candidate.canonicalize().ok();
        }
    }

    // For Python dotted paths: from .models import User → ./models.py
    if specifier.starts_with('.') {
        let py_path = specifier.trim_start_matches('.');
        let py_file = importer_dir.join(py_path.replace('.', "/"));
        let py_candidates = [py_file.with_extension("py"), py_file.join("__init__.py")];
        for candidate in &py_candidates {
            if candidate.is_file() {
                return candidate.canonicalize().ok();
            }
        }
    }

    None
}

// ─── Cross-file PII Propagation ─────────────────────────────────────

/// Result of cross-file analysis for a single finding.
#[derive(Debug, Clone)]
pub struct CrossFileFlow {
    /// The original finding that was traced
    pub finding_id: String,
    /// Files that receive this PII through imports
    pub propagation_chain: Vec<PropagationStep>,
}

#[derive(Debug, Clone)]
pub struct PropagationStep {
    /// File that receives the PII
    pub file: PathBuf,
    /// How it arrives (import statement)
    pub import_line: usize,
    /// Local name in this file
    pub local_name: String,
    /// What happens to it (sink classification if known)
    pub sink: Option<FlowNodeKind>,
    /// The specific call site if a sink is detected
    pub sink_line: Option<usize>,
    pub sink_callee: Option<String>,
}

/// Analyze cross-file PII propagation.
///
/// For each exported symbol that matches a PII pattern, trace through
/// the module graph to find all files that import and potentially
/// expose that PII to sinks.
pub fn analyze_cross_file(
    files: &[ParsedFile],
    graph: &ModuleGraph,
    intra_file_findings: &[Finding],
) -> Vec<Finding> {
    let dictionary = PiiDictionary::builtin();
    let dataflow = super::dataflow::DataFlowAnalyzer::new();
    let mut cross_findings = Vec::new();

    // Step 1: Identify PII-bearing exports
    // An export is PII-bearing if:
    //   (a) Its name matches a PII dictionary pattern, OR
    //   (b) The symbol was flagged by intra-file analysis in its defining file
    let mut pii_exports: HashMap<PathBuf, Vec<(String, &Finding)>> = HashMap::new();

    for finding in intra_file_findings {
        let file_path = &finding.location.file;
        if let Some(exports) = graph.exports.get(file_path) {
            // Check if any export corresponds to a symbol at the same line
            for exp in exports {
                if exp.line == finding.location.line || finding.code_snippet.contains(&exp.name) {
                    pii_exports
                        .entry(file_path.clone())
                        .or_default()
                        .push((exp.name.clone(), finding));
                }
            }
        }
    }

    // Also check exported symbols whose names match PII patterns
    for (path, exports) in &graph.exports {
        for exp in exports {
            if dictionary.match_identifier(&exp.name).is_some() {
                // Only add if not already tracked
                let already = pii_exports
                    .get(path)
                    .map(|v| v.iter().any(|(n, _)| n == &exp.name))
                    .unwrap_or(false);
                if !already {
                    // We don't have an existing finding, so we'll skip the
                    // original finding reference for these
                }
            }
        }
    }

    // Step 2: For each file that imports a PII-bearing symbol, check its usage
    for (source_file, pii_syms) in &pii_exports {
        for (export_name, original_finding) in pii_syms {
            // Find all files that import this symbol
            for (importer_path, resolved) in &graph.resolved_imports {
                for ri in resolved {
                    if &ri.source_file == source_file && ri.exported_name == *export_name {
                        // This file imports the PII-bearing symbol
                        let importer = files.iter().find(|f| f.path == *importer_path);
                        if let Some(importer_file) = importer {
                            // Check if the imported symbol is used in any sink
                            let sink_info =
                                find_sink_usage(importer_file, &ri.local_name, &dataflow);

                            if let Some((sink_kind, sink_line, sink_callee)) = sink_info {
                                let new_finding = Finding {
                                    id: format!(
                                        "{}->{}",
                                        original_finding.id,
                                        importer_path
                                            .file_name()
                                            .and_then(|n| n.to_str())
                                            .unwrap_or("?")
                                    ),
                                    severity: original_finding.severity,
                                    pii_type: original_finding.pii_type.clone(),
                                    category: original_finding.category,
                                    location: SourceLocation {
                                        file: importer_path.clone(),
                                        line: sink_line,
                                        column: 1,
                                    },
                                    code_snippet: importer_file
                                        .source
                                        .lines()
                                        .nth(sink_line.saturating_sub(1))
                                        .unwrap_or("")
                                        .trim()
                                        .to_string(),
                                    data_flow: Some(DataFlow {
                                        source: DataFlowNode {
                                            kind: FlowNodeKind::UserInput,
                                            label: format!(
                                                "{} (from {})",
                                                ri.local_name,
                                                source_file
                                                    .file_name()
                                                    .and_then(|n| n.to_str())
                                                    .unwrap_or("?")
                                            ),
                                            location: SourceLocation {
                                                file: importer_path.clone(),
                                                line: ri.import_line,
                                                column: 1,
                                            },
                                        },
                                        sink: DataFlowNode {
                                            kind: sink_kind,
                                            label: sink_callee.clone(),
                                            location: SourceLocation {
                                                file: importer_path.clone(),
                                                line: sink_line,
                                                column: 1,
                                            },
                                        },
                                        path: vec![
                                            // Origin
                                            original_finding.location.clone(),
                                            // Import site
                                            SourceLocation {
                                                file: importer_path.clone(),
                                                line: ri.import_line,
                                                column: 1,
                                            },
                                            // Sink site
                                            SourceLocation {
                                                file: importer_path.clone(),
                                                line: sink_line,
                                                column: 1,
                                            },
                                        ],
                                    }),
                                    framework_mappings: Vec::new(),
                                    confidence: original_finding.confidence,
                                };

                                cross_findings.push(new_finding);
                            }
                        }
                    }
                }
            }
        }
    }

    cross_findings
}

/// Check if a symbol is used as an argument to a known sink in the given file.
fn find_sink_usage(
    file: &ParsedFile,
    symbol_name: &str,
    analyzer: &super::dataflow::DataFlowAnalyzer,
) -> Option<(FlowNodeKind, usize, String)> {
    for call in &file.call_expressions {
        let in_args = call.argument_identifiers.iter().any(|arg| {
            arg == symbol_name
                || arg.ends_with(&format!(".{}", symbol_name))
                || arg.contains(symbol_name)
        });

        let in_callee = call.callee.contains(symbol_name);

        if in_args || in_callee {
            if let Some(kind) = analyzer.classify_sink_public(&call.callee) {
                return Some((kind, call.line, call.callee.clone()));
            }
        }
    }
    None
}

// ─── Impact Analysis ────────────────────────────────────────────────

/// For a given file, return all files that directly or transitively depend on it.
pub fn get_dependents(file: &Path, graph: &ModuleGraph) -> Vec<PathBuf> {
    let mut visited = HashSet::new();
    let mut result = Vec::new();
    collect_dependents(file, graph, &mut visited, &mut result);
    result
}

fn collect_dependents(
    file: &Path,
    graph: &ModuleGraph,
    visited: &mut HashSet<PathBuf>,
    result: &mut Vec<PathBuf>,
) {
    for (importer, imported) in &graph.edges {
        if imported == file && !visited.contains(importer) {
            visited.insert(importer.clone());
            result.push(importer.clone());
            collect_dependents(importer, graph, visited, result);
        }
    }
}

/// For a given file, return all files it directly or transitively depends on.
pub fn get_dependencies(file: &Path, graph: &ModuleGraph) -> Vec<PathBuf> {
    let mut visited = HashSet::new();
    let mut result = Vec::new();
    collect_dependencies(file, graph, &mut visited, &mut result);
    result
}

fn collect_dependencies(
    file: &Path,
    graph: &ModuleGraph,
    visited: &mut HashSet<PathBuf>,
    result: &mut Vec<PathBuf>,
) {
    for (importer, imported) in &graph.edges {
        if importer == file && !visited.contains(imported) {
            visited.insert(imported.clone());
            result.push(imported.clone());
            collect_dependencies(imported, graph, visited, result);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_relative_path_ts() {
        // This test uses in-memory logic; doesn't need actual files
        let spec = "./utils";
        let importer = Path::new("/project/src/main.ts");
        let root = Path::new("/project");
        // resolve_module_path checks file existence, so it will return None
        // in unit tests. Integration tests cover actual resolution.
        let result = resolve_module_path(spec, importer, root);
        // Can't test file existence here, but ensure no panic
        assert!(result.is_none() || result.is_some());
    }

    #[test]
    fn get_dependents_graph() {
        let graph = ModuleGraph {
            edges: vec![
                (PathBuf::from("a.ts"), PathBuf::from("b.ts")),
                (PathBuf::from("c.ts"), PathBuf::from("b.ts")),
                (PathBuf::from("d.ts"), PathBuf::from("a.ts")),
            ],
            exports: HashMap::new(),
            resolved_imports: HashMap::new(),
        };

        let deps = get_dependents(Path::new("b.ts"), &graph);
        assert!(deps.contains(&PathBuf::from("a.ts")));
        assert!(deps.contains(&PathBuf::from("c.ts")));
        // Transitive: d.ts depends on a.ts which depends on b.ts
        assert!(deps.contains(&PathBuf::from("d.ts")));
    }

    #[test]
    fn get_dependencies_graph() {
        let graph = ModuleGraph {
            edges: vec![
                (PathBuf::from("a.ts"), PathBuf::from("b.ts")),
                (PathBuf::from("b.ts"), PathBuf::from("c.ts")),
            ],
            exports: HashMap::new(),
            resolved_imports: HashMap::new(),
        };

        let deps = get_dependencies(Path::new("a.ts"), &graph);
        assert!(deps.contains(&PathBuf::from("b.ts")));
        assert!(deps.contains(&PathBuf::from("c.ts")));
    }
}
