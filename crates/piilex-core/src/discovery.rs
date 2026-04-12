use crate::config::ScanConfig;
use globset::{Glob, GlobSet, GlobSetBuilder};
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

pub struct FileDiscovery {
    exclude_set: GlobSet,
    include_set: Option<GlobSet>,
    max_file_size: usize,
}

#[derive(Debug)]
pub struct DiscoveryResult {
    pub files: Vec<PathBuf>,
    pub skipped: usize,
}

impl FileDiscovery {
    pub fn new(config: &ScanConfig) -> Result<Self, globset::Error> {
        let mut exclude_builder = GlobSetBuilder::new();
        for pattern in &config.exclude {
            exclude_builder.add(Glob::new(pattern)?);
        }

        let include_set = if config.include.is_empty() {
            None
        } else {
            let mut builder = GlobSetBuilder::new();
            for pattern in &config.include {
                builder.add(Glob::new(pattern)?);
            }
            Some(builder.build()?)
        };

        Ok(Self {
            exclude_set: exclude_builder.build()?,
            include_set,
            max_file_size: config.max_file_size,
        })
    }

    pub fn discover(&self, root: &Path) -> DiscoveryResult {
        let mut files = Vec::new();
        let mut skipped = 0;

        let walker = WalkDir::new(root)
            .follow_links(false)
            .into_iter()
            .filter_entry(|e| {
                let path = e.path();
                if let Ok(rel) = path.strip_prefix(root) {
                    let rel_str = rel.to_string_lossy();
                    if rel_str.is_empty() {
                        return true;
                    }
                    !self.exclude_set.is_match(rel_str.as_ref())
                } else {
                    true
                }
            });

        for entry in walker {
            let entry = match entry {
                Ok(e) => e,
                Err(_) => {
                    skipped += 1;
                    continue;
                }
            };

            if !entry.file_type().is_file() {
                continue;
            }

            let path = entry.path();

            // Check extension for supported languages
            if !is_supported_extension(path) {
                continue;
            }

            // Check file size
            if let Ok(meta) = entry.metadata() {
                if meta.len() as usize > self.max_file_size {
                    skipped += 1;
                    continue;
                }
            }

            // Check include filter
            if let Some(ref include_set) = self.include_set {
                if let Ok(rel) = path.strip_prefix(root) {
                    if !include_set.is_match(rel) {
                        continue;
                    }
                }
            }

            files.push(path.to_path_buf());
        }

        DiscoveryResult { files, skipped }
    }
}

fn is_supported_extension(path: &Path) -> bool {
    detect_language(path).is_some()
}

pub fn detect_language(path: &Path) -> Option<Language> {
    match path.extension().and_then(|e| e.to_str()) {
        #[cfg(feature = "lang-typescript")]
        Some("ts" | "tsx" | "mts") => Some(Language::TypeScript),
        #[cfg(feature = "lang-javascript")]
        Some("js" | "jsx" | "mjs") => Some(Language::JavaScript),
        #[cfg(feature = "lang-python")]
        Some("py") => Some(Language::Python),
        #[cfg(feature = "lang-go")]
        Some("go") => Some(Language::Go),
        #[cfg(feature = "lang-java")]
        Some("java") => Some(Language::Java),
        #[cfg(feature = "lang-csharp")]
        Some("cs") => Some(Language::CSharp),
        _ => None,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Language {
    #[cfg(feature = "lang-typescript")]
    TypeScript,
    #[cfg(feature = "lang-javascript")]
    JavaScript,
    #[cfg(feature = "lang-python")]
    Python,
    #[cfg(feature = "lang-go")]
    Go,
    #[cfg(feature = "lang-java")]
    Java,
    #[cfg(feature = "lang-csharp")]
    CSharp,
}

impl Language {
    pub fn as_str(&self) -> &'static str {
        match self {
            #[cfg(feature = "lang-typescript")]
            Language::TypeScript => "typescript",
            #[cfg(feature = "lang-javascript")]
            Language::JavaScript => "javascript",
            #[cfg(feature = "lang-python")]
            Language::Python => "python",
            #[cfg(feature = "lang-go")]
            Language::Go => "go",
            #[cfg(feature = "lang-java")]
            Language::Java => "java",
            #[cfg(feature = "lang-csharp")]
            Language::CSharp => "csharp",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_supported_extensions() {
        assert!(is_supported_extension(Path::new("foo.ts")));
        assert!(is_supported_extension(Path::new("bar.py")));
        assert!(is_supported_extension(Path::new("baz.js")));
        assert!(!is_supported_extension(Path::new("foo.rs")));
        assert!(!is_supported_extension(Path::new("readme.md")));
    }

    #[test]
    fn test_detect_language() {
        assert_eq!(
            detect_language(Path::new("a.ts")),
            Some(Language::TypeScript)
        );
        assert_eq!(
            detect_language(Path::new("a.tsx")),
            Some(Language::TypeScript)
        );
        assert_eq!(detect_language(Path::new("a.py")), Some(Language::Python));
        assert_eq!(
            detect_language(Path::new("a.js")),
            Some(Language::JavaScript)
        );
        assert_eq!(detect_language(Path::new("a.rs")), None);
    }
}
