use crate::discovery::detect_language;
use crate::parser::{parse_file, ParsedFile};
use rayon::prelude::*;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};

/// Result of parallel file parsing.
pub struct ParallelParseResult {
    pub files: Vec<ParsedFile>,
    pub warnings: Vec<String>,
    pub skipped: usize,
}

/// Parse all discovered files in parallel using rayon.
///
/// Each file gets its own tree-sitter Parser (Parser is !Send,
/// so we create one per rayon task). This is the recommended
/// approach from the tree-sitter documentation.
pub fn parse_files_parallel(file_paths: &[PathBuf], max_file_size: usize) -> ParallelParseResult {
    let skipped = AtomicUsize::new(0);

    let results: Vec<Option<(ParsedFile, Vec<String>)>> = file_paths
        .par_iter()
        .map(|file_path| {
            // Detect language
            let language = match detect_language(file_path) {
                Some(l) => l,
                None => return None,
            };

            // Read file
            let source = match std::fs::read_to_string(file_path) {
                Ok(s) => {
                    if s.len() > max_file_size {
                        skipped.fetch_add(1, Ordering::Relaxed);
                        return None;
                    }
                    s
                }
                Err(_) => {
                    skipped.fetch_add(1, Ordering::Relaxed);
                    return None;
                }
            };

            // Parse (each thread creates its own Parser)
            let parsed = parse_file(file_path, &source, language);
            let warnings: Vec<String> = parsed.warnings.iter().map(|w| format!("{}", w)).collect();

            Some((parsed, warnings))
        })
        .collect();

    let mut files = Vec::with_capacity(results.len());
    let mut all_warnings = Vec::new();

    for result in results.into_iter().flatten() {
        let (parsed, warnings) = result;
        all_warnings.extend(warnings);
        files.push(parsed);
    }

    ParallelParseResult {
        files,
        warnings: all_warnings,
        skipped: skipped.load(Ordering::Relaxed),
    }
}

/// Memory usage snapshot (approximate, platform-specific).
pub fn memory_usage_bytes() -> usize {
    #[cfg(target_os = "windows")]
    {
        // Use GetProcessMemoryInfo on Windows
        use std::mem::MaybeUninit;
        #[repr(C)]
        struct ProcessMemoryCounters {
            cb: u32,
            page_fault_count: u32,
            peak_working_set_size: usize,
            working_set_size: usize,
            quota_peak_paged_pool_usage: usize,
            quota_paged_pool_usage: usize,
            quota_peak_non_paged_pool_usage: usize,
            quota_non_paged_pool_usage: usize,
            pagefile_usage: usize,
            peak_pagefile_usage: usize,
        }

        extern "system" {
            fn GetCurrentProcess() -> isize;
            fn K32GetProcessMemoryInfo(
                process: isize,
                ppsmemcounters: *mut ProcessMemoryCounters,
                cb: u32,
            ) -> i32;
        }

        unsafe {
            let mut counters = MaybeUninit::<ProcessMemoryCounters>::zeroed().assume_init();
            counters.cb = std::mem::size_of::<ProcessMemoryCounters>() as u32;
            let handle = GetCurrentProcess();
            if K32GetProcessMemoryInfo(handle, &mut counters, counters.cb) != 0 {
                return counters.working_set_size;
            }
        }
        0
    }

    #[cfg(target_os = "linux")]
    {
        // Read /proc/self/statm
        if let Ok(statm) = std::fs::read_to_string("/proc/self/statm") {
            if let Some(rss) = statm.split_whitespace().nth(1) {
                if let Ok(pages) = rss.parse::<usize>() {
                    return pages * 4096; // page size
                }
            }
        }
        0
    }

    #[cfg(target_os = "macos")]
    {
        0 // Not easily available without mach APIs
    }

    #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
    {
        0
    }
}

/// Format bytes as human-readable string.
pub fn format_bytes(bytes: usize) -> String {
    if bytes < 1024 {
        format!("{} B", bytes)
    } else if bytes < 1024 * 1024 {
        format!("{:.1} KB", bytes as f64 / 1024.0)
    } else if bytes < 1024 * 1024 * 1024 {
        format!("{:.1} MB", bytes as f64 / (1024.0 * 1024.0))
    } else {
        format!("{:.2} GB", bytes as f64 / (1024.0 * 1024.0 * 1024.0))
    }
}
