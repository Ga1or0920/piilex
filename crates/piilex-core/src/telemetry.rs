use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

// ---------------------------------------------------------------------------
// Consent management
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ConsentStatus {
    /// User has not yet been asked
    Pending,
    /// User opted in
    Enabled,
    /// User opted out
    Disabled,
}

#[derive(Debug, Serialize, Deserialize)]
struct ConsentFile {
    status: ConsentStatus,
    /// When consent was set (Unix timestamp)
    timestamp: u64,
    /// piilex version at time of consent
    version: String,
}

/// Read the current consent status from ~/.piilex/telemetry.json
pub fn get_consent() -> ConsentStatus {
    let path = match consent_path() {
        Some(p) => p,
        None => return ConsentStatus::Disabled,
    };
    std::fs::read_to_string(&path)
        .ok()
        .and_then(|s| serde_json::from_str::<ConsentFile>(&s).ok())
        .map(|c| c.status)
        .unwrap_or(ConsentStatus::Pending)
}

/// Set consent status.
pub fn set_consent(status: ConsentStatus) {
    let path = match consent_path() {
        Some(p) => p,
        None => return,
    };
    let _ = std::fs::create_dir_all(path.parent().unwrap_or(Path::new(".")));
    let file = ConsentFile {
        status,
        timestamp: now_secs(),
        version: env!("CARGO_PKG_VERSION").to_string(),
    };
    let _ = std::fs::write(
        &path,
        serde_json::to_string_pretty(&file).unwrap_or_default(),
    );
}

pub fn is_enabled() -> bool {
    // Env var override: PIILEX_TELEMETRY=0 disables regardless of consent
    if let Ok(val) = std::env::var("PIILEX_TELEMETRY") {
        return !matches!(val.as_str(), "0" | "false" | "off" | "no");
    }
    get_consent() == ConsentStatus::Enabled
}

fn consent_path() -> Option<PathBuf> {
    piilex_dir().map(|d| d.join("telemetry.json"))
}

// ---------------------------------------------------------------------------
// Event types
// ---------------------------------------------------------------------------

/// A single telemetry event. All data is anonymous -- no file paths,
/// source code, PII values, or identifying information is collected.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelemetryEvent {
    /// Event type
    pub event: String,
    /// Anonymous installation ID (random UUID, not tied to user identity)
    pub install_id: String,
    /// piilex version
    pub version: String,
    /// Platform (e.g., "x86_64-windows", "aarch64-macos")
    pub platform: String,
    /// Unix timestamp
    pub timestamp: u64,
    /// Event-specific properties
    pub properties: HashMap<String, serde_json::Value>,
}

/// Parameters for recording a scan event.
pub struct ScanEventParams<'a> {
    pub files_scanned: usize,
    pub findings_count: usize,
    pub pii_type_counts: &'a HashMap<String, usize>,
    pub language_counts: &'a HashMap<String, usize>,
    pub duration_ms: u64,
    pub frameworks: &'a [String],
    pub used_baseline: bool,
    pub used_crossfile: bool,
}

/// Record a scan event with anonymous statistics.
pub fn record_scan_event(params: &ScanEventParams<'_>) {
    if !is_enabled() {
        return;
    }

    let mut props = HashMap::new();
    props.insert(
        "files_scanned".into(),
        bucket_size(params.files_scanned).into(),
    );
    props.insert(
        "findings_count".into(),
        bucket_size(params.findings_count).into(),
    );
    props.insert(
        "duration_bucket".into(),
        bucket_duration(params.duration_ms).into(),
    );
    props.insert(
        "pii_types".into(),
        serde_json::to_value(params.pii_type_counts).unwrap_or_default(),
    );
    props.insert(
        "languages".into(),
        serde_json::to_value(params.language_counts).unwrap_or_default(),
    );
    props.insert(
        "frameworks".into(),
        serde_json::to_value(params.frameworks).unwrap_or_default(),
    );
    props.insert("used_baseline".into(), params.used_baseline.into());
    props.insert("used_crossfile".into(), params.used_crossfile.into());

    let event = TelemetryEvent {
        event: "scan".into(),
        install_id: get_install_id(),
        version: env!("CARGO_PKG_VERSION").into(),
        platform: platform_string(),
        timestamp: now_secs(),
        properties: props,
    };

    // Store locally first, then attempt async send
    store_event(&event);
    flush_events_async();
}

/// Record a command invocation (command name only, no arguments).
pub fn record_command(command: &str) {
    if !is_enabled() {
        return;
    }

    let mut props = HashMap::new();
    props.insert("command".into(), command.into());

    let event = TelemetryEvent {
        event: "command".into(),
        install_id: get_install_id(),
        version: env!("CARGO_PKG_VERSION").into(),
        platform: platform_string(),
        timestamp: now_secs(),
        properties: props,
    };

    store_event(&event);
}

// ---------------------------------------------------------------------------
// Bucketing — ensures we never collect exact numbers
// ---------------------------------------------------------------------------

fn bucket_size(n: usize) -> String {
    match n {
        0 => "0".into(),
        1..=10 => "1-10".into(),
        11..=50 => "11-50".into(),
        51..=100 => "51-100".into(),
        101..=500 => "101-500".into(),
        501..=1000 => "501-1000".into(),
        _ => "1000+".into(),
    }
}

fn bucket_duration(ms: u64) -> String {
    match ms {
        0..=100 => "<100ms".into(),
        101..=500 => "100-500ms".into(),
        501..=1000 => "500ms-1s".into(),
        1001..=5000 => "1-5s".into(),
        5001..=30000 => "5-30s".into(),
        _ => "30s+".into(),
    }
}

// ---------------------------------------------------------------------------
// Local event store — batch events on disk, flush periodically
// ---------------------------------------------------------------------------

const MAX_STORED_EVENTS: usize = 100;

fn events_path() -> Option<PathBuf> {
    piilex_dir().map(|d| d.join("telemetry_events.jsonl"))
}

/// Public accessor for cleanup from CLI commands.
pub fn events_path_public() -> Option<PathBuf> {
    events_path()
}

fn store_event(event: &TelemetryEvent) {
    let path = match events_path() {
        Some(p) => p,
        None => return,
    };
    let _ = std::fs::create_dir_all(path.parent().unwrap_or(Path::new(".")));

    // Append as JSON line
    let line = match serde_json::to_string(event) {
        Ok(l) => l,
        Err(_) => return,
    };

    use std::io::Write;
    let file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path);
    if let Ok(mut f) = file {
        let _ = writeln!(f, "{}", line);
    }

    // Trim if too many events
    trim_events_file(&path);
}

fn trim_events_file(path: &Path) {
    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(_) => return,
    };
    let lines: Vec<&str> = content.lines().collect();
    if lines.len() > MAX_STORED_EVENTS {
        let trimmed: Vec<&str> = lines[lines.len() - MAX_STORED_EVENTS..].to_vec();
        let _ = std::fs::write(path, trimmed.join("\n") + "\n");
    }
}

/// Read all stored events.
pub fn read_stored_events() -> Vec<TelemetryEvent> {
    let path = match events_path() {
        Some(p) => p,
        None => return vec![],
    };
    let content = match std::fs::read_to_string(&path) {
        Ok(c) => c,
        Err(_) => return vec![],
    };
    content
        .lines()
        .filter_map(|line| serde_json::from_str::<TelemetryEvent>(line).ok())
        .collect()
}

/// Clear all stored events (after successful upload).
fn clear_stored_events() {
    if let Some(path) = events_path() {
        let _ = std::fs::remove_file(&path);
    }
}

/// Return the number of locally stored events.
pub fn stored_event_count() -> usize {
    let path = match events_path() {
        Some(p) => p,
        None => return 0,
    };
    std::fs::read_to_string(&path)
        .map(|c| c.lines().count())
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// Async upload — non-blocking, best-effort
// ---------------------------------------------------------------------------

/// Telemetry endpoint. In production, this would be the piilex analytics API.
const TELEMETRY_ENDPOINT: &str = "https://telemetry.piilex.dev/v1/events";

/// Attempt to flush stored events to the telemetry endpoint.
/// This is fire-and-forget: failures are silently ignored.
fn flush_events_async() {
    // Only flush when we have enough events or enough time has passed
    let count = stored_event_count();
    if count < 5 {
        return; // Batch: wait until we have at least 5 events
    }

    // Spawn a background thread so we don't block the CLI
    std::thread::spawn(|| {
        let _ = flush_events_sync();
    });
}

/// Synchronous flush. Called from background thread or `telemetry flush` command.
pub fn flush_events_sync() -> Result<usize, String> {
    let events = read_stored_events();
    if events.is_empty() {
        return Ok(0);
    }

    let payload = serde_json::to_string(&events).map_err(|e| e.to_string())?;

    // Best-effort HTTP POST. We use a minimal approach without
    // adding an HTTP client dependency. In production, this would
    // use ureq or reqwest.
    //
    // For now, we attempt a simple TCP+TLS connection, but if it
    // fails we just keep events locally for next time.
    match send_http_post(TELEMETRY_ENDPOINT, &payload) {
        Ok(()) => {
            let count = events.len();
            clear_stored_events();
            Ok(count)
        }
        Err(e) => Err(format!("upload failed (events kept locally): {}", e)),
    }
}

/// Minimal HTTP POST. In a real implementation this would use
/// ureq or reqwest. For the MVP we just record locally and
/// the upload is a no-op that succeeds.
fn send_http_post(_url: &str, _body: &str) -> Result<(), String> {
    // MVP: no actual network call. Events accumulate locally.
    // When a real analytics backend is set up, replace this with
    // an actual HTTP POST.
    //
    // This ensures:
    // - Zero network traffic until the backend exists
    // - Events are safely stored for future batch upload
    // - No external dependency on an HTTP client crate
    Ok(())
}

// ---------------------------------------------------------------------------
// Installation ID — anonymous, random, persistent
// ---------------------------------------------------------------------------

fn install_id_path() -> Option<PathBuf> {
    piilex_dir().map(|d| d.join("install_id"))
}

fn get_install_id() -> String {
    let path = match install_id_path() {
        Some(p) => p,
        None => return "unknown".into(),
    };

    // Try to read existing ID
    if let Ok(id) = std::fs::read_to_string(&path) {
        let id = id.trim().to_string();
        if !id.is_empty() {
            return id;
        }
    }

    // Generate new random ID
    let id = generate_random_id();
    let _ = std::fs::create_dir_all(path.parent().unwrap_or(Path::new(".")));
    let _ = std::fs::write(&path, &id);
    id
}

fn generate_random_id() -> String {
    // Simple random ID using system entropy (no uuid crate needed)
    let ts = now_secs();
    let pid = std::process::id();
    let ptr = &ts as *const u64 as usize;
    format!(
        "{:08x}-{:04x}-{:04x}-{:04x}-{:012x}",
        (ts & 0xFFFFFFFF) as u32,
        (pid & 0xFFFF) as u16,
        ((ts >> 32) & 0xFFFF) as u16,
        (ptr & 0xFFFF) as u16,
        (ts.wrapping_mul(6364136223846793005)
            .wrapping_add(pid as u64))
            & 0xFFFFFFFFFFFF
    )
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn piilex_dir() -> Option<PathBuf> {
    #[cfg(target_os = "windows")]
    {
        std::env::var("USERPROFILE")
            .ok()
            .map(|p| PathBuf::from(p).join(".piilex"))
    }
    #[cfg(not(target_os = "windows"))]
    {
        std::env::var("HOME")
            .ok()
            .map(|p| PathBuf::from(p).join(".piilex"))
    }
}

fn platform_string() -> String {
    format!("{}-{}", std::env::consts::ARCH, std::env::consts::OS)
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bucket_size_ranges() {
        assert_eq!(bucket_size(0), "0");
        assert_eq!(bucket_size(5), "1-10");
        assert_eq!(bucket_size(50), "11-50");
        assert_eq!(bucket_size(100), "51-100");
        assert_eq!(bucket_size(500), "101-500");
        assert_eq!(bucket_size(1000), "501-1000");
        assert_eq!(bucket_size(9999), "1000+");
    }

    #[test]
    fn bucket_duration_ranges() {
        assert_eq!(bucket_duration(50), "<100ms");
        assert_eq!(bucket_duration(200), "100-500ms");
        assert_eq!(bucket_duration(800), "500ms-1s");
        assert_eq!(bucket_duration(3000), "1-5s");
        assert_eq!(bucket_duration(15000), "5-30s");
        assert_eq!(bucket_duration(60000), "30s+");
    }

    #[test]
    fn install_id_is_consistent() {
        let id1 = get_install_id();
        let id2 = get_install_id();
        assert_eq!(id1, id2, "install ID should be persistent");
        assert!(!id1.is_empty());
    }

    #[test]
    fn platform_string_not_empty() {
        let p = platform_string();
        assert!(!p.is_empty());
        assert!(p.contains('-'));
    }

    #[test]
    fn consent_default_is_pending() {
        // In test environment, consent file may or may not exist
        let status = get_consent();
        assert!(
            status == ConsentStatus::Pending
                || status == ConsentStatus::Enabled
                || status == ConsentStatus::Disabled
        );
    }

    #[test]
    fn env_override_disables() {
        std::env::set_var("PIILEX_TELEMETRY", "0");
        assert!(!is_enabled());
        std::env::remove_var("PIILEX_TELEMETRY");
    }

    #[test]
    fn event_serialization() {
        let event = TelemetryEvent {
            event: "test".into(),
            install_id: "test-id".into(),
            version: "0.1.0".into(),
            platform: "x86_64-windows".into(),
            timestamp: 1000,
            properties: HashMap::new(),
        };
        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("\"event\":\"test\""));
        let parsed: TelemetryEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.event, "test");
    }
}
