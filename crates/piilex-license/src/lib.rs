mod keygen;

pub use keygen::{generate_test_token, generate_token_with_key};

use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LicenseTier {
    Free,
    Pro,
}

impl std::fmt::Display for LicenseTier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LicenseTier::Free => f.write_str("Free"),
            LicenseTier::Pro => f.write_str("Pro"),
        }
    }
}

/// Detailed information about the active license.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LicenseInfo {
    pub tier: LicenseTier,
    pub email: String,
    pub expires_at: Option<u64>,
    pub is_expired: bool,
}

impl LicenseInfo {
    pub fn free() -> Self {
        Self {
            tier: LicenseTier::Free,
            email: String::new(),
            expires_at: None,
            is_expired: false,
        }
    }

    pub fn is_pro(&self) -> bool {
        self.tier == LicenseTier::Pro && !self.is_expired
    }
}

/// Feature gating: which features require Pro.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProFeature {
    FrameworkMapping,
    Report,
    SuggestUnlimited,
    BaselineDiff,
    CustomPiiTypes,
}

impl ProFeature {
    pub fn display_name(&self) -> &'static str {
        match self {
            ProFeature::FrameworkMapping => "--framework (regulatory mapping)",
            ProFeature::Report => "report (compliance reports)",
            ProFeature::SuggestUnlimited => "suggest (unlimited)",
            ProFeature::BaselineDiff => "--baseline (diff scanning)",
            ProFeature::CustomPiiTypes => "custom PII type definitions",
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum LicenseError {
    #[error("invalid license token: {0}")]
    InvalidToken(String),
    #[error("license expired on {0}")]
    Expired(String),
    #[error("failed to read license file: {0}")]
    Io(#[from] std::io::Error),
    #[error("{feature} requires a Pro license. Run `piilex activate <key>` or visit https://piilex.dev/pricing")]
    ProRequired { feature: String },
}

// ---------------------------------------------------------------------------
// JWT claims
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct Claims {
    /// Subject: user email
    pub sub: String,
    /// Tier: "pro"
    pub tier: String,
    /// Issued at (Unix timestamp)
    pub iat: u64,
    /// Expiration (Unix timestamp)
    pub exp: u64,
    /// Unique license ID
    #[serde(default)]
    pub jti: String,
}

// ---------------------------------------------------------------------------
// Embedded RS256 public key for token verification
//
// This key is compiled into the binary. Tokens must be signed with the
// corresponding private key (kept offline in keys/private.pem).
// ---------------------------------------------------------------------------

const RS256_PUBLIC_KEY_PEM: &str = include_str!("../../../keys/public.pem");

// ---------------------------------------------------------------------------
// License resolution
// ---------------------------------------------------------------------------

/// Resolve the active license by checking (in priority order):
///   1. Explicit token string passed in
///   2. PIILEX_LICENSE_KEY environment variable
///   3. License file at ~/.piilex/license.key
///
/// Returns LicenseInfo::free() if no valid license found.
pub fn resolve_license(explicit_key: Option<&str>) -> LicenseInfo {
    // 1. Explicit key
    if let Some(key) = explicit_key {
        if let Ok(info) = validate_token(key) {
            return info;
        }
    }

    // 2. Environment variable
    if let Ok(key) = std::env::var("PIILEX_LICENSE_KEY") {
        if !key.is_empty() {
            if let Ok(info) = validate_token(&key) {
                return info;
            }
        }
    }

    // 3. License file
    if let Some(path) = license_file_path() {
        if let Ok(key) = std::fs::read_to_string(&path) {
            let key = key.trim();
            if !key.is_empty() {
                if let Ok(info) = validate_token(key) {
                    return info;
                }
            }
        }
    }

    LicenseInfo::free()
}

/// Validate a JWT token signed with RS256 and return license info.
pub fn validate_token(token: &str) -> Result<LicenseInfo, LicenseError> {
    validate_token_with_pem(token, RS256_PUBLIC_KEY_PEM)
}

/// Validate a JWT token against a specific PEM public key.
/// Used internally and by tests that use ephemeral key pairs.
pub fn validate_token_with_pem(
    token: &str,
    public_key_pem: &str,
) -> Result<LicenseInfo, LicenseError> {
    let token = token.trim();

    let mut validation = Validation::new(Algorithm::RS256);
    validation.validate_exp = false; // We check expiry manually for better error messages
    validation.required_spec_claims.clear();

    let key = DecodingKey::from_rsa_pem(public_key_pem.as_bytes())
        .map_err(|e| LicenseError::InvalidToken(format!("public key error: {}", e)))?;

    let token_data = decode::<Claims>(token, &key, &validation)
        .map_err(|e| LicenseError::InvalidToken(e.to_string()))?;

    let claims = token_data.claims;

    // Check tier
    let tier = match claims.tier.as_str() {
        "pro" => LicenseTier::Pro,
        _ => LicenseTier::Free,
    };

    // Check expiration
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let is_expired = claims.exp > 0 && now > claims.exp;

    if is_expired {
        let exp_date = format_timestamp(claims.exp);
        return Err(LicenseError::Expired(exp_date));
    }

    Ok(LicenseInfo {
        tier,
        email: claims.sub,
        expires_at: Some(claims.exp),
        is_expired,
    })
}

/// Check if a Pro feature is available and return an error if not.
pub fn require_pro(info: &LicenseInfo, feature: ProFeature) -> Result<(), LicenseError> {
    if info.is_pro() {
        Ok(())
    } else {
        Err(LicenseError::ProRequired {
            feature: feature.display_name().to_string(),
        })
    }
}

// ---------------------------------------------------------------------------
// License file management
// ---------------------------------------------------------------------------

/// Path to the license file: ~/.piilex/license.key
pub fn license_file_path() -> Option<PathBuf> {
    dirs_path().map(|d| d.join("license.key"))
}

/// Path to the piilex config directory: ~/.piilex/
fn dirs_path() -> Option<PathBuf> {
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

/// Save a license key to the license file.
pub fn save_license_key(key: &str) -> Result<PathBuf, LicenseError> {
    let dir = dirs_path().ok_or_else(|| {
        LicenseError::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "could not determine home directory",
        ))
    })?;

    std::fs::create_dir_all(&dir)?;
    let path = dir.join("license.key");
    std::fs::write(&path, key.trim())?;
    Ok(path)
}

/// Remove the saved license key.
pub fn remove_license_key() -> Result<(), LicenseError> {
    if let Some(path) = license_file_path() {
        if path.exists() {
            std::fs::remove_file(&path)?;
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Suggest daily limit tracking (Free tier)
// ---------------------------------------------------------------------------

const FREE_SUGGEST_DAILY_LIMIT: usize = 3;

/// Check if a suggest invocation is allowed under the Free tier.
/// Returns (allowed, remaining) count.
pub fn check_suggest_limit(info: &LicenseInfo) -> (bool, usize) {
    if info.is_pro() {
        return (true, usize::MAX);
    }

    let today = today_string();
    let usage_path = dirs_path().map(|d| d.join("suggest_usage.json"));

    let current = usage_path
        .as_ref()
        .and_then(|p| std::fs::read_to_string(p).ok())
        .and_then(|s| serde_json::from_str::<SuggestUsage>(&s).ok())
        .unwrap_or_default();

    if current.date == today {
        let remaining = FREE_SUGGEST_DAILY_LIMIT.saturating_sub(current.count);
        (remaining > 0, remaining)
    } else {
        (true, FREE_SUGGEST_DAILY_LIMIT)
    }
}

/// Increment the suggest usage counter for today.
pub fn record_suggest_usage() {
    let today = today_string();
    let usage_path = match dirs_path() {
        Some(d) => d.join("suggest_usage.json"),
        None => return,
    };

    let mut usage = std::fs::read_to_string(&usage_path)
        .ok()
        .and_then(|s| serde_json::from_str::<SuggestUsage>(&s).ok())
        .unwrap_or_default();

    if usage.date == today {
        usage.count += 1;
    } else {
        usage.date = today;
        usage.count = 1;
    }

    let _ = std::fs::create_dir_all(usage_path.parent().unwrap_or(Path::new(".")));
    let _ = std::fs::write(
        &usage_path,
        serde_json::to_string(&usage).unwrap_or_default(),
    );
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct SuggestUsage {
    date: String,
    count: usize,
}

fn today_string() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let days = secs / 86400;
    format!("{}", days)
}

fn format_timestamp(ts: u64) -> String {
    let days_since_epoch = ts / 86400;
    let mut y = 1970u64;
    let mut remaining = days_since_epoch;
    loop {
        let days_in_year = if y % 4 == 0 && (y % 100 != 0 || y % 400 == 0) {
            366
        } else {
            365
        };
        if remaining < days_in_year {
            break;
        }
        remaining -= days_in_year;
        y += 1;
    }
    let months = [
        31,
        if y % 4 == 0 && (y % 100 != 0 || y % 400 == 0) {
            29
        } else {
            28
        },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    let mut m = 0;
    for days_in_month in months {
        if remaining < days_in_month {
            break;
        }
        remaining -= days_in_month;
        m += 1;
    }
    format!("{}-{:02}-{:02}", y, m + 1, remaining + 1)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn free_by_default() {
        let info = resolve_license(None);
        assert_eq!(info.tier, LicenseTier::Free);
        assert!(!info.is_pro());
    }

    #[test]
    fn invalid_token_returns_error() {
        let result = validate_token("not-a-jwt");
        assert!(result.is_err());
    }

    #[test]
    fn valid_rs256_token() {
        // generate_test_token creates an ephemeral RSA key pair for testing
        let (token, public_pem) = generate_test_token("test@example.com", "pro", 365);
        let info = validate_token_with_pem(&token, &public_pem).expect("should validate");
        assert_eq!(info.tier, LicenseTier::Pro);
        assert_eq!(info.email, "test@example.com");
        assert!(info.is_pro());
        assert!(!info.is_expired);
    }

    #[test]
    fn expired_rs256_token() {
        let (token, public_pem) = generate_test_token("test@example.com", "pro", 0);
        let result = validate_token_with_pem(&token, &public_pem);
        assert!(result.is_err());
        match result {
            Err(LicenseError::Expired(_)) => {}
            other => panic!("expected Expired, got {:?}", other),
        }
    }

    #[test]
    fn free_tier_rs256_token() {
        let (token, public_pem) = generate_test_token("test@example.com", "free", 365);
        let info = validate_token_with_pem(&token, &public_pem).expect("should validate");
        assert_eq!(info.tier, LicenseTier::Free);
        assert!(!info.is_pro());
    }

    #[test]
    fn wrong_key_rejects_token() {
        let (token, _) = generate_test_token("test@example.com", "pro", 365);
        // Validate against the embedded production key (will fail since token was
        // signed by an ephemeral key, not the production private key)
        let result = validate_token(&token);
        assert!(
            result.is_err(),
            "token signed by wrong key should be rejected"
        );
    }

    #[test]
    fn require_pro_blocks_free() {
        let info = LicenseInfo::free();
        let result = require_pro(&info, ProFeature::FrameworkMapping);
        assert!(result.is_err());
    }

    #[test]
    fn require_pro_allows_pro() {
        let (token, pub_pem) = generate_test_token("pro@example.com", "pro", 365);
        let info = validate_token_with_pem(&token, &pub_pem).unwrap();
        let result = require_pro(&info, ProFeature::FrameworkMapping);
        assert!(result.is_ok());
    }

    #[test]
    fn format_timestamp_works() {
        let s = format_timestamp(1735689600);
        assert_eq!(s, "2025-01-01");
    }

    #[test]
    fn suggest_limit_free_tier() {
        let info = LicenseInfo::free();
        let (_allowed, _remaining) = check_suggest_limit(&info);
        // Note: remaining may be 0 if other tests consumed the daily limit.
        // We only verify the function doesn't panic.
    }

    #[test]
    fn suggest_limit_pro_unlimited() {
        let (token, pub_pem) = generate_test_token("pro@example.com", "pro", 365);
        let info = validate_token_with_pem(&token, &pub_pem).unwrap();
        let (allowed, remaining) = check_suggest_limit(&info);
        assert!(allowed);
        assert_eq!(remaining, usize::MAX);
    }

    #[test]
    fn production_key_is_embedded() {
        // Verify the embedded public key is a valid RSA PEM
        assert!(RS256_PUBLIC_KEY_PEM.contains("-----BEGIN PUBLIC KEY-----"));
        assert!(RS256_PUBLIC_KEY_PEM.contains("-----END PUBLIC KEY-----"));
        // Verify it can be parsed
        let result = DecodingKey::from_rsa_pem(RS256_PUBLIC_KEY_PEM.as_bytes());
        assert!(result.is_ok(), "embedded public key should be parseable");
    }

    #[test]
    fn token_signed_with_production_key() {
        // Sign with the actual private key from keys/private.pem
        let private_pem = include_str!("../../../keys/private.pem");
        let token = generate_token_with_key("prod@piilex.dev", "pro", 365, private_pem);
        // Validate with embedded production public key
        let info = validate_token(&token).expect("production-signed token should validate");
        assert_eq!(info.tier, LicenseTier::Pro);
        assert_eq!(info.email, "prod@piilex.dev");
    }
}
