use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone, sqlx::FromRow)]
pub struct Team {
    pub id: String,
    pub name: String,
    pub stripe_customer_id: Option<String>,
    pub plan: String,
    pub created_at: String,
}

#[derive(Debug, Serialize, Deserialize, Clone, sqlx::FromRow)]
pub struct User {
    pub id: String,
    pub email: String,
    pub name: String,
    pub team_id: String,
    pub role: String,
    pub created_at: String,
}

#[derive(Debug, Serialize, Deserialize, Clone, sqlx::FromRow)]
pub struct Scan {
    pub id: String,
    pub team_id: String,
    pub user_id: Option<String>,
    pub project_name: String,
    pub files_scanned: i32,
    pub findings_count: i32,
    pub critical_count: i32,
    pub high_count: i32,
    pub medium_count: i32,
    pub low_count: i32,
    pub frameworks: Option<String>,
    pub duration_ms: i32,
    pub pii_type_summary: Option<String>,
    pub language_summary: Option<String>,
    pub created_at: String,
}

#[derive(Debug, Serialize, Deserialize, Clone, sqlx::FromRow)]
pub struct ScanFinding {
    pub id: String,
    pub scan_id: String,
    pub pii_type: String,
    pub severity: String,
    pub file_path: String,
    pub line: i32,
    pub code_snippet: Option<String>,
    pub data_flow: Option<String>,
    pub framework_mappings: Option<String>,
    pub created_at: String,
}

#[derive(Debug, Serialize, Deserialize, Clone, sqlx::FromRow)]
pub struct ApiKey {
    pub id: String,
    pub user_id: String,
    pub team_id: String,
    pub key_hash: String,
    pub name: String,
    pub last_used: Option<String>,
    pub created_at: String,
}

#[derive(Debug, Serialize, Deserialize, Clone, sqlx::FromRow)]
pub struct Subscription {
    pub id: String,
    pub team_id: String,
    pub stripe_subscription_id: String,
    pub stripe_price_id: String,
    pub status: String,
    pub current_period_start: Option<String>,
    pub current_period_end: Option<String>,
}

// Request/Response DTOs

#[derive(Debug, Deserialize)]
pub struct SignupRequest {
    pub email: String,
    pub name: String,
    pub team_name: String,
    pub password: String,
}

#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}

#[derive(Debug, Serialize)]
pub struct AuthResponse {
    pub token: String,
    pub user: User,
    pub team: Team,
}

#[derive(Debug, Deserialize)]
pub struct CreateScanRequest {
    pub project_name: String,
    pub files_scanned: i32,
    pub findings_count: i32,
    pub critical_count: i32,
    pub high_count: i32,
    pub medium_count: i32,
    pub low_count: i32,
    pub frameworks: Option<Vec<String>>,
    pub duration_ms: i32,
    pub pii_type_summary: Option<serde_json::Value>,
    pub language_summary: Option<serde_json::Value>,
    pub findings: Option<Vec<CreateFindingRequest>>,
}

#[derive(Debug, Deserialize)]
pub struct CreateFindingRequest {
    pub pii_type: String,
    pub severity: String,
    pub file_path: String,
    pub line: i32,
    pub code_snippet: Option<String>,
    pub data_flow: Option<serde_json::Value>,
    pub framework_mappings: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
pub struct InviteMemberRequest {
    pub email: String,
    pub name: String,
    pub role: String,
}

#[derive(Debug, Deserialize)]
pub struct CreateKeyRequest {
    pub name: String,
}

#[derive(Debug, Serialize)]
pub struct CreateKeyResponse {
    pub id: String,
    pub key: String,
    pub name: String,
}
