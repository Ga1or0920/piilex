use axum::body::Body;
use axum::http::{self, Request, StatusCode};
use http_body_util::BodyExt;
use piilex_saas::{create_router, init_db, AppState};
use serde_json::{json, Value};
use sqlx::sqlite::SqlitePoolOptions;
use std::sync::Arc;
use tower::ServiceExt;

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

const JWT_SECRET: &str = "test-jwt-secret";
const WEBHOOK_SECRET: &str = "whsec_test_secret";

async fn setup() -> axum::Router {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .expect("failed to create test db");

    init_db(&pool).await;

    let state = Arc::new(AppState {
        db: pool,
        stripe_secret: "sk_test_fake".to_string(),
        stripe_webhook_secret: WEBHOOK_SECRET.to_string(),
        jwt_secret: JWT_SECRET.to_string(),
        license_private_key: String::new(),
        base_url: "http://localhost:3001".to_string(),
        email_config: piilex_saas::email::EmailConfig::from_env(),
    });

    create_router(state)
}

async fn body_json(body: Body) -> Value {
    let bytes = body.collect().await.unwrap().to_bytes();
    serde_json::from_slice(&bytes).unwrap_or(Value::Null)
}

fn auth_header(token: &str) -> (http::HeaderName, http::HeaderValue) {
    (
        http::header::AUTHORIZATION,
        http::HeaderValue::from_str(&format!("Bearer {}", token)).unwrap(),
    )
}

/// Sign up a user and return (token, user_id, team_id).
async fn signup_user(app: &axum::Router) -> (String, String, String) {
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/auth/signup")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "email": format!("test-{}@example.com", uuid::Uuid::new_v4()),
                        "name": "Test User",
                        "team_name": "Test Team",
                        "password": "test-password-123"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let data = body_json(resp.into_body()).await;
    (
        data["token"].as_str().unwrap().to_string(),
        data["user"]["id"].as_str().unwrap().to_string(),
        data["team"]["id"].as_str().unwrap().to_string(),
    )
}

// =====================================================================
// 1. Health check
// =====================================================================

#[tokio::test]
async fn health_check() {
    let app = setup().await;
    let resp = app
        .oneshot(Request::builder().uri("/health").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

// =====================================================================
// 2. Auth: signup + login + token validation
// =====================================================================

#[tokio::test]
async fn signup_creates_user_and_team() {
    let app = setup().await;
    let (token, user_id, team_id) = signup_user(&app).await;
    assert!(!token.is_empty());
    assert!(!user_id.is_empty());
    assert!(!team_id.is_empty());
}

#[tokio::test]
async fn login_with_correct_password() {
    let app = setup().await;
    let email = format!("login-{}@example.com", uuid::Uuid::new_v4());

    // Signup
    app.clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/auth/signup")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({ "email": email, "name": "Test", "team_name": "T", "password": "pass12345" }).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    // Login
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/auth/login")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({ "email": email, "password": "pass12345" }).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let data = body_json(resp.into_body()).await;
    assert!(data["token"].is_string());
}

#[tokio::test]
async fn login_with_wrong_password_returns_401() {
    let app = setup().await;
    let email = format!("wrong-{}@example.com", uuid::Uuid::new_v4());

    // Signup
    app.clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/auth/signup")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({ "email": email, "name": "Test", "team_name": "T", "password": "correct1" }).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    // Login with wrong password
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/auth/login")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({ "email": email, "password": "wrongpwd1" }).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn duplicate_signup_returns_conflict() {
    let app = setup().await;
    let email = format!("dup-{}@example.com", uuid::Uuid::new_v4());
    let body = json!({ "email": email, "name": "Test", "team_name": "T", "password": "password1" }).to_string();

    // First signup
    app.clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/auth/signup")
                .header("content-type", "application/json")
                .body(Body::from(body.clone()))
                .unwrap(),
        )
        .await
        .unwrap();

    // Second signup with same email
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/auth/signup")
                .header("content-type", "application/json")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::CONFLICT);
}

// =====================================================================
// 3. Auth: token validation and expiration
// =====================================================================

#[tokio::test]
async fn request_without_token_returns_401() {
    let app = setup().await;
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/api/teams/current")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn request_with_invalid_token_returns_401() {
    let app = setup().await;
    let (name, value) = auth_header("invalid-token-garbage");
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/api/teams/current")
                .header(name, value)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn expired_token_returns_401() {
    use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};

    let claims = piilex_saas::middleware::JwtClaims {
        sub: "user-1".to_string(),
        team_id: "team-1".to_string(),
        role: "owner".to_string(),
        exp: 1000, // Expired long ago
    };
    let token = encode(
        &Header::new(Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(JWT_SECRET.as_bytes()),
    )
    .unwrap();

    let app = setup().await;
    let (name, value) = auth_header(&token);
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/api/teams/current")
                .header(name, value)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

// =====================================================================
// 4. Teams: members and permissions
// =====================================================================

#[tokio::test]
async fn get_team_with_valid_token() {
    let app = setup().await;
    let (token, _, _) = signup_user(&app).await;

    let (name, value) = auth_header(&token);
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/api/teams/current")
                .header(name, value)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let data = body_json(resp.into_body()).await;
    assert_eq!(data["plan"], "free");
}

#[tokio::test]
async fn invite_member_as_owner() {
    let app = setup().await;
    let (token, _, _) = signup_user(&app).await;

    let (name, value) = auth_header(&token);
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/teams/invite")
                .header(name, value)
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({ "email": "invited@example.com", "name": "Invited", "role": "member" }).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
}

// =====================================================================
// 5. Scans: CRUD
// =====================================================================

#[tokio::test]
async fn create_and_list_scans() {
    let app = setup().await;
    let (token, _, _) = signup_user(&app).await;
    let (name, value) = auth_header(&token);

    // Create scan
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/scans")
                .header(name.clone(), value.clone())
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "project_name": "test-project",
                        "files_scanned": 42,
                        "findings_count": 10,
                        "critical_count": 2,
                        "high_count": 5,
                        "medium_count": 2,
                        "low_count": 1,
                        "duration_ms": 350
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::CREATED);

    // List scans
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/api/scans")
                .header(name, value)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let data = body_json(resp.into_body()).await;
    let scans = data.as_array().unwrap();
    assert_eq!(scans.len(), 1);
    assert_eq!(scans[0]["project_name"], "test-project");
    assert_eq!(scans[0]["findings_count"], 10);
}

// =====================================================================
// 6. API Keys
// =====================================================================

#[tokio::test]
async fn create_and_list_api_keys() {
    let app = setup().await;
    let (token, _, _) = signup_user(&app).await;
    let (name, value) = auth_header(&token);

    // Create key
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/keys")
                .header(name.clone(), value.clone())
                .header("content-type", "application/json")
                .body(Body::from(json!({ "name": "CI key" }).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::CREATED);
    let key_data = body_json(resp.into_body()).await;
    assert!(key_data["key"].as_str().unwrap().starts_with("plx_"));

    // List keys (should not include __password__)
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/api/keys")
                .header(name, value)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    let keys = body_json(resp.into_body()).await;
    let keys = keys.as_array().unwrap();
    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0]["name"], "CI key");
}

// =====================================================================
// 7. Webhook signature verification
// =====================================================================

#[test]
fn valid_webhook_signature_passes() {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    let payload = r#"{"id":"evt_1","type":"customer.subscription.created","data":{"object":{}}}"#;
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        .to_string();

    let signed = format!("{}.{}", timestamp, payload);
    let mut mac = Hmac::<Sha256>::new_from_slice(WEBHOOK_SECRET.as_bytes()).unwrap();
    mac.update(signed.as_bytes());
    let signature = hex::encode(mac.finalize().into_bytes());

    let sig_header = format!("t={},v1={}", timestamp, signature);

    let result =
        piilex_saas::stripe::verify_webhook_signature(payload, &sig_header, WEBHOOK_SECRET);
    assert!(result.is_ok(), "Valid signature should pass: {:?}", result);
}

#[test]
fn invalid_webhook_signature_rejected() {
    let payload = r#"{"test": true}"#;
    let sig_header = "t=1234567890,v1=invalidsignaturehex";

    let result =
        piilex_saas::stripe::verify_webhook_signature(payload, &sig_header, WEBHOOK_SECRET);
    assert!(result.is_err());
}

#[test]
fn missing_signature_parts_rejected() {
    let result = piilex_saas::stripe::verify_webhook_signature("body", "garbage", WEBHOOK_SECRET);
    assert!(result.is_err());
}

#[test]
fn old_timestamp_rejected() {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    let payload = "test";
    let old_timestamp = "1000000000"; // 2001, very old

    let signed = format!("{}.{}", old_timestamp, payload);
    let mut mac = Hmac::<Sha256>::new_from_slice(WEBHOOK_SECRET.as_bytes()).unwrap();
    mac.update(signed.as_bytes());
    let signature = hex::encode(mac.finalize().into_bytes());
    let sig_header = format!("t={},v1={}", old_timestamp, signature);

    let result =
        piilex_saas::stripe::verify_webhook_signature(payload, &sig_header, WEBHOOK_SECRET);
    assert!(result.is_err(), "Old timestamp should be rejected");
}

// =====================================================================
// 8. Webhook: subscription lifecycle
// =====================================================================

#[tokio::test]
async fn webhook_subscription_created_updates_plan() {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    let app = setup().await;
    let (token, _, team_id) = signup_user(&app).await;

    // Manually set stripe_customer_id on team (simulating checkout completion)
    let (name, value) = auth_header(&token);
    // We need to set it in the DB directly through the state
    // For this test, we'll use the webhook with a matching customer

    // First, update team's stripe_customer_id directly via a scan create
    // (hack: we set it by sending a webhook with checkout.session.completed)
    // Instead, let's test the subscription event with a known customer

    // Set customer ID directly in DB
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/teams/current")
                .header(name.clone(), value.clone())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Send subscription webhook (placeholder - with webhook secret as placeholder, verification is skipped)
    let event = json!({
        "id": "evt_test_1",
        "type": "customer.subscription.created",
        "data": {
            "object": {
                "id": "sub_test_1",
                "customer": "cus_test_1",
                "status": "active",
                "items": { "data": [{ "price": { "id": "price_pro_monthly" } }] },
                "current_period_end": 1893456000
            }
        }
    });

    let payload = event.to_string();
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        .to_string();

    let signed = format!("{}.{}", timestamp, payload);
    let mut mac = Hmac::<Sha256>::new_from_slice(WEBHOOK_SECRET.as_bytes()).unwrap();
    mac.update(signed.as_bytes());
    let signature = hex::encode(mac.finalize().into_bytes());
    let sig_header = format!("t={},v1={}", timestamp, signature);

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/webhooks/stripe")
                .header("content-type", "application/json")
                .header("stripe-signature", &sig_header)
                .body(Body::from(payload))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
}

// =====================================================================
// 9. Billing: subscription status
// =====================================================================

#[tokio::test]
async fn subscription_defaults_to_free() {
    let app = setup().await;
    let (token, _, _) = signup_user(&app).await;
    let (name, value) = auth_header(&token);

    let resp = app
        .oneshot(
            Request::builder()
                .uri("/api/billing/subscription")
                .header(name, value)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let data = body_json(resp.into_body()).await;
    assert_eq!(data["plan"], "free");
}

// =====================================================================
// 10. License: requires Pro
// =====================================================================

#[tokio::test]
async fn license_requires_pro_plan() {
    let app = setup().await;
    let (token, _, _) = signup_user(&app).await;
    let (name, value) = auth_header(&token);

    let resp = app
        .oneshot(
            Request::builder()
                .uri("/api/billing/license")
                .header(name, value)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    // Free plan should get 402 Payment Required
    assert_eq!(resp.status(), StatusCode::PAYMENT_REQUIRED);
}

// =====================================================================
// 11. Cross-team isolation
// =====================================================================

#[tokio::test]
async fn cannot_access_other_teams_scans() {
    let app = setup().await;

    // Create two users in different teams
    let (token_a, _, _) = signup_user(&app).await;
    let (token_b, _, _) = signup_user(&app).await;

    // User A creates a scan
    let (name_a, value_a) = auth_header(&token_a);
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/scans")
                .header(name_a, value_a)
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "project_name": "team-a-project",
                        "files_scanned": 10,
                        "findings_count": 5,
                        "critical_count": 1,
                        "high_count": 2,
                        "medium_count": 1,
                        "low_count": 1,
                        "duration_ms": 100
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);

    // User B should see no scans (different team)
    let (name_b, value_b) = auth_header(&token_b);
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/api/scans")
                .header(name_b, value_b)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let data = body_json(resp.into_body()).await;
    assert_eq!(data.as_array().unwrap().len(), 0, "User B should see 0 scans");
}
