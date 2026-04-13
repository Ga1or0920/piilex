pub mod db;
pub mod email;
pub mod handlers;
pub mod middleware;
pub mod models;
pub mod stripe;

use axum::{
    routing::{get, post},
    Router,
};
use std::sync::Arc;
use tower_http::cors::CorsLayer;

pub type DbPool = sqlx::SqlitePool;

pub struct AppState {
    pub db: DbPool,
    pub stripe_secret: String,
    pub stripe_webhook_secret: String,
    pub jwt_secret: String,
    pub license_private_key: String,
    pub base_url: String,
    pub email_config: email::EmailConfig,
}

/// Build the application router.
pub fn create_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/health", get(|| async { "ok" }))
        .route("/api/auth/signup", post(handlers::auth::signup))
        .route("/api/auth/login", post(handlers::auth::login))
        .route("/api/teams/current", get(handlers::teams::get_current_team))
        .route("/api/teams/members", get(handlers::teams::list_members))
        .route("/api/teams/invite", post(handlers::teams::invite_member))
        .route("/api/scans", get(handlers::scans::list_scans))
        .route("/api/scans", post(handlers::scans::create_scan))
        .route("/api/scans/{id}", get(handlers::scans::get_scan))
        .route("/api/scans/{id}/findings", get(handlers::scans::get_findings))
        .route("/api/scans/trends", get(handlers::scans::get_trends))
        .route("/api/scans/pii-distribution", get(handlers::scans::get_pii_distribution))
        .route("/api/keys", get(handlers::keys::list_keys))
        .route("/api/keys", post(handlers::keys::create_key))
        .route("/api/keys/{id}", axum::routing::delete(handlers::keys::delete_key))
        .route("/api/billing/checkout", post(handlers::billing::create_checkout))
        .route("/api/billing/portal", post(handlers::billing::create_portal))
        .route("/api/billing/subscription", get(handlers::billing::get_subscription))
        .route("/webhooks/stripe", post(handlers::billing::stripe_webhook))
        .route("/api/billing/license", get(handlers::billing::get_license_token))
        .layer(CorsLayer::permissive())
        .with_state(state)
}

/// Initialize database with migrations.
pub async fn init_db(pool: &DbPool) {
    for statement in include_str!("../../migrations/001_init.sql").split(';') {
        let trimmed = statement.trim();
        if !trimmed.is_empty() {
            let _ = sqlx::query(trimmed).execute(pool).await;
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let database_url =
        std::env::var("DATABASE_URL").unwrap_or_else(|_| "sqlite:piilex.db?mode=rwc".to_string());
    let stripe_secret =
        std::env::var("STRIPE_SECRET_KEY").unwrap_or_else(|_| "sk_test_placeholder".to_string());
    let stripe_webhook_secret = std::env::var("STRIPE_WEBHOOK_SECRET")
        .unwrap_or_else(|_| "whsec_placeholder".to_string());
    let jwt_secret =
        std::env::var("JWT_SECRET").unwrap_or_else(|_| "dev-jwt-secret-change-me".to_string());
    let license_private_key = std::env::var("LICENSE_PRIVATE_KEY")
        .or_else(|_| std::fs::read_to_string("../../keys/private.pem"))
        .unwrap_or_default();
    let base_url =
        std::env::var("BASE_URL").unwrap_or_else(|_| "http://localhost:3001".to_string());
    let port = std::env::var("PORT").unwrap_or_else(|_| "3001".to_string());

    let max_connections: u32 = std::env::var("DB_MAX_CONNECTIONS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(5);

    let pool = sqlx::sqlite::SqlitePoolOptions::new()
        .max_connections(max_connections)
        .connect(&database_url)
        .await?;

    init_db(&pool).await;

    let state = Arc::new(AppState {
        db: pool,
        stripe_secret,
        stripe_webhook_secret,
        jwt_secret,
        license_private_key,
        base_url,
        email_config: email::EmailConfig::from_env(),
    });

    let app = create_router(state);

    let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{}", port)).await?;
    eprintln!("piilex SaaS API listening on port {}", port);
    axum::serve(listener, app).await?;

    Ok(())
}
