mod db;
mod handlers;
mod middleware;
mod models;
mod stripe;

use axum::{
    routing::{get, post},
    Router,
};
use sqlx::sqlite::SqlitePoolOptions;
use std::sync::Arc;
use tower_http::cors::CorsLayer;

pub struct AppState {
    pub db: sqlx::SqlitePool,
    pub stripe_secret: String,
    pub stripe_webhook_secret: String,
    pub jwt_secret: String,
    pub license_private_key: String,
    pub base_url: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let database_url =
        std::env::var("DATABASE_URL").unwrap_or_else(|_| "sqlite:piilex.db?mode=rwc".to_string());
    let stripe_secret =
        std::env::var("STRIPE_SECRET_KEY").unwrap_or_else(|_| "sk_test_placeholder".to_string());
    let stripe_webhook_secret =
        std::env::var("STRIPE_WEBHOOK_SECRET").unwrap_or_else(|_| "whsec_placeholder".to_string());
    let jwt_secret =
        std::env::var("JWT_SECRET").unwrap_or_else(|_| "dev-jwt-secret-change-me".to_string());
    let license_private_key = std::env::var("LICENSE_PRIVATE_KEY")
        .or_else(|_| std::fs::read_to_string("../../keys/private.pem"))
        .unwrap_or_default();
    let base_url =
        std::env::var("BASE_URL").unwrap_or_else(|_| format!("http://localhost:{}", "3001"));
    let port = std::env::var("PORT").unwrap_or_else(|_| "3001".to_string());

    let pool = SqlitePoolOptions::new()
        .max_connections(5)
        .connect(&database_url)
        .await?;

    // Run migrations
    sqlx::query(include_str!("../../migrations/001_init.sql"))
        .execute(&pool)
        .await
        .ok(); // Ignore if tables already exist

    let state = Arc::new(AppState {
        db: pool,
        stripe_secret,
        stripe_webhook_secret,
        jwt_secret,
        license_private_key,
        base_url,
    });

    let app = Router::new()
        // Health
        .route("/health", get(|| async { "ok" }))
        // Auth
        .route("/api/auth/signup", post(handlers::auth::signup))
        .route("/api/auth/login", post(handlers::auth::login))
        // Teams
        .route("/api/teams/current", get(handlers::teams::get_current_team))
        .route("/api/teams/members", get(handlers::teams::list_members))
        .route("/api/teams/invite", post(handlers::teams::invite_member))
        // Scans
        .route("/api/scans", get(handlers::scans::list_scans))
        .route("/api/scans", post(handlers::scans::create_scan))
        .route("/api/scans/:id", get(handlers::scans::get_scan))
        .route(
            "/api/scans/:id/findings",
            get(handlers::scans::get_findings),
        )
        // API Keys
        .route("/api/keys", get(handlers::keys::list_keys))
        .route("/api/keys", post(handlers::keys::create_key))
        .route("/api/keys/:id", axum::routing::delete(handlers::keys::delete_key))
        // Stripe
        .route(
            "/api/billing/checkout",
            post(handlers::billing::create_checkout),
        )
        .route(
            "/api/billing/portal",
            post(handlers::billing::create_portal),
        )
        .route(
            "/api/billing/subscription",
            get(handlers::billing::get_subscription),
        )
        .route("/webhooks/stripe", post(handlers::billing::stripe_webhook))
        // License
        .route(
            "/api/billing/license",
            get(handlers::billing::get_license_token),
        )
        // CORS
        .layer(CorsLayer::permissive())
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{}", port)).await?;
    eprintln!("piilex SaaS API listening on port {}", port);
    axum::serve(listener, app).await?;

    Ok(())
}
