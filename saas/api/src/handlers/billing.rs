use crate::{db, middleware, stripe, AppState};
use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    Json,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

// ---------------------------------------------------------------------------
// Request / Response types
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct CheckoutRequest {
    pub price_id: String,
}

#[derive(Serialize)]
pub struct CheckoutResponse {
    pub checkout_url: String,
}

#[derive(Serialize)]
pub struct PortalResponse {
    pub portal_url: String,
}

#[derive(Serialize)]
pub struct SubscriptionResponse {
    pub plan: String,
    pub status: Option<String>,
    pub current_period_end: Option<String>,
}

#[derive(Serialize)]
pub struct LicenseResponse {
    pub token: String,
    pub expires_in_days: u64,
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// POST /api/billing/checkout
/// Creates a Stripe Checkout Session and returns the URL to redirect the user.
pub async fn create_checkout(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<CheckoutRequest>,
) -> Result<Json<CheckoutResponse>, StatusCode> {
    let claims = middleware::auth(&headers, &state.jwt_secret)?;

    // Get or create Stripe customer
    let customer_id = ensure_stripe_customer(&state, &claims).await?;

    let success_url = format!("{}/success.html?session_id={{CHECKOUT_SESSION_ID}}", state.base_url);
    let cancel_url = format!("{}/canceled.html", state.base_url);

    let client = stripe::StripeClient::new(&state.stripe_secret);
    let checkout_url = client
        .create_checkout_session(&customer_id, &body.price_id, &success_url, &cancel_url)
        .await
        .map_err(|e| {
            eprintln!("Stripe checkout error: {}", e);
            StatusCode::BAD_GATEWAY
        })?;

    Ok(Json(CheckoutResponse { checkout_url }))
}

/// POST /api/billing/portal
/// Creates a Stripe Billing Portal session for managing the subscription.
pub async fn create_portal(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<PortalResponse>, StatusCode> {
    let claims = middleware::auth(&headers, &state.jwt_secret)?;

    let customer_id = get_stripe_customer(&state, &claims.team_id)
        .await?
        .ok_or(StatusCode::NOT_FOUND)?;

    let return_url = format!("{}/index.html", state.base_url);

    let client = stripe::StripeClient::new(&state.stripe_secret);
    let portal_url = client
        .create_portal_session(&customer_id, &return_url)
        .await
        .map_err(|e| {
            eprintln!("Stripe portal error: {}", e);
            StatusCode::BAD_GATEWAY
        })?;

    Ok(Json(PortalResponse { portal_url }))
}

/// GET /api/billing/subscription
pub async fn get_subscription(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<SubscriptionResponse>, StatusCode> {
    let claims = middleware::auth(&headers, &state.jwt_secret)?;

    let sub = sqlx::query_as::<_, crate::models::Subscription>(
        "SELECT * FROM subscriptions WHERE team_id = ? ORDER BY created_at DESC LIMIT 1",
    )
    .bind(&claims.team_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    match sub {
        Some(s) => Ok(Json(SubscriptionResponse {
            plan: stripe::status_to_plan(&s.status).to_string(),
            status: Some(s.status),
            current_period_end: s.current_period_end,
        })),
        None => Ok(Json(SubscriptionResponse {
            plan: "free".to_string(),
            status: None,
            current_period_end: None,
        })),
    }
}

/// GET /api/billing/license
/// Returns a piilex Pro license JWT for CLI activation.
/// Only available to teams with an active Pro subscription.
pub async fn get_license_token(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<LicenseResponse>, StatusCode> {
    let claims = middleware::auth(&headers, &state.jwt_secret)?;

    // Verify team has Pro plan
    let plan = sqlx::query_scalar::<_, String>("SELECT plan FROM teams WHERE id = ?")
        .bind(&claims.team_id)
        .fetch_one(&state.db)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    if plan != "pro" {
        return Err(StatusCode::PAYMENT_REQUIRED);
    }

    // Get user email
    let email = sqlx::query_scalar::<_, String>("SELECT email FROM users WHERE id = ?")
        .bind(&claims.sub)
        .fetch_one(&state.db)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    if state.license_private_key.is_empty() {
        eprintln!("LICENSE_PRIVATE_KEY not configured");
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    }

    let valid_days = 365;
    let token = stripe::generate_license_jwt(
        &email,
        &claims.team_id,
        &state.license_private_key,
        valid_days,
    )
    .map_err(|e| {
        eprintln!("License JWT error: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    Ok(Json(LicenseResponse {
        token,
        expires_in_days: valid_days,
    }))
}

/// POST /webhooks/stripe
/// Receives and processes Stripe webhook events.
pub async fn stripe_webhook(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: String,
) -> Result<StatusCode, StatusCode> {
    // Verify webhook signature
    let sig = headers
        .get("stripe-signature")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    if !state.stripe_webhook_secret.contains("placeholder") {
        stripe::verify_webhook_signature(&body, sig, &state.stripe_webhook_secret).map_err(
            |e| {
                eprintln!("Webhook signature verification failed: {}", e);
                StatusCode::UNAUTHORIZED
            },
        )?;
    }

    let event: stripe::StripeEvent =
        serde_json::from_str(&body).map_err(|_| StatusCode::BAD_REQUEST)?;

    eprintln!("Stripe webhook: {}", event.event_type);

    match event.event_type.as_str() {
        // Subscription lifecycle
        "customer.subscription.created"
        | "customer.subscription.updated"
        | "customer.subscription.deleted" => {
            handle_subscription_event(&state, &event.data.object).await?;
        }

        // Checkout completed -> link customer to team
        "checkout.session.completed" => {
            handle_checkout_completed(&state, &event.data.object).await?;
        }

        // Payment failed
        "invoice.payment_failed" => {
            let customer = event.data.object["customer"].as_str().unwrap_or("");
            eprintln!(
                "Payment failed for customer {}: notify team",
                customer
            );
            // In production: send email notification to team owner
        }

        _ => {
            eprintln!("Unhandled webhook event: {}", event.event_type);
        }
    }

    Ok(StatusCode::OK)
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

async fn handle_subscription_event(
    state: &AppState,
    sub_obj: &serde_json::Value,
) -> Result<(), StatusCode> {
    let stripe_sub_id = sub_obj["id"].as_str().unwrap_or("");
    let stripe_customer = sub_obj["customer"].as_str().unwrap_or("");
    let status = sub_obj["status"].as_str().unwrap_or("canceled");
    let price_id = sub_obj["items"]["data"][0]["price"]["id"]
        .as_str()
        .unwrap_or("");
    let period_end = sub_obj["current_period_end"].as_i64();

    let team_id = sqlx::query_scalar::<_, String>(
        "SELECT id FROM teams WHERE stripe_customer_id = ?",
    )
    .bind(stripe_customer)
    .fetch_optional(&state.db)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let team_id = match team_id {
        Some(id) => id,
        None => {
            eprintln!(
                "No team found for Stripe customer {}",
                stripe_customer
            );
            return Ok(());
        }
    };

    let sub_id = db::generate_id();
    let period_end_str = period_end
        .map(|ts| {
            chrono::DateTime::from_timestamp(ts, 0)
                .map(|dt| dt.format("%Y-%m-%d").to_string())
                .unwrap_or_default()
        });

    // Upsert subscription
    sqlx::query(
        "INSERT OR REPLACE INTO subscriptions \
         (id, team_id, stripe_subscription_id, stripe_price_id, status, \
          current_period_end, updated_at) \
         VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)",
    )
    .bind(&sub_id)
    .bind(&team_id)
    .bind(stripe_sub_id)
    .bind(price_id)
    .bind(status)
    .bind(&period_end_str)
    .execute(&state.db)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // Update team plan
    let plan = stripe::status_to_plan(status);
    sqlx::query("UPDATE teams SET plan = ? WHERE id = ?")
        .bind(plan)
        .bind(&team_id)
        .execute(&state.db)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    eprintln!(
        "Subscription {} for team {}: status={}, plan={}",
        stripe_sub_id, team_id, status, plan
    );

    Ok(())
}

async fn handle_checkout_completed(
    state: &AppState,
    session: &serde_json::Value,
) -> Result<(), StatusCode> {
    let customer_id = session["customer"].as_str().unwrap_or("");
    let _subscription_id = session["subscription"].as_str().unwrap_or("");

    // The customer was already linked to the team during create_checkout
    eprintln!(
        "Checkout completed for customer {}",
        customer_id
    );

    Ok(())
}

async fn ensure_stripe_customer(
    state: &AppState,
    claims: &middleware::JwtClaims,
) -> Result<String, StatusCode> {
    // Check if team already has a Stripe customer
    if let Some(existing) = get_stripe_customer(state, &claims.team_id).await? {
        return Ok(existing);
    }

    // Get user email for creating customer
    let email = sqlx::query_scalar::<_, String>("SELECT email FROM users WHERE id = ?")
        .bind(&claims.sub)
        .fetch_one(&state.db)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let team_name = sqlx::query_scalar::<_, String>("SELECT name FROM teams WHERE id = ?")
        .bind(&claims.team_id)
        .fetch_one(&state.db)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let client = stripe::StripeClient::new(&state.stripe_secret);
    let customer_id = client
        .create_customer(&email, &team_name, &claims.team_id)
        .await
        .map_err(|e| {
            eprintln!("Stripe create customer error: {}", e);
            StatusCode::BAD_GATEWAY
        })?;

    // Save to team
    sqlx::query("UPDATE teams SET stripe_customer_id = ? WHERE id = ?")
        .bind(&customer_id)
        .bind(&claims.team_id)
        .execute(&state.db)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(customer_id)
}

async fn get_stripe_customer(
    state: &AppState,
    team_id: &str,
) -> Result<Option<String>, StatusCode> {
    let row: (Option<String>,) = sqlx::query_as(
        "SELECT stripe_customer_id FROM teams WHERE id = ?",
    )
    .bind(team_id)
    .fetch_one(&state.db)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(row.0)
}
