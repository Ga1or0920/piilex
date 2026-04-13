use crate::{db, middleware, models::*, AppState};
use axum::{extract::State, http::StatusCode, Json};
use std::sync::Arc;

pub async fn signup(
    State(state): State<Arc<AppState>>,
    Json(req): Json<SignupRequest>,
) -> Result<Json<AuthResponse>, StatusCode> {
    // Input validation
    let email = req.email.trim().to_lowercase();
    if email.is_empty() || !email.contains('@') || email.len() > 254 {
        return Err(StatusCode::BAD_REQUEST);
    }
    if req.name.trim().is_empty() || req.name.len() > 200 {
        return Err(StatusCode::BAD_REQUEST);
    }
    if req.team_name.trim().is_empty() || req.team_name.len() > 200 {
        return Err(StatusCode::BAD_REQUEST);
    }
    if req.password.len() < 8 || req.password.len() > 1000 {
        return Err(StatusCode::BAD_REQUEST);
    }

    let team_id = db::generate_id();
    let user_id = db::generate_id();
    let password_hash = db::hash_key(&req.password);

    // Create team
    sqlx::query("INSERT INTO teams (id, name) VALUES (?, ?)")
        .bind(&team_id)
        .bind(&req.team_name)
        .execute(&state.db)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // Create user (store password hash in a separate field; for MVP we reuse key_hash pattern)
    sqlx::query("INSERT INTO users (id, email, name, team_id, role) VALUES (?, ?, ?, ?, 'owner')")
        .bind(&user_id)
        .bind(&email)
        .bind(req.name.trim())
        .bind(&team_id)
        .execute(&state.db)
        .await
        .map_err(|_| StatusCode::CONFLICT)?; // Email likely already exists

    // Store password hash as an API key with special name
    sqlx::query("INSERT INTO api_keys (id, user_id, team_id, key_hash, name) VALUES (?, ?, ?, ?, '__password__')")
        .bind(&db::generate_id())
        .bind(&user_id)
        .bind(&team_id)
        .bind(&password_hash)
        .execute(&state.db)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let token = middleware::create_jwt(&user_id, &team_id, "owner", &state.jwt_secret);

    let user = sqlx::query_as::<_, User>("SELECT * FROM users WHERE id = ?")
        .bind(&user_id)
        .fetch_one(&state.db)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let team = sqlx::query_as::<_, Team>("SELECT * FROM teams WHERE id = ?")
        .bind(&team_id)
        .fetch_one(&state.db)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(AuthResponse { token, user, team }))
}

pub async fn login(
    State(state): State<Arc<AppState>>,
    Json(req): Json<LoginRequest>,
) -> Result<Json<AuthResponse>, StatusCode> {
    let password_hash = db::hash_key(&req.password);

    // Find user by email
    let user = sqlx::query_as::<_, User>("SELECT * FROM users WHERE email = ?")
        .bind(&req.email)
        .fetch_optional(&state.db)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::UNAUTHORIZED)?;

    // Verify password
    let row = sqlx::query(
        "SELECT COUNT(*) as cnt FROM api_keys WHERE user_id = ? AND name = '__password__' AND key_hash = ?",
    )
    .bind(&user.id)
    .bind(&password_hash)
    .fetch_one(&state.db)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let key_exists: i32 = sqlx::Row::try_get(&row, "cnt").unwrap_or(0);

    if key_exists == 0 {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let team = sqlx::query_as::<_, Team>("SELECT * FROM teams WHERE id = ?")
        .bind(&user.team_id)
        .fetch_one(&state.db)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let token = middleware::create_jwt(&user.id, &user.team_id, &user.role, &state.jwt_secret);

    Ok(Json(AuthResponse { token, user, team }))
}
