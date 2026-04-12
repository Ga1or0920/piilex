use crate::{db, middleware, models::*, AppState};
use axum::{
    extract::{State},
    http::{HeaderMap, StatusCode},
    Json,
};
use std::sync::Arc;

pub async fn get_current_team(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<Team>, StatusCode> {
    let claims = middleware::auth(&headers, &state.jwt_secret)?;

    let team = sqlx::query_as::<_, Team>("SELECT * FROM teams WHERE id = ?")
        .bind(&claims.team_id)
        .fetch_one(&state.db)
        .await
        .map_err(|_| StatusCode::NOT_FOUND)?;

    Ok(Json(team))
}

pub async fn list_members(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<Vec<User>>, StatusCode> {
    let claims = middleware::auth(&headers, &state.jwt_secret)?;

    let members = sqlx::query_as::<_, User>("SELECT * FROM users WHERE team_id = ? ORDER BY created_at")
        .bind(&claims.team_id)
        .fetch_all(&state.db)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(members))
}

pub async fn invite_member(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<InviteMemberRequest>,
) -> Result<Json<User>, StatusCode> {
    let claims = middleware::auth(&headers, &state.jwt_secret)?;

    // Only owner/admin can invite
    if claims.role != "owner" && claims.role != "admin" {
        return Err(StatusCode::FORBIDDEN);
    }

    let user_id = db::generate_id();
    sqlx::query("INSERT INTO users (id, email, name, team_id, role) VALUES (?, ?, ?, ?, ?)")
        .bind(&user_id)
        .bind(&body.email)
        .bind(&body.name)
        .bind(&claims.team_id)
        .bind(&body.role)
        .execute(&state.db)
        .await
        .map_err(|_| StatusCode::CONFLICT)?;

    let user = sqlx::query_as::<_, User>("SELECT * FROM users WHERE id = ?")
        .bind(&user_id)
        .fetch_one(&state.db)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(user))
}
