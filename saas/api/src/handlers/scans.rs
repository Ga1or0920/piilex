use crate::{db, middleware, models::*, AppState};
use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    Json,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[derive(Deserialize)]
pub struct ListParams {
    limit: Option<i64>,
    offset: Option<i64>,
}

pub async fn list_scans(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(params): Query<ListParams>,
) -> Result<Json<Vec<Scan>>, StatusCode> {
    let claims = middleware::auth(&headers, &state.jwt_secret)?;
    let limit = params.limit.unwrap_or(50).min(100);
    let offset = params.offset.unwrap_or(0);

    let scans = sqlx::query_as::<_, Scan>(
        "SELECT * FROM scans WHERE team_id = ? ORDER BY created_at DESC LIMIT ? OFFSET ?",
    )
    .bind(&claims.team_id)
    .bind(limit)
    .bind(offset)
    .fetch_all(&state.db)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(scans))
}

pub async fn create_scan(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<CreateScanRequest>,
) -> Result<(StatusCode, Json<Scan>), StatusCode> {
    let claims = middleware::auth(&headers, &state.jwt_secret)?;
    let scan_id = db::generate_id();

    let frameworks_json = body
        .frameworks
        .as_ref()
        .map(|f| serde_json::to_string(f).unwrap_or_default());
    let pii_json = body
        .pii_type_summary
        .as_ref()
        .map(|v| v.to_string());
    let lang_json = body
        .language_summary
        .as_ref()
        .map(|v| v.to_string());

    sqlx::query(
        "INSERT INTO scans (id, team_id, user_id, project_name, files_scanned, findings_count, \
         critical_count, high_count, medium_count, low_count, frameworks, duration_ms, \
         pii_type_summary, language_summary) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(&scan_id)
    .bind(&claims.team_id)
    .bind(&claims.sub)
    .bind(&body.project_name)
    .bind(body.files_scanned)
    .bind(body.findings_count)
    .bind(body.critical_count)
    .bind(body.high_count)
    .bind(body.medium_count)
    .bind(body.low_count)
    .bind(&frameworks_json)
    .bind(body.duration_ms)
    .bind(&pii_json)
    .bind(&lang_json)
    .execute(&state.db)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // Insert findings if provided
    if let Some(findings) = &body.findings {
        for f in findings {
            let finding_id = db::generate_id();
            let df_json = f.data_flow.as_ref().map(|v| v.to_string());
            let fm_json = f.framework_mappings.as_ref().map(|v| v.to_string());

            let _ = sqlx::query(
                "INSERT INTO scan_findings (id, scan_id, pii_type, severity, file_path, line, \
                 code_snippet, data_flow, framework_mappings) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            )
            .bind(&finding_id)
            .bind(&scan_id)
            .bind(&f.pii_type)
            .bind(&f.severity)
            .bind(&f.file_path)
            .bind(f.line)
            .bind(&f.code_snippet)
            .bind(&df_json)
            .bind(&fm_json)
            .execute(&state.db)
            .await;
        }
    }

    let scan = sqlx::query_as::<_, Scan>("SELECT * FROM scans WHERE id = ?")
        .bind(&scan_id)
        .fetch_one(&state.db)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // Send email notification for critical/high findings (async, non-blocking)
    if body.critical_count > 0 || body.high_count > 0 {
        let state_clone = state.clone();
        let project = body.project_name.clone();
        let sid = scan_id.clone();
        let fc = body.findings_count;
        let cc = body.critical_count;
        let hc = body.high_count;
        let pii_summary = body.pii_type_summary.clone();
        let user_id = claims.sub.clone();

        tokio::spawn(async move {
            send_scan_alert(&state_clone, &user_id, &project, &sid, fc, cc, hc, pii_summary).await;
        });
    }

    Ok((StatusCode::CREATED, Json(scan)))
}

async fn send_scan_alert(
    state: &AppState,
    user_id: &str,
    project: &str,
    scan_id: &str,
    findings: i32,
    critical: i32,
    high: i32,
    pii_summary: Option<serde_json::Value>,
) {
    // Get user email
    let email = sqlx::query_scalar::<_, String>("SELECT email FROM users WHERE id = ?")
        .bind(user_id)
        .fetch_one(&state.db)
        .await;

    let email = match email {
        Ok(e) => e,
        Err(_) => return,
    };

    let top_types: Vec<(String, i32)> = pii_summary
        .and_then(|v| serde_json::from_value::<std::collections::HashMap<String, i32>>(v).ok())
        .map(|m| {
            let mut v: Vec<_> = m.into_iter().collect();
            v.sort_by(|a, b| b.1.cmp(&a.1));
            v
        })
        .unwrap_or_default();

    let (subject, html) = crate::email::templates::new_findings_alert(
        project,
        scan_id,
        findings,
        critical,
        high,
        &top_types,
        &state.base_url,
    );

    if let Err(e) = crate::email::send_email(&state.email_config, &email, &subject, &html).await {
        eprintln!("Failed to send scan alert email: {}", e);
    }
}

pub async fn get_scan(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<Scan>, StatusCode> {
    let claims = middleware::auth(&headers, &state.jwt_secret)?;

    let scan = sqlx::query_as::<_, Scan>("SELECT * FROM scans WHERE id = ? AND team_id = ?")
        .bind(&id)
        .bind(&claims.team_id)
        .fetch_optional(&state.db)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::NOT_FOUND)?;

    Ok(Json(scan))
}

pub async fn get_findings(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<Vec<ScanFinding>>, StatusCode> {
    let claims = middleware::auth(&headers, &state.jwt_secret)?;

    // Verify scan belongs to team
    let _ = sqlx::query_scalar::<_, String>(
        "SELECT id FROM scans WHERE id = ? AND team_id = ?",
    )
    .bind(&id)
    .bind(&claims.team_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
    .ok_or(StatusCode::NOT_FOUND)?;

    let findings = sqlx::query_as::<_, ScanFinding>(
        "SELECT * FROM scan_findings WHERE scan_id = ? ORDER BY severity DESC, line ASC",
    )
    .bind(&id)
    .fetch_all(&state.db)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(findings))
}

// ── Trend / analytics endpoints ──

#[derive(Serialize, sqlx::FromRow)]
pub struct TrendPoint {
    pub date: String,
    pub scan_count: i64,
    pub total_findings: i64,
    pub total_critical: i64,
    pub total_high: i64,
}

pub async fn get_trends(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(params): Query<TrendParams>,
) -> Result<Json<Vec<TrendPoint>>, StatusCode> {
    let claims = middleware::auth(&headers, &state.jwt_secret)?;
    let days = params.days.unwrap_or(30).min(365);

    let trends = sqlx::query_as::<_, TrendPoint>(
        "SELECT \
           DATE(created_at) as date, \
           COUNT(*) as scan_count, \
           SUM(findings_count) as total_findings, \
           SUM(critical_count) as total_critical, \
           SUM(high_count) as total_high \
         FROM scans \
         WHERE team_id = ? AND created_at >= DATE('now', '-' || ? || ' days') \
         GROUP BY DATE(created_at) \
         ORDER BY date ASC",
    )
    .bind(&claims.team_id)
    .bind(days)
    .fetch_all(&state.db)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(trends))
}

#[derive(Deserialize)]
pub struct TrendParams {
    days: Option<i64>,
}

#[derive(Serialize)]
pub struct PiiDistribution {
    pub pii_type: String,
    pub count: i64,
}

pub async fn get_pii_distribution(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<Vec<PiiDistribution>>, StatusCode> {
    let claims = middleware::auth(&headers, &state.jwt_secret)?;

    // Aggregate PII types from the 10 most recent scans
    let scans = sqlx::query_scalar::<_, Option<String>>(
        "SELECT pii_type_summary FROM scans WHERE team_id = ? ORDER BY created_at DESC LIMIT 10",
    )
    .bind(&claims.team_id)
    .fetch_all(&state.db)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let mut totals: std::collections::HashMap<String, i64> = std::collections::HashMap::new();
    for summary in scans.into_iter().flatten() {
        if let Ok(map) = serde_json::from_str::<std::collections::HashMap<String, i64>>(&summary) {
            for (k, v) in map {
                *totals.entry(k).or_default() += v;
            }
        }
    }

    let mut dist: Vec<PiiDistribution> = totals
        .into_iter()
        .map(|(pii_type, count)| PiiDistribution { pii_type, count })
        .collect();
    dist.sort_by(|a, b| b.count.cmp(&a.count));

    Ok(Json(dist))
}
