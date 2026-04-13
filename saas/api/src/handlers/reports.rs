use crate::{email, AppState};
use std::sync::Arc;

/// Run the weekly summary report for all teams.
/// Called by a scheduled task (e.g., cron, tokio interval).
pub async fn send_weekly_reports(state: Arc<AppState>) {
    eprintln!("Generating weekly summary reports...");

    // Get all teams with at least one scan this week
    let teams = sqlx::query_as::<_, (String, String)>(
        "SELECT DISTINCT t.id, t.name FROM teams t \
         JOIN scans s ON s.team_id = t.id \
         WHERE s.created_at >= DATE('now', '-7 days')",
    )
    .fetch_all(&state.db)
    .await;

    let teams = match teams {
        Ok(t) => t,
        Err(e) => {
            eprintln!("Failed to fetch teams for weekly report: {}", e);
            return;
        }
    };

    for (team_id, team_name) in &teams {
        if let Err(e) = send_team_weekly_report(&state, team_id, team_name).await {
            eprintln!("Failed to send weekly report for team {}: {}", team_id, e);
        }
    }

    eprintln!("Weekly reports sent to {} teams", teams.len());
}

async fn send_team_weekly_report(
    state: &AppState,
    team_id: &str,
    team_name: &str,
) -> Result<(), String> {
    // Aggregate stats for the past week
    let stats = sqlx::query_as::<_, (i32, i32, i32, i32)>(
        "SELECT \
           COALESCE(COUNT(*), 0), \
           COALESCE(SUM(findings_count), 0), \
           COALESCE(SUM(critical_count), 0), \
           COALESCE(SUM(high_count), 0) \
         FROM scans WHERE team_id = ? AND created_at >= DATE('now', '-7 days')",
    )
    .bind(team_id)
    .fetch_one(&state.db)
    .await
    .map_err(|e| e.to_string())?;

    let (total_scans, total_findings, total_critical, total_high) = stats;

    // Previous week for trend comparison
    let prev_stats = sqlx::query_as::<_, (i32,)>(
        "SELECT COALESCE(SUM(findings_count), 0) \
         FROM scans WHERE team_id = ? \
         AND created_at >= DATE('now', '-14 days') \
         AND created_at < DATE('now', '-7 days')",
    )
    .bind(team_id)
    .fetch_one(&state.db)
    .await
    .map_err(|e| e.to_string())?;

    let trend = if total_findings > prev_stats.0 {
        "up"
    } else if total_findings < prev_stats.0 {
        "down"
    } else {
        "stable"
    };

    // Top projects
    let top_projects = sqlx::query_as::<_, (String, i32)>(
        "SELECT project_name, SUM(findings_count) as total \
         FROM scans WHERE team_id = ? AND created_at >= DATE('now', '-7 days') \
         GROUP BY project_name ORDER BY total DESC LIMIT 5",
    )
    .bind(team_id)
    .fetch_all(&state.db)
    .await
    .unwrap_or_default();

    // Top PII types (from pii_type_summary JSON)
    let summaries = sqlx::query_scalar::<_, Option<String>>(
        "SELECT pii_type_summary FROM scans \
         WHERE team_id = ? AND created_at >= DATE('now', '-7 days')",
    )
    .bind(team_id)
    .fetch_all(&state.db)
    .await
    .unwrap_or_default();

    let mut type_totals: std::collections::HashMap<String, i32> = std::collections::HashMap::new();
    for summary in summaries.into_iter().flatten() {
        if let Ok(map) = serde_json::from_str::<std::collections::HashMap<String, i32>>(&summary) {
            for (k, v) in map {
                *type_totals.entry(k).or_default() += v;
            }
        }
    }
    let mut top_types: Vec<(String, i32)> = type_totals.into_iter().collect();
    top_types.sort_by(|a, b| b.1.cmp(&a.1));

    let period = format!(
        "{} - {}",
        chrono::Utc::now()
            .checked_sub_signed(chrono::Duration::days(7))
            .map(|d| d.format("%b %d").to_string())
            .unwrap_or_default(),
        chrono::Utc::now().format("%b %d, %Y")
    );

    let (subject, html) = email::templates::weekly_summary(
        team_name,
        &period,
        total_scans,
        total_findings,
        total_critical,
        total_high,
        &top_projects,
        &top_types,
        trend,
        &state.base_url,
    );

    // Send to team owner
    let owner_email = sqlx::query_scalar::<_, String>(
        "SELECT email FROM users WHERE team_id = ? AND role = 'owner' LIMIT 1",
    )
    .bind(team_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| e.to_string())?;

    if let Some(email_addr) = owner_email {
        email::send_email(&state.email_config, &email_addr, &subject, &html)
            .await
            .map_err(|e| format!("email send failed: {}", e))?;
    }

    Ok(())
}
