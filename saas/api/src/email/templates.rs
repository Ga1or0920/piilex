/// Generate HTML email for new PII findings alert.
pub fn new_findings_alert(
    project_name: &str,
    scan_id: &str,
    findings_count: i32,
    critical_count: i32,
    high_count: i32,
    top_types: &[(String, i32)],
    dashboard_url: &str,
) -> (String, String) {
    let subject = format!(
        "piilex: {} new finding(s) in {}",
        findings_count, project_name
    );

    let severity_summary = if critical_count > 0 {
        format!(
            "<span style='color:#d32f2f;font-weight:700'>{} critical</span>, {} high",
            critical_count, high_count
        )
    } else if high_count > 0 {
        format!(
            "<span style='color:#f57c00;font-weight:700'>{} high</span>",
            high_count
        )
    } else {
        format!("{} finding(s)", findings_count)
    };

    let types_html: String = top_types
        .iter()
        .take(5)
        .map(|(t, c)| format!("<li><code>{}</code>: {}</li>", t, c))
        .collect::<Vec<_>>()
        .join("\n");

    let html = format!(
        r#"<!DOCTYPE html>
<html><head><meta charset="utf-8"></head>
<body style="font-family:-apple-system,sans-serif;max-width:600px;margin:0 auto;padding:20px;">
<div style="background:#1a1a2e;color:white;padding:16px 24px;border-radius:8px 8px 0 0;">
  <h2 style="margin:0">piilex Scan Alert</h2>
</div>
<div style="border:1px solid #ddd;border-top:none;padding:24px;border-radius:0 0 8px 8px;">
  <p>A new scan of <strong>{project}</strong> detected <strong>{severity}</strong>.</p>

  <table style="width:100%;border-collapse:collapse;margin:16px 0;">
    <tr style="background:#f5f5f5"><th style="text-align:left;padding:8px">Metric</th><th style="text-align:right;padding:8px">Count</th></tr>
    <tr><td style="padding:8px">Total findings</td><td style="text-align:right;padding:8px"><strong>{total}</strong></td></tr>
    <tr><td style="padding:8px;color:#d32f2f">Critical</td><td style="text-align:right;padding:8px">{critical}</td></tr>
    <tr><td style="padding:8px;color:#f57c00">High</td><td style="text-align:right;padding:8px">{high}</td></tr>
  </table>

  <p><strong>Top PII types:</strong></p>
  <ul>{types}</ul>

  <a href="{url}" style="display:inline-block;background:#4361ee;color:white;padding:12px 24px;border-radius:6px;text-decoration:none;margin-top:16px;font-weight:600">View in Dashboard</a>

  <p style="color:#999;font-size:12px;margin-top:24px">Scan ID: {scan_id}</p>
</div>
</body></html>"#,
        project = project_name,
        severity = severity_summary,
        total = findings_count,
        critical = critical_count,
        high = high_count,
        types = types_html,
        url = format!("{}/index.html", dashboard_url),
        scan_id = scan_id,
    );

    (subject, html)
}

/// Generate HTML email for payment failure.
pub fn payment_failed(
    team_name: &str,
    reason: &str,
    dashboard_url: &str,
) -> (String, String) {
    let subject = format!("piilex: Payment failed for {}", team_name);

    let html = format!(
        r#"<!DOCTYPE html>
<html><head><meta charset="utf-8"></head>
<body style="font-family:-apple-system,sans-serif;max-width:600px;margin:0 auto;padding:20px;">
<div style="background:#d32f2f;color:white;padding:16px 24px;border-radius:8px 8px 0 0;">
  <h2 style="margin:0">Payment Failed</h2>
</div>
<div style="border:1px solid #ddd;border-top:none;padding:24px;border-radius:0 0 8px 8px;">
  <p>We were unable to process payment for your piilex Pro subscription.</p>

  <div style="background:#fff3e0;border-left:4px solid #f57c00;padding:12px 16px;margin:16px 0;">
    <strong>Reason:</strong> {reason}
  </div>

  <p>Your Pro features will remain active for a grace period. Please update your payment method to avoid service interruption.</p>

  <a href="{url}" style="display:inline-block;background:#4361ee;color:white;padding:12px 24px;border-radius:6px;text-decoration:none;margin-top:16px;font-weight:600">Update Payment Method</a>

  <p style="color:#999;font-size:12px;margin-top:24px">
    If you believe this is an error, please contact support.
  </p>
</div>
</body></html>"#,
        reason = reason,
        url = format!("{}/index.html#billing", dashboard_url),
    );

    (subject, html)
}

/// Generate HTML for weekly summary report.
pub fn weekly_summary(
    team_name: &str,
    period: &str,
    total_scans: i32,
    total_findings: i32,
    total_critical: i32,
    total_high: i32,
    top_projects: &[(String, i32)],
    top_pii_types: &[(String, i32)],
    trend: &str, // "up", "down", "stable"
    dashboard_url: &str,
) -> (String, String) {
    let subject = format!("piilex Weekly Report: {} | {}", team_name, period);

    let trend_icon = match trend {
        "up" => "&#8593;",    // arrow up
        "down" => "&#8595;",  // arrow down
        _ => "&#8594;",       // arrow right
    };

    let trend_color = match trend {
        "up" => "#d32f2f",
        "down" => "#2e7d32",
        _ => "#666",
    };

    let projects_html: String = top_projects
        .iter()
        .take(5)
        .map(|(p, c)| format!("<tr><td style='padding:6px 8px'>{}</td><td style='text-align:right;padding:6px 8px'>{}</td></tr>", p, c))
        .collect::<Vec<_>>()
        .join("\n");

    let types_html: String = top_pii_types
        .iter()
        .take(5)
        .map(|(t, c)| format!("<tr><td style='padding:6px 8px'><code>{}</code></td><td style='text-align:right;padding:6px 8px'>{}</td></tr>", t, c))
        .collect::<Vec<_>>()
        .join("\n");

    let html = format!(
        r#"<!DOCTYPE html>
<html><head><meta charset="utf-8"></head>
<body style="font-family:-apple-system,sans-serif;max-width:600px;margin:0 auto;padding:20px;">
<div style="background:#1a1a2e;color:white;padding:16px 24px;border-radius:8px 8px 0 0;">
  <h2 style="margin:0">Weekly PII Report</h2>
  <p style="margin:4px 0 0;opacity:0.8">{team} | {period}</p>
</div>
<div style="border:1px solid #ddd;border-top:none;padding:24px;border-radius:0 0 8px 8px;">

  <div style="display:flex;gap:16px;margin-bottom:24px;">
    <div style="flex:1;text-align:center;background:#f5f5f5;padding:16px;border-radius:8px;">
      <div style="font-size:28px;font-weight:700">{scans}</div>
      <div style="font-size:12px;color:#666">Scans</div>
    </div>
    <div style="flex:1;text-align:center;background:#f5f5f5;padding:16px;border-radius:8px;">
      <div style="font-size:28px;font-weight:700">{findings}</div>
      <div style="font-size:12px;color:#666">Findings</div>
    </div>
    <div style="flex:1;text-align:center;background:#f5f5f5;padding:16px;border-radius:8px;">
      <div style="font-size:28px;font-weight:700;color:{trend_color}">{trend_icon}</div>
      <div style="font-size:12px;color:#666">Trend</div>
    </div>
  </div>

  <table style="width:100%;border-collapse:collapse;margin-bottom:8px;">
    <tr style="background:#fde8e8"><td style="padding:8px;color:#d32f2f;font-weight:600">Critical</td><td style="text-align:right;padding:8px">{critical}</td></tr>
    <tr style="background:#fff3e0"><td style="padding:8px;color:#f57c00;font-weight:600">High</td><td style="text-align:right;padding:8px">{high}</td></tr>
  </table>

  <h3 style="margin:24px 0 8px">Top Projects</h3>
  <table style="width:100%;border-collapse:collapse">{projects}</table>

  <h3 style="margin:24px 0 8px">Top PII Types</h3>
  <table style="width:100%;border-collapse:collapse">{types}</table>

  <a href="{url}" style="display:inline-block;background:#4361ee;color:white;padding:12px 24px;border-radius:6px;text-decoration:none;margin-top:24px;font-weight:600">View Dashboard</a>

  <p style="color:#999;font-size:11px;margin-top:24px">
    This is an automated weekly report from piilex.
    <a href="{url}" style="color:#999">Manage notifications</a>
  </p>
</div>
</body></html>"#,
        team = team_name,
        period = period,
        scans = total_scans,
        findings = total_findings,
        critical = total_critical,
        high = total_high,
        trend_icon = trend_icon,
        trend_color = trend_color,
        projects = projects_html,
        types = types_html,
        url = dashboard_url,
    );

    (subject, html)
}
