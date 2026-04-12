-- piilex SaaS schema

-- Teams
CREATE TABLE teams (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    stripe_customer_id TEXT,
    plan        TEXT NOT NULL DEFAULT 'free',  -- free | pro | enterprise
    created_at  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Users
CREATE TABLE users (
    id          TEXT PRIMARY KEY,
    email       TEXT NOT NULL UNIQUE,
    name        TEXT NOT NULL,
    team_id     TEXT NOT NULL REFERENCES teams(id),
    role        TEXT NOT NULL DEFAULT 'member',  -- owner | admin | member | viewer
    created_at  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- API keys (for CLI authentication)
CREATE TABLE api_keys (
    id          TEXT PRIMARY KEY,
    user_id     TEXT NOT NULL REFERENCES users(id),
    team_id     TEXT NOT NULL REFERENCES teams(id),
    key_hash    TEXT NOT NULL,  -- SHA256 of the actual key
    name        TEXT NOT NULL,
    last_used   TIMESTAMP,
    created_at  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Scan history
CREATE TABLE scans (
    id              TEXT PRIMARY KEY,
    team_id         TEXT NOT NULL REFERENCES teams(id),
    user_id         TEXT REFERENCES users(id),
    project_name    TEXT NOT NULL,
    files_scanned   INTEGER NOT NULL,
    findings_count  INTEGER NOT NULL,
    critical_count  INTEGER NOT NULL DEFAULT 0,
    high_count      INTEGER NOT NULL DEFAULT 0,
    medium_count    INTEGER NOT NULL DEFAULT 0,
    low_count       INTEGER NOT NULL DEFAULT 0,
    frameworks      TEXT,  -- JSON array: ["gdpr","ccpa"]
    duration_ms     INTEGER NOT NULL,
    pii_type_summary TEXT,  -- JSON: {"email":5,"password":2}
    language_summary TEXT,  -- JSON: {"typescript":10,"python":3}
    created_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Scan findings (detailed, for drill-down)
CREATE TABLE scan_findings (
    id          TEXT PRIMARY KEY,
    scan_id     TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    pii_type    TEXT NOT NULL,
    severity    TEXT NOT NULL,
    file_path   TEXT NOT NULL,
    line        INTEGER NOT NULL,
    code_snippet TEXT,
    data_flow   TEXT,  -- JSON or null
    framework_mappings TEXT,  -- JSON array
    created_at  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Stripe subscriptions
CREATE TABLE subscriptions (
    id                      TEXT PRIMARY KEY,
    team_id                 TEXT NOT NULL REFERENCES teams(id),
    stripe_subscription_id  TEXT NOT NULL UNIQUE,
    stripe_price_id         TEXT NOT NULL,
    status                  TEXT NOT NULL,  -- active | past_due | canceled | trialing
    current_period_start    TIMESTAMP,
    current_period_end      TIMESTAMP,
    created_at              TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at              TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Indexes
CREATE INDEX idx_users_team ON users(team_id);
CREATE INDEX idx_scans_team ON scans(team_id);
CREATE INDEX idx_scans_created ON scans(created_at DESC);
CREATE INDEX idx_scan_findings_scan ON scan_findings(scan_id);
CREATE INDEX idx_api_keys_hash ON api_keys(key_hash);
CREATE INDEX idx_subscriptions_team ON subscriptions(team_id);
