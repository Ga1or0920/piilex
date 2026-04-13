-- piilex SaaS schema (PostgreSQL)
-- Run: psql $DATABASE_URL -f 001_init_pg.sql

-- Teams
CREATE TABLE IF NOT EXISTS teams (
    id          VARCHAR(36) PRIMARY KEY,
    name        VARCHAR(200) NOT NULL,
    stripe_customer_id VARCHAR(255),
    plan        VARCHAR(20) NOT NULL DEFAULT 'free',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Users
CREATE TABLE IF NOT EXISTS users (
    id          VARCHAR(36) PRIMARY KEY,
    email       VARCHAR(254) NOT NULL UNIQUE,
    name        VARCHAR(200) NOT NULL,
    team_id     VARCHAR(36) NOT NULL REFERENCES teams(id),
    role        VARCHAR(20) NOT NULL DEFAULT 'member',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- API keys
CREATE TABLE IF NOT EXISTS api_keys (
    id          VARCHAR(36) PRIMARY KEY,
    user_id     VARCHAR(36) NOT NULL REFERENCES users(id),
    team_id     VARCHAR(36) NOT NULL REFERENCES teams(id),
    key_hash    VARCHAR(64) NOT NULL,
    name        VARCHAR(200) NOT NULL,
    last_used   TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Scan history
CREATE TABLE IF NOT EXISTS scans (
    id              VARCHAR(36) PRIMARY KEY,
    team_id         VARCHAR(36) NOT NULL REFERENCES teams(id),
    user_id         VARCHAR(36) REFERENCES users(id),
    project_name    VARCHAR(200) NOT NULL,
    files_scanned   INTEGER NOT NULL,
    findings_count  INTEGER NOT NULL,
    critical_count  INTEGER NOT NULL DEFAULT 0,
    high_count      INTEGER NOT NULL DEFAULT 0,
    medium_count    INTEGER NOT NULL DEFAULT 0,
    low_count       INTEGER NOT NULL DEFAULT 0,
    frameworks      JSONB,
    duration_ms     INTEGER NOT NULL,
    pii_type_summary JSONB,
    language_summary JSONB,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Scan findings
CREATE TABLE IF NOT EXISTS scan_findings (
    id          VARCHAR(36) PRIMARY KEY,
    scan_id     VARCHAR(36) NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    pii_type    VARCHAR(50) NOT NULL,
    severity    VARCHAR(20) NOT NULL,
    file_path   TEXT NOT NULL,
    line        INTEGER NOT NULL,
    code_snippet TEXT,
    data_flow   JSONB,
    framework_mappings JSONB,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Stripe subscriptions
CREATE TABLE IF NOT EXISTS subscriptions (
    id                      VARCHAR(36) PRIMARY KEY,
    team_id                 VARCHAR(36) NOT NULL REFERENCES teams(id),
    stripe_subscription_id  VARCHAR(255) NOT NULL UNIQUE,
    stripe_price_id         VARCHAR(255) NOT NULL,
    status                  VARCHAR(30) NOT NULL,
    current_period_start    TIMESTAMPTZ,
    current_period_end      TIMESTAMPTZ,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at              TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_users_team ON users(team_id);
CREATE INDEX IF NOT EXISTS idx_scans_team ON scans(team_id);
CREATE INDEX IF NOT EXISTS idx_scans_created ON scans(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_scan_findings_scan ON scan_findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_api_keys_hash ON api_keys(key_hash);
CREATE INDEX IF NOT EXISTS idx_subscriptions_team ON subscriptions(team_id);

-- Partial indexes for performance
CREATE INDEX IF NOT EXISTS idx_scans_team_recent ON scans(team_id, created_at DESC)
    WHERE created_at > NOW() - INTERVAL '90 days';
CREATE INDEX IF NOT EXISTS idx_subscriptions_active ON subscriptions(team_id)
    WHERE status IN ('active', 'trialing');
