# SaaS Deployment Guide

## Database Options

### Development / Testing: SQLite (default)

```bash
# No setup needed -- SQLite database is created automatically
DATABASE_URL="sqlite:piilex.db?mode=rwc" cargo run
```

### Production: PostgreSQL

#### 1. Set up PostgreSQL

```bash
# Create database
createdb piilex_prod

# Run migrations
psql piilex_prod -f migrations/001_init_pg.sql

# Set connection string
export DATABASE_URL="postgres://user:password@host:5432/piilex_prod"
```

#### 2. Connection Pooling with PgBouncer (recommended)

```ini
# pgbouncer.ini
[databases]
piilex_prod = host=localhost port=5432 dbname=piilex_prod

[pgbouncer]
listen_port = 6432
listen_addr = 0.0.0.0
auth_type = md5
auth_file = /etc/pgbouncer/userlist.txt
pool_mode = transaction        # Best for web apps
max_client_conn = 200          # Max clients connecting to PgBouncer
default_pool_size = 20         # Connections per database
min_pool_size = 5
reserve_pool_size = 5
server_lifetime = 3600
```

```bash
# Connect through PgBouncer
export DATABASE_URL="postgres://user:password@localhost:6432/piilex_prod"
```

#### 3. Environment Variables

```bash
# Required
DATABASE_URL="postgres://user:password@host:5432/piilex_prod"
STRIPE_SECRET_KEY="sk_live_..."
STRIPE_WEBHOOK_SECRET="whsec_..."
JWT_SECRET="<random-256-bit-hex>"
LICENSE_PRIVATE_KEY="$(cat /path/to/private.pem)"

# Optional
DB_MAX_CONNECTIONS=20    # Default: 20 for PostgreSQL, 5 for SQLite
BASE_URL="https://app.piilex.dev"
PORT=3001
```

#### 4. Multi-Instance Deployment

```
                    Load Balancer
                    (nginx / ALB)
                         |
          +----+----+----+----+----+
          |    |    |    |    |    |
        App1 App2 App3 App4 App5 App6
          |    |    |    |    |    |
          +----+----+----+----+----+
                         |
                    PgBouncer
                    (pool_mode=transaction)
                         |
                    PostgreSQL
                    (primary)
```

**Key considerations for multi-instance:**
- All app instances connect through PgBouncer
- `pool_mode = transaction` avoids session-level lock contention
- Advisory locks via `pg_advisory_lock` for critical sections (e.g., subscription upsert)
- JWT auth is stateless -- no session sharing needed
- Webhook idempotency: use `stripe_subscription_id` UNIQUE constraint

#### 5. Docker Compose (production)

```yaml
version: "3.8"
services:
  api:
    build: ./saas/api
    environment:
      DATABASE_URL: postgres://piilex:secret@pgbouncer:6432/piilex
      STRIPE_SECRET_KEY: ${STRIPE_SECRET_KEY}
      STRIPE_WEBHOOK_SECRET: ${STRIPE_WEBHOOK_SECRET}
      JWT_SECRET: ${JWT_SECRET}
      LICENSE_PRIVATE_KEY: ${LICENSE_PRIVATE_KEY}
    ports:
      - "3001:3001"
    deploy:
      replicas: 3

  pgbouncer:
    image: edoburu/pgbouncer
    environment:
      DB_HOST: postgres
      DB_PORT: 5432
      DB_USER: piilex
      DB_PASSWORD: secret
      POOL_MODE: transaction
      MAX_CLIENT_CONN: 200
      DEFAULT_POOL_SIZE: 20
    ports:
      - "6432:6432"

  postgres:
    image: postgres:16
    environment:
      POSTGRES_DB: piilex
      POSTGRES_USER: piilex
      POSTGRES_PASSWORD: secret
    volumes:
      - pgdata:/var/lib/postgresql/data
      - ./migrations/001_init_pg.sql:/docker-entrypoint-initdb.d/init.sql

volumes:
  pgdata:
```

## Schema Differences: SQLite vs PostgreSQL

| Feature | SQLite | PostgreSQL |
|---------|--------|------------|
| JSON columns | TEXT | JSONB |
| Timestamps | TEXT (CURRENT_TIMESTAMP) | TIMESTAMPTZ (NOW()) |
| UPSERT | INSERT OR REPLACE | INSERT ... ON CONFLICT |
| Partial indexes | Not supported | Supported |
| Concurrent writes | Limited (WAL mode helps) | Full MVCC |
| Connection pooling | 5 max recommended | 20-100 via PgBouncer |
