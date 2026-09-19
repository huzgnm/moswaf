// Package store owns persistence: Postgres is the source of truth for the
// configuration, the rules and the attack log.
package store

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

type Store struct {
	pool *pgxpool.Pool
}

func Open(ctx context.Context, dsn string) (*Store, error) {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("invalid dsn: %w", err)
	}
	cfg.MaxConns = 10
	cfg.MaxConnLifetime = time.Hour

	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("cannot create the pool: %w", err)
	}

	// Postgres may not be ready the instant its container comes up
	var lastErr error
	for i := 0; i < 30; i++ {
		if lastErr = pool.Ping(ctx); lastErr == nil {
			return &Store{pool: pool}, nil
		}
		time.Sleep(time.Second)
	}
	pool.Close()
	return nil, fmt.Errorf("cannot connect to postgres: %w", lastErr)
}

func (s *Store) Close() { s.pool.Close() }

func (s *Store) Ping(ctx context.Context) error { return s.pool.Ping(ctx) }

const schema = `
CREATE TABLE IF NOT EXISTS users (
    id            BIGSERIAL PRIMARY KEY,
    username      TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS sites (
    id              TEXT PRIMARY KEY,
    name            TEXT NOT NULL,
    domains         JSONB NOT NULL DEFAULT '[]',
    upstream_scheme TEXT NOT NULL DEFAULT 'http',
    upstream_host   TEXT NOT NULL,
    upstream_port   INT  NOT NULL DEFAULT 80,
    mode            TEXT NOT NULL DEFAULT 'protect',
    challenge       TEXT NOT NULL DEFAULT 'auto',
    rate_rps        INT  NOT NULL DEFAULT 0,
    rate_burst      INT  NOT NULL DEFAULT 0,
    tls_cert        TEXT NOT NULL DEFAULT '',
    tls_key         TEXT NOT NULL DEFAULT '',
    force_https     BOOLEAN NOT NULL DEFAULT false,
    enabled         BOOLEAN NOT NULL DEFAULT true,
    rules_off       JSONB NOT NULL DEFAULT '[]',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS rules (
    id         TEXT PRIMARY KEY,
    name       TEXT NOT NULL,
    category   TEXT NOT NULL DEFAULT 'custom',
    target     TEXT NOT NULL DEFAULT 'any',
    pattern    TEXT NOT NULL,
    action     TEXT NOT NULL DEFAULT 'deny',
    severity   TEXT NOT NULL DEFAULT 'medium',
    enabled    BOOLEAN NOT NULL DEFAULT true,
    builtin    BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS ip_entries (
    id         BIGSERIAL PRIMARY KEY,
    cidr       TEXT NOT NULL,
    kind       TEXT NOT NULL,
    reason     TEXT NOT NULL DEFAULT '',
    expires_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (cidr, kind)
);

CREATE TABLE IF NOT EXISTS events (
    id        BIGSERIAL PRIMARY KEY,
    ts        TIMESTAMPTZ NOT NULL,
    ray       TEXT NOT NULL DEFAULT '',
    site      TEXT NOT NULL DEFAULT '',
    ip        TEXT NOT NULL DEFAULT '',
    method    TEXT NOT NULL DEFAULT '',
    host      TEXT NOT NULL DEFAULT '',
    uri       TEXT NOT NULL DEFAULT '',
    ua        TEXT NOT NULL DEFAULT '',
    referer   TEXT NOT NULL DEFAULT '',
    action    TEXT NOT NULL DEFAULT '',
    reason    TEXT NOT NULL DEFAULT '',
    rule_id   TEXT NOT NULL DEFAULT '',
    rule_name TEXT NOT NULL DEFAULT '',
    severity  TEXT NOT NULL DEFAULT '',
    status    INT  NOT NULL DEFAULT 0,
    rt        DOUBLE PRECISION NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS events_ts_idx     ON events (ts DESC);
CREATE INDEX IF NOT EXISTS events_ip_idx     ON events (ip);
CREATE INDEX IF NOT EXISTS events_site_idx   ON events (site);
CREATE INDEX IF NOT EXISTS events_action_idx ON events (action);

CREATE TABLE IF NOT EXISTS stats_minute (
    minute     TIMESTAMPTZ PRIMARY KEY,
    total      BIGINT NOT NULL DEFAULT 0,
    blocked    BIGINT NOT NULL DEFAULT 0,
    challenged BIGINT NOT NULL DEFAULT 0,
    monitored  BIGINT NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS settings (
    key   TEXT PRIMARY KEY,
    value JSONB NOT NULL
);

-- Added after the first release, so they have to be applied to existing installs
-- as well as new ones.
ALTER TABLE sites ADD COLUMN IF NOT EXISTS acme_enabled    BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE sites ADD COLUMN IF NOT EXISTS acme_email      TEXT NOT NULL DEFAULT '';
ALTER TABLE sites ADD COLUMN IF NOT EXISTS cert_expires_at TIMESTAMPTZ;
ALTER TABLE sites ADD COLUMN IF NOT EXISTS acme_last_error TEXT NOT NULL DEFAULT '';
ALTER TABLE sites ADD COLUMN IF NOT EXISTS acme_last_try   TIMESTAMPTZ;
ALTER TABLE sites ADD COLUMN IF NOT EXISTS flood_rps       INT NOT NULL DEFAULT 0;

ALTER TABLE stats_minute ADD COLUMN IF NOT EXISTS errors_4xx  BIGINT NOT NULL DEFAULT 0;
ALTER TABLE stats_minute ADD COLUMN IF NOT EXISTS blocked_4xx BIGINT NOT NULL DEFAULT 0;
ALTER TABLE stats_minute ADD COLUMN IF NOT EXISTS errors_5xx  BIGINT NOT NULL DEFAULT 0;
ALTER TABLE stats_minute ADD COLUMN IF NOT EXISTS page_views  BIGINT NOT NULL DEFAULT 0;

-- Two-letter country code, filled in by the control plane when the event is
-- recorded. Empty means unknown, which is an ordinary answer: private ranges have
-- no country, the dataset does not cover every address, and an installation with
-- no route to the internet has no dataset at all.
ALTER TABLE events ADD COLUMN IF NOT EXISTS country CHAR(2) NOT NULL DEFAULT '';

-- Accounts for the login gate that can be put in front of a site.
--
-- Separate from the dashboard's own users: these people are allowed through to
-- one site, not into MosWAF. Mixing them would mean an account created to read a
-- staging server could administer the firewall.
--
-- generation is what makes a session revocable. The cookie carries the value it
-- was signed with; raising this makes every cookie already issued for that
-- account stop verifying at the next request. Deleting the row does the same
-- thing more bluntly - a cookie naming an id that no longer exists is refused
-- without needing a counter at all.
CREATE TABLE IF NOT EXISTS site_users (
    id            BIGSERIAL PRIMARY KEY,
    site_id       TEXT NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
    username      TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    generation    BIGINT NOT NULL DEFAULT 1,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (site_id, username)
);
CREATE INDEX IF NOT EXISTS site_users_site_idx ON site_users (site_id);

ALTER TABLE sites ADD COLUMN IF NOT EXISTS auth_enabled BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE sites ADD COLUMN IF NOT EXISTS auth_paths   JSONB   NOT NULL DEFAULT '["/"]';

-- A site's own country rule. '' means "follow the global one", which is not the
-- same as 'off' - 'off' is a site opting out of a rule everything else follows.
ALTER TABLE sites ADD COLUMN IF NOT EXISTS geo_mode      TEXT  NOT NULL DEFAULT '';
ALTER TABLE sites ADD COLUMN IF NOT EXISTS geo_countries JSONB NOT NULL DEFAULT '[]';

-- The operator's own ordered allow/deny rules, tried before the firewall's own
-- checks. priority is the evaluation order and part of the meaning: the first
-- rule that matches decides, so two rules swapped are a different policy.
CREATE TABLE IF NOT EXISTS access_rules (
    id         TEXT PRIMARY KEY,
    name       TEXT NOT NULL,
    action     TEXT NOT NULL,
    priority   INTEGER NOT NULL DEFAULT 1000,
    enabled    BOOLEAN NOT NULL DEFAULT true,
    site_id    TEXT NOT NULL DEFAULT '',
    conditions JSONB NOT NULL DEFAULT '[]'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS access_rules_order_idx ON access_rules (priority, created_at);

-- The per-address budget stopped being two hard ceilings and became a sustained
-- rate plus a burst, so the old numbers no longer mean what they meant.
--
-- 60 and 120 were never a choice anybody made - they were this program's
-- defaults, and under the old algorithm they worked out at twelve requests a
-- second sustained, which one page load spent half of. Installations still
-- carrying them are carrying a mistake of ours, so they are moved to the new
-- defaults.
--
-- Only when BOTH still match exactly. An operator who picked their own numbers
-- picked them, and a migration that overwrites a deliberate setting because the
-- meaning changed underneath it is worse than one that leaves a stale value: the
-- first is us deciding we know better about their site.
UPDATE settings
   SET value = jsonb_set(
                 jsonb_set(value, '{global_rate_rps}',   '20'::jsonb, true),
                 '{global_rate_burst}', '300'::jsonb, true)
 WHERE key = 'global'
   AND value->>'global_rate_rps'   = '60'
   AND value->>'global_rate_burst' = '120';
`

func (s *Store) Migrate(ctx context.Context) error {
	if _, err := s.pool.Exec(ctx, schema); err != nil {
		return fmt.Errorf("failed to create the schema: %w", err)
	}
	return nil
}
