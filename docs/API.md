# MosWAF REST API

Everything lives under `https://<IP>:<MOSWAF_ADMIN_PORT>/api/`, port `9443` by
default, behind a self-signed certificate (use `curl -k` when testing).

Except for `POST /api/auth/login` and `GET /api/health`, every endpoint needs:

```
Authorization: Bearer <token>
```

Errors always come back as `{"error": "description"}` with a matching HTTP status.

---

## Authentication

### `POST /api/auth/login`

```bash
curl -sk https://127.0.0.1:9443/api/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"..."}'
```

```json
{
  "token": "eyJhbGciOiJIUzI1NiIs...",
  "expires_at": "2026-09-18T05:12:00Z",
  "user": { "id": 1, "username": "admin", "created_at": "..." }
}
```

Five failed attempts from one IP lock it out for 5 minutes; ten lock it for 30.
The counter lives in process memory and resets on restart.

### `GET /api/auth/me`

Returns the signed-in account.

### `POST /api/auth/password`

```json
{ "current": "old-password", "new": "new-password-at-least-8-chars" }
```

---

## Sites

### `GET /api/sites`

An array of sites. The TLS private key is **never** returned; `has_tls` tells you
whether a certificate is installed.

### `POST /api/sites`

```json
{
  "name": "Online store",
  "domains": ["example.com", "www.example.com"],
  "upstream_scheme": "http",
  "upstream_host": "10.0.0.5",
  "upstream_port": 8080,
  "mode": "protect",
  "challenge": "auto",
  "rate_rps": 0,
  "rate_burst": 0,
  "force_https": false,
  "tls_cert": "-----BEGIN CERTIFICATE-----\n...",
  "tls_key": "-----BEGIN PRIVATE KEY-----\n..."
}
```

| Field | Values | Meaning |
|-------|--------|---------|
| `mode` | `protect` / `monitor` / `off` | block for real / log only / pass everything |
| `challenge` | `auto` / `always` / `off` | when the JS challenge is used |
| `rate_rps` | integer, `0` = use the global value | requests per second per IP |
| `rate_burst` | integer, `0` = use the global value | threshold over a 10 second window |

Every site change makes the control plane rewrite the nginx files and publish the
configuration to Redis; the proxy container notices the file change and reloads.

### `PUT /api/sites/{id}`

Same body as `POST`. Leave `tls_cert` and `tls_key` empty to keep the certificate
already in use.

### `DELETE /api/sites/{id}`

---

## Detection rules

### `GET /api/rules`

Returns both the built-in rules (`builtin: true`) and custom ones.

### `POST /api/rules`

```json
{
  "name": "Block external access to /internal",
  "category": "custom",
  "target": "uri",
  "pattern": "(?i)^/internal/",
  "action": "deny",
  "severity": "high"
}
```

| Field | Values |
|-------|--------|
| `target` | `any`, `uri`, `args`, `body`, `ua`, `header`, `cookie` |
| `action` | `deny`, `challenge`, `ban`, `log` |
| `severity` | `low`, `medium`, `high`, `critical` |

Custom rule ids are always prefixed with `custom-`. Patterns are syntax checked
before they are stored.

### `PUT /api/rules/{id}` · `POST /api/rules/{id}/toggle` · `DELETE /api/rules/{id}`

```json
{ "enabled": false }
```

Built-in rules can only be **disabled**, never deleted, so a later upgrade still
has something to compare against.

---

## IP lists

### `GET /api/ips?kind=black`

`kind` is `black` or `white`. Omit it to get both.

### `POST /api/ips`

```json
{ "cidr": "45.83.122.0/24", "kind": "black", "reason": "Layer 7 flood", "minutes": 60 }
```

`minutes: 0` means permanent. Addresses are normalised before storage
(`1.2.3.4/24` becomes `1.2.3.0/24`).

### `DELETE /api/ips/{id}`

---

## Temporary bans

These are created by the engine itself when an IP repeatedly crosses the rate
limit. They live only in the data plane's shared memory, so the control plane
proxies these two calls to it.

### `GET /api/bans`

```json
{ "items": [ { "ip": "45.83.122.9", "reason": "rate_rps", "ttl": 463.8 } ], "total": 1 }
```

### `DELETE /api/bans/{ip}`

Lifts the ban for one IP. Use `*` as the id to lift every temporary ban.

---

## Attack log

### `GET /api/events`

| Parameter | Example | Meaning |
|-----------|---------|---------|
| `hours` | `24` | time window |
| `site` | `s1a2b3c4d5` | filter by site |
| `ip` | `45.83.122.9` | filter by IP |
| `action` | `deny` | `deny`, `challenge`, `monitor`, `log` |
| `severity` | `high` | severity |
| `q` | `union` | search URI, User-Agent and rule name |
| `limit` / `offset` | `50` / `0` | paging, 500 maximum |

```json
{ "items": [ { "id": 1, "ts": "...", "ip": "...", "action": "deny", "rule_name": "SQLi - UNION SELECT" } ],
  "total": 1284, "limit": 50, "offset": 0 }
```

Only requests that were blocked, challenged or matched a rule are recorded. To
log normal traffic as well, enable `log_allowed` in the settings (it uses a lot
of disk).

---

## Statistics

### `GET /api/stats/overview?hours=24`

```json
{
  "requests": 83768, "blocked": 18206, "challenged": 5615,
  "sites_total": 3, "sites_active": 2, "under_attack": true,
  "top_attackers": [ { "key": "45.83.122.9", "count": 3184 } ],
  "top_rules":     [ { "key": "sqli-union", "label": "SQLi - UNION SELECT", "count": 2890 } ],
  "config_version": 1737000000000
}
```

### `GET /api/stats/timeseries?hours=6`

An array of per-minute points:
`{ "minute": "...", "total": 0, "blocked": 0, "challenged": 0, "monitored": 0 }`.

Minutes with no traffic are absent from the array; the dashboard fills them with
zeros.

---

## Settings

### `GET /api/settings` · `PUT /api/settings`

Send only the fields you want to change; everything else is preserved.

| Field | Default | Meaning |
|-------|---------|---------|
| `under_attack` | `false` | force every unknown visitor through the JS challenge |
| `default_mode` | `protect` | mode for sites that do not set their own |
| `global_rate_rps` | `60` | requests per second per IP |
| `global_rate_burst` | `120` | threshold over a 10 second window |
| `ban_seconds` | `600` | temporary ban duration |
| `challenge_difficulty` | `16` | leading zero bits of SHA-256, capped at 24 |
| `challenge_ttl` | `1800` | challenge cookie lifetime |
| `block_status` | `403` | status code returned when blocking |
| `real_ip_header` | `""` | `X-Forwarded-For`, `CF-Connecting-IP`, ... |
| `trusted_proxies` | `[]` | only trust the real-IP header from these ranges |
| `scan_body` | `true` | scan POST bodies |
| `max_body_scan` | `65536` | maximum body bytes scanned |
| `log_retain_days` | `7` | how long the attack log is kept |

> Only set `real_ip_header` when a CDN or proxy genuinely sits in front of MosWAF
> and `trusted_proxies` is filled in. Otherwise an attacker just sets the header
> themselves and spoofs any IP they like.

### `POST /api/settings/under-attack`

```json
{ "enabled": true }
```

Separated out so it is a single button during an attack.

---

## System

### `GET /api/health`

No authentication. Returns `200` while Postgres is reachable.

### `GET /api/system/status`

```json
{ "config_version": 1737000000000, "database": "ok", "redis": "ok",
  "dataplane": { "status": "ok", "version": 17 }, "event_queue": 0 }
```

### `POST /api/system/publish`

Republish the whole configuration to the data plane if you suspect it has drifted.

---

## Data plane internal endpoints

These listen on port `8081` and are only reachable from inside the Docker network
(the server block has an `allow` list of private ranges).

| Path | Purpose |
|------|---------|
| `GET /healthz` | status and the configuration version in use |
| `GET /metrics` | Prometheus format |
| `GET /sync` | load the configuration now, without waiting for the 3s poll |
| `GET /bans` | list temporary bans |
| `GET /unban?ip=` | lift one ban, or all of them with `ip=*` |

```
moswaf_config_version 1737000000000
moswaf_requests_total 1284
moswaf_blocked_total 96
moswaf_challenged_total 12
moswaf_rules_active 18
moswaf_banned_ips 3
moswaf_event_queue 0
```
