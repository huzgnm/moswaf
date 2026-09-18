# MosWAF

[![CI](https://github.com/huzgnm/moswaf/actions/workflows/ci.yml/badge.svg)](https://github.com/huzgnm/moswaf/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Go](https://img.shields.io/badge/Go-1.22%2B-00ADD8?logo=go&logoColor=white)](control/go.mod)
[![OpenResty](https://img.shields.io/badge/OpenResty-1.27-009639?logo=nginx&logoColor=white)](dataplane/Dockerfile)
[![Vue 3](https://img.shields.io/badge/Vue-3-4FC08D?logo=vuedotjs&logoColor=white)](web/package.json)
[![Docker](https://img.shields.io/badge/deploy-one--command-2496ED?logo=docker&logoColor=white)](install.sh)

A layer-7 web application firewall and anti-DDoS gateway. One command to deploy,
with an admin dashboard on its **own port**, fully separated from real traffic.

---

## One-command install

On a Linux server (Ubuntu / Debian / CentOS / Alma / ...), as root:

```bash
curl -fsSL https://raw.githubusercontent.com/huzgnm/moswaf/main/install.sh | bash
```

Or, from a source checkout:

```bash
sudo bash install.sh
```

Run without arguments and the installer shows a menu:

```
  1) INSTALL     fresh install
  2) UPDATE      pull the latest code, rebuild, keep all data
  3) REPAIR      diagnose and fix a broken install
  4) UNINSTALL   remove MosWAF
  0) Exit
```

**INSTALL** checks for (and installs) Docker, generates a `.env` with fresh random
secrets, builds the images, starts the stack and prints the dashboard URL together
with the admin password.

**UPDATE** is the same one-line command, run again:

```bash
curl -fsSL https://raw.githubusercontent.com/huzgnm/moswaf/main/install.sh | sudo bash
```

There is nothing else to remember. On a machine that already has MosWAF the
installer updates it — pressing Enter at the menu picks UPDATE, and with no
terminal at all (a provisioning script, CI) it updates without asking. Your `.env`,
database, certificates and attack log are kept; only the code is replaced.

The installer updates itself along with everything else, so a fix to `install.sh`
takes effect in the same run that fetches it.

**REPAIR** is for the usual breakages: a container stuck in a restart loop, a `.env`
that lost a secret, missing data directories, or an image that no longer matches the
source. It regenerates what is missing, rebuilds, recreates the containers and forces
a config resync — and never touches the database.

Every action also has a flag, for scripts and CI:

```bash
sudo bash install.sh --install --admin-port 9443 --admin-bind 127.0.0.1  # SSH tunnel only
sudo bash install.sh --update
sudo bash install.sh --repair
sudo bash install.sh --uninstall --yes
```

## Ports

| Port | Service | Notes |
|------|---------|-------|
| `80` | Data plane (HTTP) | real visitor traffic |
| `443` | Data plane (HTTPS) | real visitor traffic |
| **`9443`** | **Admin dashboard** | **separate port, HTTPS with a self-signed cert, configurable in `.env`** |
| `8081` | Data plane internal API | Docker network only, never published |

The dashboard never shares a port with traffic: hammering 80/443 cannot reach
the admin panel. For a tighter setup, set `MOSWAF_ADMIN_BIND=127.0.0.1` and
reach it through a tunnel:

```bash
ssh -L 9443:127.0.0.1:9443 root@SERVER_IP
```

## Architecture

```
                      Internet
                         │
              ┌──────────▼───────────┐   ports 80/443
              │   proxy (OpenResty)  │   ← data plane, Lua engine
              │  rate limit ▸ IP set │
              │  JS challenge ▸ rules│
              └─────┬──────────┬─────┘
       config (3s)  │          │  events + counters
              ┌─────▼──────────▼─────┐
              │        Redis         │
              └─────┬──────────┬─────┘
                    │          │
              ┌─────▼──────────▼─────┐   port 9443 (separate)
              │   mgmt (Go + Vue)    │   ← control plane + dashboard
              └──────────┬───────────┘
                         │
                   ┌─────▼─────┐
                   │ Postgres  │  sites, rules, attack log
                   └───────────┘
```

Why the split:

- The **data plane** only filters traffic. No database, no blocking I/O. Every
  decision reads from an in-memory `lua_shared_dict`, so the per-request cost
  stays in the tens of microseconds.
- The **control plane** owns the source of truth in Postgres, publishes policy
  to Redis and writes the nginx site files. If the control plane goes down, the
  WAF **keeps blocking** using the last configuration it loaded.

## Defense layers (in execution order)

| # | Layer | What it does |
|---|-------|--------------|
| 1 | nginx `limit_conn` / `limit_req` | cuts crude floods before any Lua runs |
| 2 | IP allowlist | skips every remaining check |
| 3 | IP blocklist + temporary bans | rejected straight from the shared dict |
| 4 | Two-window rate limiting (1s + 10s) | catches instant bursts *and* slow, evenly paced floods |
| 5 | JS challenge (SHA-256 proof-of-work) | filters clients that cannot run JavaScript |
| 6 | Signature engine | SQLi, XSS, LFI/traversal, RCE, SSRF, scanners, CRLF |

Cross the threshold three times in a minute and the IP is **temporarily banned**
instead of being rejected request by request — far cheaper when a botnet is
pounding on the door.

### How the JS challenge works

A visitor without a valid cookie gets the challenge page. The browser must find
a `nonce` such that `SHA-256(salt + nonce)` starts with N zero bits (16 by
default, roughly 0.1–0.3s of work). On success it receives an HMAC-signed cookie
valid for 30 minutes.

Bots driving `curl` or `python-requests` do not run JavaScript, so they fail
immediately. A botnet that wants to sustain a flood has to pay thousands of
times more CPU than the server does.

When an attack is in progress, flip **under-attack mode** in the top right of
the dashboard: every unknown visitor must solve a challenge before reaching the
site.

## Getting started

1. Open `https://SERVER_IP:9443` and log in with the credentials the installer printed.
2. **Change the password immediately** under Settings.
3. Go to **Sites → Add site** and enter your domains plus the real upstream
   (for example `10.0.0.5:8080`, or `host.docker.internal:8080` if the app runs
   on this same machine).
4. Point the domain's A record at the machine running MosWAF.
5. Watch **Overview** and **Attack log**.

Run in **monitor** mode for the first few days to see whether any rule blocks
legitimate traffic, then switch to **protect**.

## Certificates

Turn on **Get and renew the certificate automatically** when adding a site, give a
contact email, and MosWAF obtains a Let's Encrypt certificate over ACME HTTP-01 and
renews it once 30 days are left. Nothing to schedule and no cron job to forget.

Two things have to be true before it can work, because they are what the authority
checks:

- the domain already resolves to this server
- port 80 is reachable from the internet

The challenge path `/.well-known/acme-challenge/` is answered ahead of every filter,
so a site whose certificate has already expired can still renew. Renewal runs every
six hours; a failed order backs off for an hour and the reason is shown on the site
row. **Get cert** on that row runs an order immediately and reports what the
authority said.

While testing, point at the staging endpoint to avoid the production rate limits:

```bash
MOSWAF_ACME_DIRECTORY=https://acme-staging-v02.api.letsencrypt.org/directory
```

The challenge location is the one place in the config that is exempt from the WAF,
and it has to be: an authority cannot solve a JavaScript challenge, and a random
token can look like an attack payload. It keeps its own much smaller rate limit, so
being exempt does not make it a cheap way to flood the server.

## Verifying that it actually blocks

After adding a site, fire a batch of common attacks at your own site and compare
the results:

```bash
./scripts/attack-sim.sh https://example.com
./scripts/attack-sim.sh https://example.com --flood 150   # also exercise rate limiting
```

The script tries SQLi, XSS, path traversal, RCE, secret-file probes, SSRF to
cloud metadata and scanner user agents — and also checks that two **normal**
requests are *not* blocked. A dashboard reading "0 blocked" does not tell you
whether nobody attacked you or your configuration is simply wrong; this does.

## Everyday commands

```bash
cd /opt/moswaf
docker compose ps                 # status
docker compose logs -f proxy      # data plane logs
docker compose logs -f mgmt       # control plane logs
docker compose restart proxy
```

From a source checkout there is also `make`:

```bash
make up          # build and start
make logs        # follow logs
make nginx-test  # validate the running nginx config
make down        # stop
```

## Development

Requires Go >= 1.22 and Node >= 20.

Enable the repository's git hooks once per clone:

```bash
git config core.hooksPath .githooks
```

```bash
make web-build   # build the dashboard into control/internal/web/dist
make go-build    # build the control plane binary
make go-test     # go vet + go test
make lua-check   # check Lua syntax (needs luajit)
make web-dev     # Vite dev server, proxying the API to https://127.0.0.1:9443
```

After editing the Lua engine in `dataplane/lua/moswaf/`:

```bash
docker compose restart proxy
```

## Layout

```
moswaf/
├── install.sh              one-command installer
├── docker-compose.yml
├── scripts/attack-sim.sh   verify the WAF blocks what it should
├── dataplane/              OpenResty - the filtering layer
│   ├── conf/               nginx.conf, default server, challenge/blocked pages
│   └── lua/moswaf/
│       ├── access.lua      allow / block / challenge decision
│       ├── rules.lua       signature engine + built-in ruleset
│       ├── ratelimit.lua   two-window counters
│       ├── ipset.lua       allow/blocklists + temporary bans
│       ├── challenge.lua   proof-of-work JS challenge
│       ├── config.lua      config sync from Redis
│       └── log.lua         event and stats shipping
├── control/                Go - API, dashboard, sync
│   ├── cmd/moswafd/
│   └── internal/{api,store,engine,config,web}
└── web/                    Vue 3 + Vite - dashboard UI
```

## Documentation

- [REST API reference](docs/API.md) — every control-plane endpoint with `curl` examples.

## Current limitations

Worth knowing before putting this in front of production traffic:

- No multi-node clustering — each install is an independent machine.
- No TLS fingerprinting (JA3/JA4) and no machine learning; detection is
  signature- and rate-based.
- No two-factor authentication for the dashboard.
- No Telegram/email alerting when an attack starts.

## License

MIT — see [LICENSE](LICENSE).
