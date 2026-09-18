# Moving from SafeLine to MosWAF on the same machine

This is the runbook for the harder of the two cases: SafeLine and MosWAF share one
host and one IP address. The easier case — a second machine — is in
[.claude/agents/safeline-migration.md](../.claude/agents/safeline-migration.md),
and most of what follows still applies.

## What one host changes

With two machines you move DNS one domain at a time and each move is independently
reversible. With one machine there is no DNS to move: both firewalls answer on the
same address, and only one of them can hold ports 80 and 443. So:

- **Preparation and verification are still per-domain.** Every site is built on
  MosWAF and proven to serve, on spare ports, before anything is switched.
- **The cutover itself is all sites at once.** It is a port swap, and it takes
  seconds, not minutes — but it is one event, so everything has to be verified
  before it happens.
- **Rollback is the same swap in reverse**, which is why SafeLine is stopped, not
  removed, on the day.

Two more consequences worth knowing before you start:

- **ACME cannot run during staging.** An HTTP-01 challenge is answered on port 80,
  which SafeLine still owns. Existing certificates are copied across instead;
  automatic renewal is turned on after the swap.
- **`force_https` stays off during staging.** A redirect from the staged MosWAF
  sends the browser to `https://domain/` — port 443, which is SafeLine. The test
  would pass while proving nothing.

## Port plan

| Port | Staging (SafeLine live) | After cutover |
|------|-------------------------|---------------|
| 80 / 443 | SafeLine | **MosWAF** |
| 8880 / 8443 | **MosWAF**, for verification | free |
| 9443 | SafeLine console | SafeLine console |
| **9445** | **MosWAF dashboard** | MosWAF dashboard |

SafeLine's console also uses 9443, so MosWAF's dashboard is moved off it. Confirm
what is actually listening before choosing:

```bash
ss -lntp | grep -E ':(80|443|9443|8880|8443|9445)\s'
```

---

## Step 1 — get the truth out of SafeLine, and a way back

On the SafeLine host, from a MosWAF checkout:

```bash
sudo bash scripts/safeline-export.sh --full
```

It reads only. It writes `~/moswaf-migration/safeline-<date>/` containing
`nginx-T.conf` (every `server_name` with the `proxy_pass` behind it), the
certificates copied out of the proxy container, a `pg_dump`, and with `--full` a
tarball of `/data/safeline`.

It prints how many server blocks and distinct names it found. **Compare that with
the application count on SafeLine's own dashboard.** If they differ, stop: the
missing ones are the sites nobody remembers until they are down.

Nothing after this point deletes anything on SafeLine.

## Step 2 — install MosWAF beside SafeLine

```bash
sudo bash install.sh --install \
  --http-port 8880 --https-port 8443 \
  --admin-port 9445 --admin-bind 127.0.0.1
```

`--admin-bind 127.0.0.1` keeps the dashboard off the internet; reach it through a
tunnel from your own machine:

```bash
ssh -L 9445:127.0.0.1:9445 root@SERVER
```

The installer prints the admin password. Change it at the first login.

## Step 3 — turn the SafeLine applications into MosWAF sites

```bash
python3 scripts/safeline-import.py \
  ~/moswaf-migration/safeline-*/nginx-T.conf \
  --certs-from ~/moswaf-migration/safeline-*/certs
```

Every site comes out in `mode: monitor` — it logs and blocks nothing. Read the
report before going further; it separates four things that need a decision:

- **upstreams to check by hand** — an upstream block with several servers (MosWAF
  takes the first), or a `127.0.0.1` backend rewritten to `host.docker.internal`
  because MosWAF's proxy runs in a bridge network.
- **sites with no certificate**.
- **sites that redirected to HTTPS** — turn `force_https` on after the swap.
- **sites not migrated** — no `proxy_pass` in the dump. Find the real backend for
  each; do not guess. A site pointed at the wrong backend is worse than a site
  left behind.

Then create them. Log in yourself and export the token — the password does not go
into a command:

```bash
read -rs -p 'MosWAF password: ' PW; echo
export MOSWAF_TOKEN=$(curl -sk https://127.0.0.1:9445/api/auth/login \
  -H 'Content-Type: application/json' \
  -d "$(jq -cn --arg p "$PW" '{username:"admin",password:$p}')" | jq -r .token)
unset PW

python3 scripts/safeline-import.py ~/moswaf-migration/safeline-*/nginx-T.conf \
  --certs-from ~/moswaf-migration/safeline-*/certs --post https://127.0.0.1:9445
```

`~/moswaf-migration/sites.json` holds real domains and private keys. It is written
outside the repository and mode `600` on purpose. Never commit it.

## Step 4 — prove every domain serves, without touching DNS

`--connect-to` sends a genuine request — right `Host`, right SNI — to the staged
ports instead of the live ones:

```bash
curl -ksSI --connect-to example.com:443:127.0.0.1:8443 https://example.com/
```

For each domain check that:

- the status matches what SafeLine returns for the same request;
- the body is the real page, not a MosWAF error page (a WAF page means the
  upstream is wrong, or points at the WAF's own port);
- the certificate covers that exact name:
  `openssl s_client -connect 127.0.0.1:8443 -servername example.com </dev/null 2>/dev/null | openssl x509 -noout -dates -subject -ext subjectAltName`
- `GET /api/stats/overview` counts the requests arriving for that site.

Do not go on until every domain passes. This is the part that replaces the
per-domain DNS move, and it is the only safety net the swap has.

## Step 5 — the swap

Downtime is the time between stopping one proxy and starting the other. Run it as
one block and it is a few seconds:

```bash
cd /opt/moswaf

docker stop safeline-tengine                      # stopped, not removed
sed -i 's/^MOSWAF_HTTP_PORT=.*/MOSWAF_HTTP_PORT=80/;   s/^MOSWAF_HTTPS_PORT=.*/MOSWAF_HTTPS_PORT=443/' .env
docker compose up -d proxy
```

Then, immediately:

```bash
curl -ksSI https://example.com/            # every domain, this time for real
docker compose logs --tail=50 proxy
```

### Rollback

If anything is wrong, go back first and diagnose afterwards:

```bash
cd /opt/moswaf
sed -i 's/^MOSWAF_HTTP_PORT=.*/MOSWAF_HTTP_PORT=8880/; s/^MOSWAF_HTTPS_PORT=.*/MOSWAF_HTTPS_PORT=8443/' .env
docker compose up -d proxy
docker start safeline-tengine
```

SafeLine is untouched and comes back with its own configuration, so this is
seconds as well. Keep it that way until MosWAF has run for a few days.

## Step 6 — after the swap

In this order, one thing at a time:

1. **`force_https`** on the sites the import listed. Now it is MosWAF's own 443.
2. **ACME.** Port 80 belongs to MosWAF, so certificates can renew themselves. Turn
   it on per site, with a contact address, and watch `cert_expires_at` and
   `acme_last_error` on the site row. Let's Encrypt allows five orders a week for
   the same names — do not press **Get cert** in a loop.
3. **`mode: protect`**, site by site, quietest first. Watch the attack log for a
   day between each. Blocked requests that are real visitors show up here and
   nowhere else — check the rule id in the log before disabling anything.
4. **Verify it blocks**: `./scripts/attack-sim.sh https://example.com`. A dashboard
   reading "0 blocked" does not say whether nobody attacked you or the
   configuration is simply wrong.

## Step 7 — removing SafeLine

Only once every site has run under `protect` without a complaint, and the backup
from step 1 is somewhere that is not this machine.

```bash
# Confirm the backup exists and is not empty, elsewhere
ls -lh ~/moswaf-migration/safeline-*/

cd /data/safeline && docker compose down          # containers and network, data kept
```

`down -v` also destroys SafeLine's volumes and is the one command with no way back.
Run it only when you no longer want the option to return — and after the tarball
has been copied off the server.

## What goes wrong, and what it looks like

| Symptom | Usually |
|---|---|
| Site serves a WAF page, never the real site | upstream wrong, or pointing at the WAF's own port |
| Site works on 8443 but not after the swap | a second thing was still bound to 443 — `ss -lntp` |
| Certificate warning | the certificate does not cover that exact name |
| Visitors report being blocked | `protect` with a rule matching normal traffic; find the rule id in the attack log |
| Everything shows one client IP | a CDN in front: set `real_ip_header` **and** `trusted_proxies`, never one alone |
| Search traffic disappears | a country rule; verified crawlers are exempt only when the rule is on the site |
