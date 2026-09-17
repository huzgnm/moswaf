# MosWAF — Test report #1

**Date:** 2026-09-17
**Scope:** data plane (`dataplane/lua/`, `dataplane/conf/`), control plane (`control/`), deployment config (`install.sh`, `docker-compose.yml`, `.env.example`)
**Method:** source review + runnable reproduction tests (Go and Lua), then black-box re-verification against a running stack.
**Baseline commit:** `cd6ce7d` · **Fixes verified through:** PRs #4, #5, #7, #8, #10, #12

---

## Summary

The data-plane / control-plane split is sound, the JWT layer is clean, and much of
the code shows careful thought (the comment explaining the `tonumber(x) or default`
trap when the value is `0`, the per-part `pcall` in `init_worker`, the write-temp-then-rename
for site files). The problems were not carelessness; they lived in the **seams
between the two layers**: rule order is decided by SQL but "first match wins" lives
in Lua; regexes are validated with RE2 but executed with PCRE; sites are validated
in Go but rendered to nginx in Go with nothing escaped.

The headline result of round 1: **a single `User-Agent` header disabled the entire
signature engine.**

The first four rounds raised **18 findings, all fixed and re-verified** (the WAF core,
the control plane, deployment, and the deep-evasion sweep in round 4). Round 5 then
reviewed a newer feature — **automatic certificates over ACME HTTP-01** — and opened
**5 more (1 medium, 4 low)**, all on that feature. The medium is the notable one: the
ACME challenge path is meant to sit outside every WAF check so a site can always renew,
but it does not — `access_by_lua` is inherited into its location, so under-attack mode
(and a ban or rate-limit) blocks the CA and breaks renewal. Details in the round-5
section.

| # | Severity | Finding | Reproduction | Status |
|---|----------|---------|--------------|--------|
| 1 | **Critical** | `log` rule shadows a `deny` rule → WAF bypass with one header | `TestLoggingRuleDoesNotShadowBlockingRule` | **Fixed ✓** |
| 2 | **Critical** | `make up` ships with `changeme` secrets, nothing refuses to boot | — | **Fixed ✓** |
| 3 | **High** | `Site.Name` unvalidated → nginx directive injection (workers run `root`) | `TestRenderSiteDoesNotEmitInjectedDirectives` | **Fixed ✓** |
| 4 | **High** | Headers and User-Agent invisible to every `any` rule | `TestAttackInHeaderIsDetected` | **Fixed ✓** |
| 5 | **High** | Body > 64 KB or `Transfer-Encoding: chunked` not scanned | — | **Fixed ✓** |
| 6a | **High** | `real_ip_header` without `trusted_proxies` → IP spoofing | `TestValidateSettingsRequiresTrustedProxiesWithRealIPHeader` | **Fixed ✓** |
| 6b | **High** | `X-Forwarded-For` read left-to-right → spoofing even when configured correctly | `client_ip: XFF is read right to left` (Lua) | **Fixed ✓ (PR #5)** |
| 7 | Medium | Rate limit fails open when the shared dict is full | `ratelimit.lua` #7 checks | **Fixed ✓ (PR #10)** |
| 8 | Medium | Fixed counting windows → up to 2× the configured limit at the boundary | `ratelimit.lua` #8 checks | **Fixed ✓ (PR #10)** |
| 9 | Medium | Rules validated with RE2, run with PCRE; PCRE errors were swallowed | `TestValidateRuleAcceptsPCRELookahead` | **Fixed ✓** |
| 10 | Medium | `/__moswaf/verify` runs before every ban / rate-limit check | source (access.lua ordering) | **Fixed ✓ (PR #8)** |
| 11 | Medium | `loginGuard` leaked memory forever | `TestLoginGuardReleasesInertEntries` | **Fixed ✓** |
| 12 | Medium | `/unban?ip=*` on port 8081 is unauthenticated, allows all of RFC1918 | black-box token checks | **Fixed ✓ (PR #12)** |
| 13 | Low | Open redirect via `/\` in the verify `r` parameter | `is_local_path` checks (Lua) | **Fixed ✓ (PR #8)** |
| 14 | Low | Changing the password does not revoke existing JWTs | `auth_test.go` | **Fixed ✓ (PR #8)** |
| 15 | Medium | URL-encoding ≥ 3 layers bypasses the engine (`expand` decodes only 2) | `verify.sh` triple-encode row | **Fixed ✓ (PR #5)** |
| 16 | Low | Zero-padded IPv4 octets evade a ban (`01.2.3.4` ≠ `1.2.3.4` as a key) | `normalize_ip: zero-padded octets collapse` (Lua) | **Fixed ✓ (PR #5)** |
| 17 | Low | `SeedRules` freezes rule name/category on first run (`ON CONFLICT DO NOTHING`) | — | **Fixed ✓ (PR #5)** |
| 18 | Low | `normalize_ip` does not canonicalise IPv6 → `::1` ≠ `0:0:0:0:0:0:0:1` as a key | `normalize_ip: IPv6 forms collapse` (Lua) | **Fixed ✓ (PR #7)** |
| 19 | Medium | ACME challenge path is not exempt from the WAF → under-attack / ban / rate-limit blocks the CA and breaks renewal | black-box (ban + under-attack) | **Open (round 5)** |
| 20 | Low | `cert_expires_at` is settable via `PUT /api/sites` → renewal can be frozen | — | **Open (round 5)** |
| 21 | Low | Wildcard domain accepted for HTTP-01 ACME → renewal fails forever | `TestValidateSiteACMERejectsWildcard` (skipped) | **Open (round 5)** |
| 22 | Low | Trailing-dot IP `1.2.3.4.` slips the IP guard for ACME | `TestValidateSiteACMERejectsTrailingDotIP` (skipped) | **Open (round 5)** |
| 23 | Low | Manual `POST /api/sites/{id}/certificate` has no rate-limit / ignores backoff → can burn CA limits | — | **Open (round 5)** |

---

## Round 2 — verification of the fixes (against the running stack)

Re-run any time with `.local/verify.sh http://127.0.0.1:8088` (script is gitignored;
it is reproduced in the appendix).

### The 8 fixes hold

```
=== FIX #1: signature-engine bypass via User-Agent ===
  default UA + SQLi                          403  (want 403)
  -A python-requests + SQLi                  403  (want 403)
  -A Go-http-client + SQLi                   403  (want 403)
  -A okhttp + SQLi                           403  (want 403)
  -A axios + XSS                             403  (want 403)
  GET /pma/.env                              403  (want 403)
=== FIX #4: header and User-Agent are now scanned ===
  SQLi in X-Api-Version                      403  (want 403)
  SQLi in User-Agent                         403  (want 403)
=== evasion variants ===
  SQLi with /**/ comments                    403  (want 403)
  SQLi in Cookie                             403  (want 403)
  SQLi in JSON body                          403  (want 403)
  SQLi in chunked body                       403  (want 403)   ← FIX #5
=== clean traffic must still pass ===
  GET /                                      200  (not 403)
  normal browser UA                          404  (not 403)   ← origin 404, WAF let it through
  POST clean JSON                            501  (not 403)
```

The critical bypass is closed: announcing yourself as `python-requests` no longer
buys an exemption, and payloads in headers, the User-Agent, cookies and chunked
bodies are all caught. No false positives on clean traffic.

I also confirmed the control-plane fixes at the source level: the server now
refuses to boot on a placeholder secret (#2), `ValidateSettings` rejects a real-IP
header with no trusted proxies (#6a), `ValidateRule` accepts PCRE-only syntax and
rejects nested quantifiers (#9), and `loginGuard` reaps inert records and has a hard
ceiling (#11). The full Go suite and `lua-check` pass.

### On the `loginGuard` test I wrote

The peer correctly reworked `TestLoginGuardReleasesInertEntries`. My original
version demanded the map be empty immediately after a single failure, which cannot
hold at the same time as `TestLoginGuardLocksOutAfterRepeatedFailures` — the lockout
needs the `fails` counter to survive from attempt 1 through 5. The leak was real;
the right fix is "keep recent records, reap after the retention window, cap the
total," which is what landed. Agreed, no objection.

---

## Round 2 — three findings raised, and now fixed (PR #5)

All three were confirmed against the running stack, fixed by the peer session, and
re-verified. The `dataplane/test/run.lua` checks that pinned them are now green.

### 6b. `X-Forwarded-For` was read left-to-right — HIGH (the unfixed half of #6) — FIXED

`util.client_ip` took the **leftmost** valid entry. A CDN *appends* to
`X-Forwarded-For`, so with a real client behind Cloudflare the header is
`<whatever the client sent>, <real client IP>`; the leftmost entry is attacker text.
Bans, the blocklist and every rate-limit counter keyed on it, so all three were
defeated per request — **even when `trusted_proxies` was configured correctly.** Fix
6a (PR #4) only closed the empty-trusted-list half.

The fix reads the header right to left, skips hops that are in `trusted_proxies`, and
returns the first address that is not one of them (falling back to the leftmost when
every hop is trusted). Verified:

```
X-Forwarded-For: 1.2.3.4, 198.51.100.7   (trusted_proxies = 203.0.113.0/24, peer 203.0.113.10)
  -> client_ip = 198.51.100.7   (was 1.2.3.4)
```

Pinned by `client_ip: XFF is read right to left, skipping trusted hops` and the
trusted-proxy-chain case in `run.lua`.

### 15. URL-encoding of 3+ layers bypassed the engine — MEDIUM (new) — FIXED

`access.lua:expand` decoded exactly two layers (`for _ = 1, 2`), so a payload encoded
one layer deeper was never normalised to the form the rules match. Measured before
the fix, same `UNION ALL SELECT` payload, varying only encoding depth: 0/1/2 layers
→ 403, **3/4 layers → 404 (reached the origin)**.

The fix decodes in a loop until the string stops changing, capped at 5 iterations.
After it, 1–4 layers all return 403, and `scripts/attack-sim.sh` gained double- and
triple-encoded cases (now 19/19).

### 16. Zero-padded IPv4 octets evaded a ban — LOW (new) — FIXED

`ipv4_to_int("01.2.3.4")` parses to the same integer as `1.2.3.4`, so both match the
same CIDR — but `ipset.ban_ip` and the rate-limit counters keyed on the **raw
string**, so `01.2.3.4`, `001.2.3.4`, … were distinct keys resolving to one host. A
banned attacker got a fresh identity by padding an octet.

The fix adds `util.normalize_ip` (canonical dotted-quad, strips a port and IPv6
brackets), applied before the value becomes a key. Verified:
`010.000.000.007 -> 10.0.0.7`. Pinned by the `normalize_ip:` checks in `run.lua`.

### 17. `SeedRules` froze rule names on first run — LOW (found by the peer) — FIXED

Surfaced while verifying #6b: the attack log still showed a Vietnamese rule name
("XSS - thẻ nguy hiểm") after the whole project had been translated. `SeedRules` used
`ON CONFLICT (id) DO NOTHING`, so `name` and `category` were frozen at first boot and
no upgrade ever refreshed them. The fix refreshes `name`/`category` from code on every
start while leaving `pattern`, `action`, `severity` and `enabled` under the admin's
control. Not one I raised — recording it so the round is complete.

---

## Round 2 — the gap it opened, since fixed (PR #7)

### 18. `normalize_ip` did not canonicalise IPv6 — LOW — FIXED

`normalize_ip` returned an IPv6 address verbatim, so `::1` and `0:0:0:0:0:0:0:1` were
the same host but two different ban/counter keys — the #16 many-identities problem,
one layer down, for IPv6 clients. I flagged it as a **soft** (non-failing) check in
`run.lua` so it would not be lost. PR #7 rewrites IPv6 into the single RFC 5952 form
(lowercase, leading zeros dropped, the longest zero run compressed to `::`, zone
index removed, an IPv4-mapped tail folded to hex, and a syntactically invalid address
rejected rather than passed through). The soft check was promoted to a hard check and
8 more cases added; the harness is 57/57.

---

## Round 3 — three more fixed (PR #8), two measured then fixed (PR #10)

### Verified fixed

- **#10 — `/__moswaf/verify` ordering.** The verify handler now sits *after* the
  allowlist, ban and blocklist checks but *before* the rate limiter
  (`access.lua` lines 126/132/136 → 150). A banned or blocklisted IP can no longer
  reach the handler and spend the server's CPU on HMAC + SHA-256, while a client that
  was merely rate-limited can still solve its challenge — putting verify after the
  rate limiter instead would trap such a client in a loop where it is challenged for
  exceeding the limit yet can never call the endpoint that clears it. The ordering
  chosen is the correct one.
- **#13 — open redirect.** The check moved into `util.is_local_path`, which now
  rejects a second leading `/`, a leading `\`, control characters and any string
  carrying a scheme. Pinned by 9 cases in `run.lua` (`//evil`, `/\evil`,
  `https://evil`, `/redir?u=https://evil`, a CRLF case, empty, `nil`, …).
- **#14 — JWT after a password change.** Tokens now carry `iat`, and `requireAuth`
  compares it against `users.updated_at`, so a token minted before the last password
  change is rejected. Costs one indexed query per authenticated API request — an
  admin-plane path, not the data plane, so acceptable. Covered in `auth_test.go`.

### Measured, then fixed — #7 and #8

Both were first raised as *possible* trade-offs. Round 3 pinned each with a
**deterministic** test in `dataplane/test/ratelimit.lua` — the shared dict and the
clock are stubbed, so the effects are shown exactly and repeatably rather than fished
out of noisy HTTP timing. On the evidence, one turned out to be a plain bug and the
other a small trade-off, and PR #10 fixed both.

**#8 — fixed counting windows let ~2× the rate through at a boundary.** The
per-second bucket was keyed on `floor(ngx.now())`, so it reset on the wall-clock
second. Firing `rps` requests at `t = 5.90` and `rps` more at `t = 6.00` put each half
in a different bucket; neither exceeded `rps`, so nothing was blocked even though
`2 × rps` arrived inside ~100 ms. The 10-second backstop had the same flaw one order
of magnitude up (`floor(now / 10)`).

> **Correction.** Round 3 first flagged this as a decision because a sliding window
> "would shift the dashboard numbers." That premise was wrong: the rate-limit counters
> live in `ngx.shared.moswaf_cnt`, while the dashboard figures live in a *separate*
> dict, `ngx.shared.moswaf_stats`, written by `log.lua`. Changing how the limiter
> counts touches neither. With no metric cost, #8 was just a bug — thanks to the peer
> for checking the assumption that was holding it up.

PR #10 makes both windows *sliding*: each carries the weighted tail of the previous
bucket, `estimate = current + previous * (1 − elapsed_fraction)`, so the count decays
smoothly instead of dropping to zero at a boundary. Verified on the stack — 120
requests around a second boundary at `rps = 60`: the 60 before pass, and after the
boundary 53 × `403` / 2 × `503` / 1 × `429` / 4 × `200`, where before all 120 passed.
The `ratelimit.lua` checks now assert the fixed behaviour (8/8).

**#7 — the limiter failed open when the shared dict was full.** `bump()` returned `0`
when `cnt:incr` returned `nil`, and a full `moswaf_cnt` is exactly what a flood from
many IPs produces (one key per IP per second). The test filled the dict and sent 1000
requests over an `rps = 10` limit: **0 were blocked** — the protection turned itself
off under precisely the load it exists to stop.

PR #10 makes `bump` run `flush_expired` once and retry; if it still fails it returns
`nil`, and `check` reports `DICT_FULL`. `access.lua` turns that into a **challenge**
for everyone (`access.lua:170`) and deliberately does **not** escalate to a ban, since
the count a ban would rest on is meaningless in that state. Fail-closed would have
blocked real users; challenging instead lets a real browser through silently while a
flood cannot. The test asserts the degraded path reports `DICT_FULL` specifically, so
a future "fix" that returned a normal rate reason (and so could trigger a ban on a
bogus count) would fail the test.

### The one item left open after round 3

- **#12** the port-8081 internal API (`/sync`, `/unban?ip=*`, `/bans`) was guarded by
  source IP only, and the allow list covered all of RFC1918. Closed in round 4 — see
  below.

---

## Round 4 — deep evasion, and the last finding closed

### #12 — internal API now requires a shared token — FIXED (PR #12)

`/sync`, `/bans` and `/unban` now require an `X-MosWAF-Token` header matching
`MOSWAF_INTERNAL_TOKEN`, compared with `util.const_eq` (constant time); the IP allow
list stays as a second layer. `/healthz` and `/metrics` stay open, since the
container healthcheck and metrics scrapers depend on them and neither returns anything
sensitive. Verified against the running stack:

```
/unban  no token    403      /unban  correct token   200
/unban  wrong token 403      /bans   correct token   200
/bans   no token    403      /sync   correct token   200
/sync   no token    403      /healthz 200   /metrics 200
```

Upgrade-safe: if `MOSWAF_INTERNAL_TOKEN` is unset (an install from before the token
existed), the API keeps working on the allow list alone and logs a warning on every
call rather than breaking `unban`. The variable is present in `.env.example` and for
both the `mgmt` and `proxy` services in `docker-compose.yml`. One caveat worth noting:
an install that never runs `install.sh --repair` stays at the old allow-list-only
protection indefinitely, surfaced only by that log line — an accepted trade-off to
avoid breaking `unban` on upgrade.

### Deep evasion — no new findings

Round 4 pushed on the vectors a signature WAF most often misses. All are curl-checked
in `scripts/attack-sim.sh` (the multipart/upgrade/method cases) or by the raw-socket
probe kept alongside the report; none got through.

- **Multipart uploads.** A payload in a form field, a filename, or a file part is
  scanned as raw body and blocked (`403`). A part carrying `Content-Transfer-Encoding:
  base64` does pass the engine, but this is **not** a practical bypass: RFC 7578
  deprecates that header in `multipart/form-data`, so a compliant upstream never
  decodes it and the payload never materialises. Tested, not a concern.
- **WebSocket upgrade.** An attack in the URL or headers of an `Upgrade: websocket`
  request is still scanned and blocked — declaring an upgrade buys no exemption.
  Frames *after* the upgrade are outside any layer-7 HTTP WAF by nature, which is
  expected, not a defect.
- **Unusual methods.** A SQLi body on `PATCH` (and other body methods) is scanned;
  duplicated `Content-Type` headers do not confuse the engine.
- **Request smuggling.** Raw-socket probes for `CL.TE`, an obfuscated
  `Transfer-Encoding :` (space before the colon), and duplicate `Transfer-Encoding`
  headers are each rejected by the frontend with a single `400 Bad Request` — no
  second response, so no desync. A correctly framed chunked body is still scanned
  (`403`). OpenResty/nginx refuses the ambiguous framing before any upstream can
  disagree, so no strict upstream was needed to confirm it.
- **HTTP/2.** Rule scanning runs in `access_by_lua`, which nginx executes after it has
  normalised the request, identically for HTTP/1.1 and HTTP/2; the h2-specific framing
  (HPACK, pseudo-headers) is handled by nginx core, not by MosWAF. Confirmed
  end-to-end against the site's TLS/h2 listener: over HTTP/2, a clean request returns
  `200` while SQLi, XSS and a scanner User-Agent each return `403` — the same verdicts
  as HTTP/1.1.

  ```
  clean h2       -> 200 h2      SQLi h2         -> 403 h2
  XSS h2         -> 403 h2      sqlmap UA h2    -> 403 h2
  ```

---

## Round 5 — automatic certificates (ACME HTTP-01)

Review of the ACME feature: the control plane obtains and renews certificates by
answering `http://<domain>/.well-known/acme-challenge/<token>`, with the token passed
to the data plane through Redis (`moswaf:acme:<token>`, 10-minute TTL).

### 19. The ACME challenge path is not exempt from the WAF — MEDIUM

Both the Lua handler and the config generator state the path is meant to sit *before*
every check ("reachable before every other check in access.lua"; "sits outside every
check on purpose ... a block here would stop the CA from ever reaching the token").
It does not. `renderSite` emits `access_by_lua_block`, `limit_req` and `limit_conn`
at **server** level and the ACME `location` has no override, so nginx inherits them —
`access.run()` executes for the challenge path like any other request.

Confirmed against the running stack:

```
banned IP        -> /.well-known/acme-challenge/<tok>   403 "banned"   (not the 404 acme.serve returns)
flood the path   -> 257×403 + 43×429                    (ban + rate-limit both apply)
token "..%2Fetc" -> 403                                 (the traversal rule fired)
under-attack ON  -> /.well-known/acme-challenge/<tok>   503 "Checking" (the JS challenge page)
```

The good news is what the peer feared — an unauthenticated flood channel bypassing
every check — is **not** the case; the path is fully rate-limited and ban-checked.
The bad news is the opposite of the intent: a certificate authority runs no
JavaScript and carries no cookie, so **under-attack mode returns it the challenge page
instead of the token, and validation fails.** A site under a sustained attack — or one
configured `challenge = "always"`, or one whose validating IP is caught by the rate
limiter — cannot renew, and a `challenge = "always"` site can never obtain its *first*
certificate (a chicken-and-egg). The certificate then expires during the very incident
the WAF is there to weather, adding a TLS outage to the attack.

**Fix:** make the location genuinely exempt — `access_by_lua_block { return }` inside
the ACME `location` (and drop the inherited `limit_req`/`limit_conn` there) — while
keeping a modest dedicated `limit_req` on that location so the flood concern the
comment worries about is still covered. This is a rare case where the safest thing is
to *stop* the WAF running on one specific path.

### 20. `cert_expires_at` can be set through `PUT /api/sites` — LOW

`CertExpiresAt` carries the JSON tag `cert_expires_at`, `handleUpdateSite` overlays
the request onto the stored site (partial update) without pinning it the way it pins
`ID` and `CreatedAt`, and `UpsertSite` writes `cert_expires_at = EXCLUDED`. So an
authenticated `PUT {"cert_expires_at":"3000-01-01T00:00:00Z"}` freezes renewal —
`NeedsCertificate` sees a date far in the future and never renews, so the real
certificate expires silently. It is a system-managed field and should not be accepted
from the client. **Fix:** in `handleUpdateSite`, `in.CertExpiresAt = cur.CertExpiresAt`
before validating. (`acme_last_error` / `acme_last_try` are *not* in `UpsertSite`, so
they are already safe.)

### 21. Wildcard domain accepted for HTTP-01 — LOW

`net.ParseIP("*.example.com")` is nil and the string has a dot, so a wildcard slips
the ACME domain guard. HTTP-01 can never validate a wildcard (only DNS-01 can), so the
order fails forever and retries every hour. **Fix:** reject a leading `*.` when
`acme_enabled`. Pinned by `TestValidateSiteACMERejectsWildcard` (skipped until fixed).

### 22. Trailing-dot IP slips the IP guard — LOW

`net.ParseIP("1.2.3.4.")` returns nil because of the trailing dot, so a dotted-quad
with a trailing dot passes the "no IP address" check while still being an IP to any CA.
More broadly there is no hostname-format validation, so empty labels or over-long names
also reach the CA (which rejects them). **Fix:** strip a trailing dot before the IP
check, or validate the hostname shape. Pinned by `TestValidateSiteACMERejectsTrailingDotIP`
(skipped until fixed).

### 23. Manual certificate endpoint has no rate-limit — LOW

`POST /api/sites/{id}/certificate` is authenticated (good) but drives a real ACME
order synchronously on every call and ignores the `retryAfterFailure` backoff that
guards the renewal sweep. Repeated calls — a frustrated operator on a misconfigured
site, or a script — hammer the CA and can burn its per-account rate limits. **Fix:**
apply the same per-site cooldown to the manual path.

### Checked and defended

- **Redis key escape** (via the challenge token): not possible. `acme.serve` extracts
  the token with `[%w%-_]+$`, and nginx rejects the rest; `%3A` (colon) → 404, `%00` →
  400, `..%2F` → 403, `%0d%0a` → 404. The `moswaf:acme:` prefix cannot be escaped.
- **Email header injection**: `hasControlChar` rejects a CRLF in `acme_email` before it
  reaches the CA's Contact field.
- **Partial update**: `PUT /api/sites` correctly overlays onto the stored site and
  re-validates, so toggling one ACME field does not wipe the rest.
- **The order flow** (`acme.go`) uses `golang.org/x/crypto/acme`, reuses the account
  key across restarts, and backs off an hour after a failure.

### The real ACME order — run against Pebble

The `MOSWAF_ACME_INSECURE` dev flag (added after round 5, gated to a localhost/private
directory) made a live run possible. Driven against a local Pebble test CA, most of
the flow is now verified:

- **The insecure-flag gating works.** With `MOSWAF_ACME_DIRECTORY=https://localhost:14000/dir`
  the control plane trusts Pebble's self-signed directory and completes the TLS
  handshake; pointed at a public directory the flag is ignored, as intended.
- **register → order → accept run.** The control plane registers an account, creates
  an order and accepts the challenge. (Pebble is strict about the contact email — it
  rejects `@*.local` and `@example.com` — and about the identifier suffix; these are
  Pebble's rules, not MosWAF bugs.)
- **The challenge responder is proven.** With a token placed in Redis
  (`moswaf:acme:<token>`), the data plane serves it as `200` with the exact body over
  the *same route the CA uses* — from a container to `192.168.5.2:8088` with the
  site's `Host` — and `404` when the token is absent. This is the MosWAF-owned half of
  HTTP-01, confirmed end to end.
- **The manual-issue cooldown (finding #23) works** — a second `POST` inside five
  minutes returns `429` with the remaining wait.

What the Pebble run did **not** reach: its validation authority would not resolve the
test domain under colima (persistent `NXDOMAIN`, even though the companion
`challtestsrv` answered `dig` from other containers on the same network) — a
container-DNS quirk of the harness, orthogonal to MosWAF — so validation never passed
and the tail of `Issue` did not run live.

That tail has since been split into two testable pieces and unit-tested (the CSR
builder and the chain-encode/store step, with a self-built chain): the full chain is
kept, `notAfter` comes from the leaf, `tls.X509KeyPair` re-loads the pair, and the
requested SANs survive. So the only step now unexercised anywhere is the single live
call to the CA (`CreateOrderCert`) — which, like the Docker Compose deployment path,
can only be closed against a **real domain on a real host**. The safe order there is:
deploy via `install.sh` on a VPS, add a site with a real domain and
`MOSWAF_ACME_DIRECTORY` pointed at Let's Encrypt **staging**, confirm the order, then
switch to production (starting on production risks a week-long lockout after a few
failures).

---

## Checked and PASSING

Not everything was broken — these were verified and are solid:

- **JWT**: rejects `alg=none`, wrong key, and expired tokens; `jwt.WithValidMethods`
  is used correctly.
- **`requireAuth`**: rejects a missing header, the wrong scheme, and a garbage token.
- **Login lockout**: 5 failures → 5-minute lock, 10 → 30 minutes; a success clears
  it. Keyed on `r.RemoteAddr`, and does **not** trust `X-Forwarded-For` — correct.
- **Security headers**: `nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy`, and a
  CSP of `default-src 'self'` are all present.
- **Token transport**: `Authorization: Bearer`, not a cookie → no CSRF surface.
- **Dashboard**: no `v-html` / `innerHTML` sink; the token lives in `localStorage`,
  acceptable given Bearer transport and the CSP.
- **`renderSite`**: applies `limit_conn`, `limit_req`, `access_by_lua_block` and
  `log_by_lua_block` in the right places; output is deterministic; bad site ids are
  rejected.
- **`expand()`** decodes two URL layers as designed; `%2e%2e%2f` is caught (but see
  #15 for three layers).
- **`const_eq`** is a constant-time comparison — correct.
- **`ValidateSettings`** clamps challenge difficulty, TTL, ban time and status code
  to sane bounds.

---

## Not yet covered

- **`install.sh`** beyond the secret-generation path.
- **Load-based attacks** (slowloris, PoW bypass with a headless browser, h2
  rapid-reset / CONTINUATION flood) — need a dedicated load rig.

---

## How to run the tests

```bash
cd control && go test ./...     # control plane (Go)
make lua-test                   # data plane pure-Lua units (needs luajit)
make lua-check                  # Lua syntax
./scripts/attack-sim.sh http://127.0.0.1:8088   # black-box: does it block? (needs a running stack)
```

Reproduction tests:

- `control/internal/store/rules_scan_test.go` — faithful model of the data plane's
  rule-evaluation order (including `expand()`), for hunting bypasses without booting
  the stack.
- `control/internal/store/validate_test.go` — site, settings and rule validation.
- `control/internal/engine/nginxconf_test.go` — the rendered nginx output.
- `control/internal/api/auth_test.go` — JWT, `requireAuth`, login throttling.
- `dataplane/test/run.lua` — pure-Lua units for IP parsing, normalisation and
  client-IP resolution (this is where #6b, #16 and #18 are pinned; the repo had no
  Lua tests before). Wired into CI's data-plane job.
- `dataplane/test/ratelimit.lua` — deterministic coverage of #7 (a full shared dict
  degrades to a challenge instead of passing everything) and #8 (a burst across a
  window boundary no longer doubles the rate), with the shared dict and the clock
  stubbed. Also wired into CI.

`scripts/attack-sim.sh` also carries the round-4 vectors — a SQLi in a multipart
field and filename, in a WebSocket-upgrade URL and in a `PATCH` body, plus a clean
multipart control. The request-smuggling probes are raw-socket (curl normalises the
framing away) and live in the report's companion script rather than in `attack-sim.sh`.

When round 1 started the repo had **zero** test files, so `go test ./...` in CI was
green without verifying anything. Every finding above now has a test that goes green
when — and only when — the underlying bug is fixed.

---

## Appendix — `.local/verify.sh`

The black-box script is kept out of git (the `.local/` runtime dir is gitignored).
For reference it issues `curl` probes for each fixed bypass and each evasion variant,
asserting `403` on attacks and *not*-`403` on the clean-traffic controls, against the
stack at `http://127.0.0.1:8088`.
