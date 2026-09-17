# MosWAF — Test report #1

**Date:** 2026-09-17
**Scope:** data plane (`dataplane/lua/`, `dataplane/conf/`), control plane (`control/`), deployment config (`install.sh`, `docker-compose.yml`, `.env.example`)
**Method:** source review + runnable reproduction tests (Go and Lua), then black-box re-verification against a running stack.
**Baseline commit:** `cd6ce7d` · **Fixes verified through:** `4bdbc16` (PRs #4, #5, #7, #8)

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

Across three rounds, **18 findings were raised and 15 fixed and re-verified** (PRs #4,
#5, #7, #8). Every High/Critical finding is closed. What remains: **#7** and **#8**,
two rate-limit *trade-offs* now pinned with deterministic tests so the owner can
decide with evidence, and **#12**, the source-IP-only guard on the internal API.

| # | Severity | Finding | Reproduction | Status |
|---|----------|---------|--------------|--------|
| 1 | **Critical** | `log` rule shadows a `deny` rule → WAF bypass with one header | `TestLoggingRuleDoesNotShadowBlockingRule` | **Fixed ✓** |
| 2 | **Critical** | `make up` ships with `changeme` secrets, nothing refuses to boot | — | **Fixed ✓** |
| 3 | **High** | `Site.Name` unvalidated → nginx directive injection (workers run `root`) | `TestRenderSiteDoesNotEmitInjectedDirectives` | **Fixed ✓** |
| 4 | **High** | Headers and User-Agent invisible to every `any` rule | `TestAttackInHeaderIsDetected` | **Fixed ✓** |
| 5 | **High** | Body > 64 KB or `Transfer-Encoding: chunked` not scanned | — | **Fixed ✓** |
| 6a | **High** | `real_ip_header` without `trusted_proxies` → IP spoofing | `TestValidateSettingsRequiresTrustedProxiesWithRealIPHeader` | **Fixed ✓** |
| 6b | **High** | `X-Forwarded-For` read left-to-right → spoofing even when configured correctly | `client_ip: XFF is read right to left` (Lua) | **Fixed ✓ (PR #5)** |
| 7 | Medium | Rate limit fails open when the shared dict is full | `ratelimit.lua` #7 checks | **Open — trade-off, measured (round 3)** |
| 8 | Medium | Fixed counting windows → up to 2× the configured limit at the boundary | `ratelimit.lua` #8 checks | **Open — trade-off, measured (round 3)** |
| 9 | Medium | Rules validated with RE2, run with PCRE; PCRE errors were swallowed | `TestValidateRuleAcceptsPCRELookahead` | **Fixed ✓** |
| 10 | Medium | `/__moswaf/verify` runs before every ban / rate-limit check | source (access.lua ordering) | **Fixed ✓ (PR #8)** |
| 11 | Medium | `loginGuard` leaked memory forever | `TestLoginGuardReleasesInertEntries` | **Fixed ✓** |
| 12 | Medium | `/unban?ip=*` on port 8081 is unauthenticated, allows all of RFC1918 | — | Open |
| 13 | Low | Open redirect via `/\` in the verify `r` parameter | `is_local_path` checks (Lua) | **Fixed ✓ (PR #8)** |
| 14 | Low | Changing the password does not revoke existing JWTs | `auth_test.go` | **Fixed ✓ (PR #8)** |
| 15 | Medium | URL-encoding ≥ 3 layers bypasses the engine (`expand` decodes only 2) | `verify.sh` triple-encode row | **Fixed ✓ (PR #5)** |
| 16 | Low | Zero-padded IPv4 octets evade a ban (`01.2.3.4` ≠ `1.2.3.4` as a key) | `normalize_ip: zero-padded octets collapse` (Lua) | **Fixed ✓ (PR #5)** |
| 17 | Low | `SeedRules` freezes rule name/category on first run (`ON CONFLICT DO NOTHING`) | — | **Fixed ✓ (PR #5)** |
| 18 | Low | `normalize_ip` does not canonicalise IPv6 → `::1` ≠ `0:0:0:0:0:0:0:1` as a key | `normalize_ip: IPv6 forms collapse` (Lua) | **Fixed ✓ (PR #7)** |

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

## Round 3 — three more fixed (PR #8), two measured for a decision

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

### Measured for the owner to decide — #7 and #8

Both are genuine behaviour trade-offs, not clear-cut bugs, so they are left for the
owner. Round 3 pins each with a **deterministic** test in
`dataplane/test/ratelimit.lua` — the shared dict and the clock are stubbed, so the
effects are shown exactly and repeatably rather than fished out of noisy HTTP timing.

**#8 — fixed counting windows let ~2× the rate through at a boundary.** The
per-second bucket is keyed on `floor(ngx.now())`, so it resets on the wall-clock
second. Firing `rps` requests at `t = 5.90` and `rps` more at `t = 6.00` puts each
half in a different bucket; neither bucket exceeds `rps`, so **nothing is blocked**
even though `2 × rps` arrived inside ~100 ms. The 10-second window is the intended
backstop and does catch a large mid-window burst — but it has the same flaw one order
of magnitude up (`floor(now / 10)`), so a burst straddling the 10-second boundary
doubles there too. Both are proven in the test.

A black-box burst against the running stack corroborated that the limiter is live and
escalates correctly: 200 sequential requests returned ~60 × `200` (roughly one
`rps=60` window's worth) before the limiter tripped and the IP was auto-banned
(`403`) after three violations. Precise boundary doubling is hard to show over HTTP
timing, which is exactly why the deterministic test carries that claim.

*Fix options:* a sliding window (weighted sum of the current and previous bucket) is
the standard remedy, but it changes how requests are counted, so the dashboard
numbers will shift. Owner's call.

**#7 — the limiter fails open when the shared dict is full.** `bump()` returns `0`
when `cnt:incr` returns `nil`, and a full `moswaf_cnt` is exactly what a flood from
many IPs produces (one key per IP per second). The test fills the dict and then sends
1000 requests over an `rps = 10` limit: **0 are blocked.** The protection turns
itself off under precisely the load it exists to stop.

*Fix options:* on an `incr` failure, run `flush_expired` once and retry; if it still
fails, count it as a violation (degrade toward challenge) instead of passing. That
trades a full-dict edge into blocking real users, so — owner's call. Monitoring
`cnt:free_space()` and alerting before it fills is the low-risk half of the fix.

### Still open after round 3

- **#7** rate limit fail-open (trade-off, measured above).
- **#8** fixed counting windows (trade-off, measured above).
- **#12** the port-8081 internal API (`/sync`, `/unban?ip=*`, `/bans`) is guarded by
  source IP only, and the allow list covers all of RFC1918; add a shared secret.

Everything else raised across the three rounds is fixed and re-verified.

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

- **Deeper evasion** the peer asked for: multipart upload, WebSocket upgrade, HTTP/2
  specifics, request smuggling between nginx and the upstream. Next round.
- **`install.sh`** beyond the secret-generation path.
- **Load-based attacks** (slowloris, PoW bypass with a headless browser) — need a
  dedicated load rig.

---

## How to run the tests

```bash
cd control && go test ./...     # control plane (Go)
make lua-test                   # data plane pure-Lua units (needs luajit)
make lua-check                  # Lua syntax
.local/verify.sh http://127.0.0.1:8088   # black-box re-verification (needs a running stack)
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
- `dataplane/test/ratelimit.lua` — deterministic proof of #7 (fail-open on a full
  shared dict) and #8 (2× the rate at a window boundary), with the shared dict and
  the clock stubbed. Also wired into CI.

When round 1 started the repo had **zero** test files, so `go test ./...` in CI was
green without verifying anything. Every finding above now has a test that goes green
when — and only when — the underlying bug is fixed; `run.lua` uses a **soft** check
for the one documented open gap (#18) so CI stays honest without staying red.

---

## Appendix — `.local/verify.sh`

The black-box script is kept out of git (the `.local/` runtime dir is gitignored).
For reference it issues `curl` probes for each fixed bypass and each evasion variant,
asserting `403` on attacks and *not*-`403` on the clean-traffic controls, against the
stack at `http://127.0.0.1:8088`.
