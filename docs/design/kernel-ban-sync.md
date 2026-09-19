# Design: kernel-level ban enforcement (nftables sync)

Status: proposed (tester design + threat model + test plan). Owner to approve
the deployment shape before the fixer implements.

## Problem

Temporary bans live only in the data plane's `moswaf_ban` shared dict. A banned
IP's packets still traverse the kernel, reach nginx, and run the full Lua access
phase on **every request** before the request is refused. Under an L7 flood from
already-banned sources this spends CPU on traffic the WAF has already judged
hostile — the exact "full CPU, can't keep up" symptom seen in production
(979 IPs auto-banned, CPU still saturated).

Dropping banned IPs in the **host kernel** (nftables) stops their packets before
they reach userspace/nginx/Lua. This is now the primary CPU-reduction lever:
the upstream option (Cloudflare) is unavailable — **Cloudflare is blocked in
Russia**, where the production traffic is — so we cannot offload at the edge and
must shed load on the box itself.

Non-goal: this does not change *detection*. The first request from a new bad IP
still reaches Lua (that is where the ban decision is made). The win is on the
*repeat* traffic from an IP already banned: kernel drop instead of N Lua runs.

## Where bans live (current)

- `dataplane/lua/moswaf/ipset.lua`: `ban_ip(ip, seconds, reason)` writes
  `b:<ip>` into `ngx.shared.moswaf_ban` with a TTL; single addresses, v4 or v6.
- `dataplane/lua/moswaf/api.lua`: internal API `/bans` returns
  `[{ip, reason, ttl}]` from `moswaf_ban:get_keys(1000)`; `/unban?ip=` deletes.
  Both require the `X-MosWAF-Token` internal token.
- Postgres knows nothing about temporary bans; they expire on their own.

**Cap hazard:** `/bans` reads `get_keys(1000)`. Production already sits at ~979
bans, so the sync source silently truncates near 1000 — the agent would fail to
drop exactly the IPs present during the worst floods. `get_keys` is also an O(n)
full-dict scan that blocks the worker, so it cannot be polled aggressively.

## Proposed shape

A small **host-level** agent (`moswaf-kbans`) that reconciles the ban set into
two nftables named sets and lets the kernel drop matching packets.

Host-level because nftables is the host kernel's, and the proxy runs in a
network-namespaced container. Two deployment options — owner to pick:

- **A. systemd unit on the host** (Go binary). Cleanest isolation; the container
  keeps no extra capabilities. Cost: install now touches the host, not just
  `docker compose`.
- **B. compose service with `network_mode: host` + `cap_add: [NET_ADMIN]`.**
  Stays inside the compose file. Cost: one container now runs on host net with
  NET_ADMIN — a larger blast radius if that image is ever compromised.

Recommendation: **A** for a security product — do not grant a container host-net
+ NET_ADMIN just to avoid a systemd unit.

### What gets kernel-dropped — graduated escalation (owner decision)

Do **not** kernel-drop an IP the moment it is banned. Kernel-drop only the
**persistent** offenders: an IP that has already been blocked/banned at the Lua
layer **and keeps sending anyway**. Three tiers:

1. **Detected bad → 403 block** (existing). One offence, refused at Lua.
2. **Repeated blocks → temporary ban** in `moswaf_ban` (existing). Still enforced
   at Lua.
3. **Banned but still hammering → kernel drop** (new). While an IP is banned,
   every request from it that still arrives is a "post-ban hit" — the IP is
   ignoring the ban. Count those hits; when the count crosses a threshold `K`
   within the ban window, emit the ban event with a `kernel` flag and only then
   does the agent add it to `ban4/ban6`.

   **The counter must NOT live in `moswaf_ban`.** That dict currently holds
   exactly one key shape (`b:<ip>`, written only at `ipset.lua:30`), and two
   readers depend on that invariant: `ipset.banned_count()` (`ipset.lua:53`) does
   `#ban:get_keys(0)` with **no prefix filter** — a `bh:` key would inflate the
   `/metrics` ban gauge, and `api.lua` bans list does `get_keys(1000)` filtered to
   `^b:` — a mix of `b:`+`bh:` keys makes 800 bans = 1600 keys and truncates the
   list at 1000, order-dependent. (This is precisely the `get_keys(1000)` hazard
   raised — and correctly dismissed — before `bh:` existed; adding the counter to
   `moswaf_ban` would make it real. Don't.) Put the counter in the existing
   `moswaf_cnt` dict (already holds `v:`/`nf:` counters) or a dedicated dict, with
   **TTL = the ban's remaining TTL** so a banned IP that goes quiet does not leave
   a counter alive forever.

Why this shape:
- **Fewer false-positive lockouts.** A legitimate client that trips one rule is
  blocked once and never kernel-dropped; only something that deliberately keeps
  pounding after being refused reaches the kernel set.
- **Targets exactly the CPU-expensive IPs.** The IPs worth a kernel drop are the
  ones generating *volume*; a banned IP that goes quiet costs nothing to leave at
  Lua level. The flood sources self-select into the kernel set.
- **Bounds per-IP Lua cost.** Under a sustained single-source flood, that IP hits
  Lua at most ~`K` times, then graduates to kernel and goes silent — bounded work
  per bad IP instead of unbounded.

`K` and the window are config (sensible default e.g. `K=50` over the ban TTL).
The post-ban hit counter is incremented on the ban-check path that already runs;
it adds one `incr` per already-banned request, no new scan. Note the cost
direction: escalation makes the ban-check path **more** expensive (one `incr` per
post-ban request under flood) *before* the kernel drop makes it free — a bounded
trade that buys permanent silence past `K`.

### Ban state is now two-valued — `/api/bans` contract + unban propagation

Once kernel-drop exists, a banned IP is in one of two states that mean very
different things to an operator:

- **lua-banned** — still runs the full access phase on every request, still costs
  CPU (this is where an IP sits until it crosses the escalation threshold);
- **kernel-dropped** — packets dropped in-kernel, silent, ~free.

The dashboard reads `GET /api/bans` (today a flat list) and unbans via
`DELETE /api/bans/{ip}`. Two requirements so the UI neither misleads nor fails
silently (raised by the UI session, which owns the dashboard):

1. **`/api/bans` must expose the state, and it must reflect the kernel's reality,
   not merely intent** — an *additive* field so the dashboard can show which IPs
   are still eating CPU versus already silenced. Intent and reality diverge: the
   control plane decides to escalate an IP, but the **agent** is what actually
   programs nft, and it can lag, die, or still have the event queued. So a
   two-value `"lua" | "kernel"` is not enough — reporting `"kernel"` before the
   nft element exists lies in the opposite direction (UI shows silenced while the
   IP is still hitting Lua). At least three states:
   - `lua` — banned, enforced at Lua only;
   - `kernel_pending` — escalation crossed / removal requested, but the agent has
     not confirmed the nft change yet;
   - `kernel` — the agent has **confirmed** the element is programmed in nft.

   This requires an **agent → control-plane ack path**: the agent publishes its
   actually-applied set (e.g. a `moswaf:kernel_applied` key it rewrites each
   reconcile) and `/api/bans` joins against it, so `"kernel"` is only ever
   reported for IPs the agent has confirmed. During a flood, or if the agent is
   down, IPs correctly show `kernel_pending` rather than a false `kernel`.
   The firewall project owns the `/api/bans` contract and has committed to keeping
   it stable, so this field (and the ack mechanism) is **agreed between firewall +
   UI before either writes** — not sprung at deploy.
2. **unban must propagate to the kernel** — `DELETE /api/bans/{ip}` on a
   kernel-dropped IP must remove the nft element too (emit an unban tombstone the
   agent applies), not only delete the shared-dict key. Otherwise the UI reports
   "unbanned" while the kernel still drops the IP — a silent failure, the worst
   kind. The DELETE must not report success until the removal is *confirmed
   applied* (not merely enqueued); if it cannot be applied (agent down, nft
   error) the API must **return a failure**, not `200` — telling the operator
   "couldn't remove it" is far better than claiming it was removed while the
   kernel still drops the IP.

### Sync source — prefer push over `get_keys`

Do **not** build the agent on `/bans`/`get_keys(1000)` (truncates at the cap,
O(n) scan). Instead add a dedicated, bounded feed:

- `ban_ip()` also `rpush`es `{ip, ttl, ts}` onto a capped Redis stream/list
  `moswaf:ban_events` (and `unban` pushes a tombstone). The agent consumes the
  stream incrementally — no full-dict scan, no 1000 cap, and it survives agent
  restarts by replaying from its last id.
- Keep a periodic **full resync** (every ~60s) from a new uncapped
  `/bans?limit=0` so a missed event cannot leave a stale kernel set. The full
  resync is the correctness backstop; the stream is the low-latency path.

### Kernel objects

```
table inet moswaf {
  set ban4 { type ipv4_addr; flags timeout; }
  set ban6 { type ipv6_addr; flags timeout; }
  set allow4 { type ipv4_addr; }          # never-drop (management)
  set allow6 { type ipv6_addr; }
  chain input {
    type filter hook input priority -150; policy accept;
    ct state established,related accept;   # never strand a live mgmt session
    ip  saddr @allow4 accept;
    ip6 saddr @allow6 accept;
    ip  saddr @ban4 drop;
    ip6 saddr @ban6 drop;
  }
}
```

Each `ban4/ban6` element is added with `timeout <ttl>` mirroring the ban's
remaining TTL, so the **kernel expires bans on its own** even if the agent dies.
Re-adding on each resync refreshes the timeout. `priority -150` runs before the
default filter chains but the explicit `policy accept` and the leading
established/allow rules mean this table can only ever *drop banned strangers* —
it never becomes a default-deny that could black-hole the host.

## Threat model / safety (the part that must not be wrong)

The failure that matters is **locking the operator out of their own box** or
**letting a poisoned ban entry drop legitimate/infrastructure traffic**. Rules:

1. **Never-drop allowlist is enforced in the agent, before insert** — not only in
   nft. The agent refuses to add to `ban4/ban6` any address that is:
   - the SSH/management IP(s) (from config, required, install fails without it);
     decided for this deployment: `59.153.224.0/20` (the operator's SSH source is
     dynamic across that ISP /20, so the whole prefix is allowlisted; the ~4096
     addresses are exempt from **kernel-drop only** — they are still inspected and
     Lua-banned as normal);
   - loopback `127.0.0.0/8`, `::1`;
   - RFC1918 `10/8 172.16/12 192.168/16`, CGNAT `100.64/10`, link-local
     `169.254/16`, `fe80::/10`, ULA `fc00::/7`;
   - the Docker bridge subnet(s) the stack uses;
   so even a `/bans` response that (through a bug or a forged internal call)
   lists the management IP can never program a drop for it. Defense in depth:
   the same ranges also sit in `allow4/allow6` so nft accepts them first.
2. **ct established,related accept** — an in-flight admin SSH session is never cut
   even if its source somehow enters a ban set mid-connection.
3. **Fail-open, never fail-closed.** If the agent cannot reach Redis / the data
   plane, or nft errors, it logs and leaves the existing set alone; it never
   flips a chain to default-drop. If the agent process dies, kernel timeouts
   drain the sets and traffic returns to Lua-level bans — degraded, not down.
4. **Own table only.** Create/modify only `table inet moswaf`; never flush or
   touch other tables. Install is idempotent (re-run adds nothing).
5. **Bounded set size.** Cap `ban4/ban6` (e.g. 262144 elements) so a runaway
   ban source cannot exhaust kernel memory.
6. **Clean uninstall** removes only `table inet moswaf`.

## Test plan (tester deliverable)

Unit (agent reconcile logic, no root):
- a `/bans` (or event) list maps to the correct add/remove ops, v4 → ban4,
  v6 → ban6, `ttl` → element timeout.
- **allowlist safety:** management IP, loopback, every private/CGNAT/link-local
  range, and the docker subnet are NEVER emitted as a ban add, even when present
  in the input. This is the #1 test — a poisoned ban list must not lock out SSH.
- stream + periodic full-resync converge to the same set; a dropped event is
  repaired by the next full resync; a tombstone removes an element.
- ttl already expired / <= 0 → not added.

Integration (lima VM, real kernel):
- program the table in a throwaway netns; assert `nft list set` contents match
  the input after add/expire/unban.
- a packet from a banned source is dropped; from an allowlisted source (and from
  the management IP even if it is injected into the ban feed) it passes.
- kill the agent mid-run → existing elements still expire on their timeouts; no
  new drops appear; the host stays reachable.
- run install twice → no duplicate rules; a pre-existing unrelated nft ruleset in
  another table is untouched.
- Redis/data-plane unreachable → agent no-ops, existing traffic still served by
  Lua bans (fail-open verified).

Graduated escalation (data-plane side):
- an IP blocked/banned once but that stops is NEVER promoted to the kernel feed
  (no `kernel` event emitted below the threshold) — the false-positive guard.
- a banned IP that keeps hitting emits the `kernel` event exactly once at the
  `K`-th post-ban hit, not before and not repeatedly.
- the post-ban counter resets/expires with the ban window so a later, unrelated
  ban of the same IP starts its count fresh.

Regression to add on the data-plane side:
- the new uncapped `/bans?limit=0` returns all bans (harness that pushes >1000
  bans and asserts none are truncated), and `ban_events` receives one entry per
  `ban_ip`/`unban`.

## Decisions made

- Deployment shape: **A (host systemd unit)** — owner to reconfirm, but do not
  grant a container host-net + NET_ADMIN.
- Management/SSH allowlist: **`59.153.224.0/20`** (see threat model §1).
- Escalation to kernel is **graduated** (see "What gets kernel-dropped"): only
  persistent post-ban offenders, default `K=50` over the ban window.

## Open questions for the fixer

1. Acceptable full-resync interval vs. event latency (default 60s / stream).
2. Do we ever ban CIDRs, or only single IPs? (single → simple sets; CIDR →
   `flags interval` sets and interval-safe allowlist checks.)
3. Exact `K` and post-ban window defaults.
