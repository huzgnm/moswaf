-- moswaf.api - the data plane internal endpoints (port 8081, never published)
local cjson  = require "cjson.safe"
local config = require "moswaf.config"
local rules  = require "moswaf.rules"
local ipset  = require "moswaf.ipset"
local log    = require "moswaf.log"
local flood  = require "moswaf.flood"

local util     = require "moswaf.util"
local rulesets = require "moswaf.accessrules"

local _M = {}

-- Shared with the control plane through the environment. The IP allow list on this
-- server block is a network boundary, not an identity check: anything sharing the
-- Docker network - another container, a compromised sidecar - sits inside it and
-- could lift bans or force config reloads. The token is the second lock.
local ENV_TOKEN = os.getenv("MOSWAF_INTERNAL_TOKEN")

-- The token can arrive two ways: from the environment, or inside the configuration
-- the control plane publishes. The second path is what protects an install that was
-- upgraded and never had the variable added to its .env - it heals itself on the
-- next config sync, with nothing for an operator to remember.
local function expected_token()
    if ENV_TOKEN and ENV_TOKEN ~= "" then return ENV_TOKEN end
    local published = config.get().internal_token
    if published and published ~= "" then return published end
    return nil
end

-- Endpoints that change state or expose data require the token. /healthz and
-- /metrics stay open: the container healthcheck and any metrics scraper depend on
-- them, and neither returns anything sensitive.
local function authorised()
    local token = expected_token()
    if not token then
        -- No token from either source: neither the environment nor a published
        -- configuration has one, which on a normal install never happens because
        -- install.sh always generates one. It can happen on a bare
        -- `docker compose up`, or on an upgrade whose .env was never given the
        -- variable, and only until the first configuration sync arrives.
        --
        -- That window used to be answered by letting the call through on the
        -- strength of the IP allow list alone. The allow list is a network
        -- boundary, not an identity: anything sharing the Docker network sits
        -- inside it. Refusing is the safer half of the trade - the endpoints
        -- behind this are lifting bans and forcing config reloads, and a few
        -- seconds of "not ready" costs an operator nothing, where a few seconds
        -- of "anyone on this network may lift bans" is the thing being guarded
        -- against.
        ngx.log(ngx.WARN, "moswaf: refusing an internal API call - no token from ",
                "the environment and no configuration synced yet")
        ngx.status = 503
        ngx.header["Content-Type"] = "application/json; charset=utf-8"
        ngx.print('{"error":"the data plane has not received its configuration yet"}')
        ngx.exit(503)
        return false
    end

    local got = ngx.req.get_headers()["X-MosWAF-Token"]
    if type(got) == "table" then got = got[1] end
    if util.const_eq(got or "", token) then return true end

    ngx.log(ngx.WARN, "moswaf: internal API call from ", ngx.var.remote_addr,
            " rejected: token missing or wrong")
    ngx.status = 403
    ngx.header["Content-Type"] = "application/json; charset=utf-8"
    ngx.print('{"error":"forbidden"}')
    ngx.exit(403)
    return false
end

local function json(status, tbl)
    ngx.status = status
    ngx.header["Content-Type"] = "application/json; charset=utf-8"
    ngx.print(cjson.encode(tbl))
    return ngx.exit(status)
end

function _M.healthz()
    return json(200, {
        status  = "ok",
        version = config.version(),
        worker  = ngx.worker.id(),
        uptime  = ngx.now() - ngx.req.start_time(),
    })
end

-- Prometheus format, so it drops straight into an existing monitoring stack
function _M.metrics()
    local stats = ngx.shared.moswaf_stats
    local cnt   = ngx.shared.moswaf_cnt
    local minute = math.floor(ngx.time() / 60) * 60

    local out = {
        "# HELP moswaf_config_version Configuration version currently loaded",
        "# TYPE moswaf_config_version gauge",
        "moswaf_config_version " .. config.version(),
        "# HELP moswaf_requests_total Requests in the current minute",
        "# TYPE moswaf_requests_total gauge",
        "moswaf_requests_total " .. (stats:get("t:" .. minute) or 0),
        "# HELP moswaf_blocked_total Requests blocked in the current minute",
        "# TYPE moswaf_blocked_total gauge",
        "moswaf_blocked_total " .. (stats:get("b:" .. minute) or 0),
        "# HELP moswaf_challenged_total Requests challenged in the current minute",
        "# TYPE moswaf_challenged_total gauge",
        "moswaf_challenged_total " .. (stats:get("c:" .. minute) or 0),
        "# HELP moswaf_rules_active Number of enabled rules",
        "# TYPE moswaf_rules_active gauge",
        "moswaf_rules_active " .. rules.count(),
        "# HELP moswaf_banned_ips Number of IPs under a temporary ban",
        "# TYPE moswaf_banned_ips gauge",
        "moswaf_banned_ips " .. ipset.banned_count(),
        "# HELP moswaf_event_queue Events waiting to be shipped from this worker",
        "# TYPE moswaf_event_queue gauge",
        "moswaf_event_queue " .. log.pending(),
        "# HELP moswaf_counter_free_bytes Free space in the counter shared dict",
        "# TYPE moswaf_counter_free_bytes gauge",
        "moswaf_counter_free_bytes " .. (cnt:free_space() or 0),
    }

    -- Per-site flood state. Worth alerting on: the automatic defence engaging is
    -- the first machine-readable sign that a site is under a distributed flood.
    out[#out + 1] = "# HELP moswaf_flood_engaged 1 while the automatic flood defence is on"
    out[#out + 1] = "# TYPE moswaf_flood_engaged gauge"
    out[#out + 1] = "# HELP moswaf_site_rps Requests per second measured across the site"
    out[#out + 1] = "# TYPE moswaf_site_rps gauge"
    for id in pairs(config.get().sites or {}) do
        local st = flood.state(id)
        local label = '{site="' .. id:gsub('"', '') .. '"}'
        out[#out + 1] = "moswaf_flood_engaged" .. label .. " " .. (st.engaged and 1 or 0)
        out[#out + 1] = "moswaf_site_rps" .. label .. " " .. st.rps
    end
    out[#out + 1] = ""


    ngx.status = 200
    ngx.header["Content-Type"] = "text/plain; version=0.0.4; charset=utf-8"
    ngx.print(table.concat(out, "\n"))
    return ngx.exit(200)
end

-- The IPs currently under a temporary ban. These are created by the engine when it
-- detects a flood, so they only live in data plane memory and the database knows
-- nothing about them - they have to be read here.
function _M.bans()
    if not authorised() then return end
    local ban = ngx.shared.moswaf_ban
    local items = {}
    for _, key in ipairs(ban:get_keys(1000)) do
        local ip = key:match("^b:(.+)$")
        if ip then
            items[#items + 1] = {
                ip     = ip,
                reason = ban:get(key) or "auto",
                ttl    = ban:ttl(key) or 0,
            }
        end
    end
    return json(200, { items = items, total = #items })
end

-- Lift the ban for one IP, or for all of them when ip=*
function _M.unban()
    if not authorised() then return end
    local args = ngx.req.get_uri_args(5)
    local ip = args.ip
    if type(ip) ~= "string" or ip == "" then
        return json(400, { error = "the ip parameter is required" })
    end
    if ip == "*" then
        ngx.shared.moswaf_ban:flush_all()
        ngx.log(ngx.NOTICE, "moswaf: lifted every temporary ban")
        return json(200, { unbanned = "all" })
    end
    ipset.unban(ip)
    ngx.log(ngx.NOTICE, "moswaf: lifted the ban for ", ip)
    return json(200, { unbanned = ip })
end

-- Live flood state per site, for the dashboard. Read-only, and it reads shared
-- memory only - safe to poll.
function _M.flood()
    if not authorised() then return end
    local items = {}
    for id, site in pairs(config.get().sites or {}) do
        local st = flood.state(id)
        st.site = id
        st.name = site.name
        items[#items + 1] = st
    end
    return json(200, { items = items })
end

-- Called by the control plane after an admin saves, so the config loads now
-- instead of waiting for the poll timer
function _M.sync()
    if not authorised() then return end
    local ok = config.sync()
    return json(ok and 200 or 502, { synced = ok, version = config.version() })
end

-- "Which of my rules would this request hit?"
--
-- Answered here, by the engine that will actually decide, rather than by a second
-- implementation in the control plane. A dry-run that disagrees with the running
-- firewall is worse than none at all: the operator would be reading a confident
-- answer about a policy that is not the one in force, and would trust it exactly
-- where trust matters - deciding whether a rule near the top is quietly shadowing
-- everything below it.
--
-- So there is one matcher, and this is it.
function _M.rule_test()
    if not authorised() then return end

    ngx.req.read_body()
    local body = cjson.decode(ngx.req.get_body_data() or "")
    if type(body) ~= "table" then
        return json(400, { error = "expected a JSON object" })
    end

    local conf = config.get()
    local subject = {
        ip      = tostring(body.ip or ""),
        crawler = body.crawler and "test" or nil,
        path    = tostring(body.path or "/"),
        host    = tostring(body.host or ""):lower(),
        ua      = tostring(body.ua or ""),
        method  = tostring(body.method or "GET"):upper(),
    }

    local site = tostring(body.site or "")
    local hit = rulesets.match(conf.access_rules, site, subject, conf.geo_sets)
    if not hit then
        return json(200, { matched = false })
    end
    return json(200, {
        matched = true,
        id      = hit.id,
        name    = hit.name,
        action  = hit.action,
        site    = hit.site,
    })
end

return _M
