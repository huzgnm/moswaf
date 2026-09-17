-- moswaf.api - the data plane internal endpoints (port 8081, never published)
local cjson  = require "cjson.safe"
local config = require "moswaf.config"
local rules  = require "moswaf.rules"
local ipset  = require "moswaf.ipset"
local log    = require "moswaf.log"

local _M = {}

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
        "",
    }

    ngx.status = 200
    ngx.header["Content-Type"] = "text/plain; version=0.0.4; charset=utf-8"
    ngx.print(table.concat(out, "\n"))
    return ngx.exit(200)
end

-- The IPs currently under a temporary ban. These are created by the engine when it
-- detects a flood, so they only live in data plane memory and the database knows
-- nothing about them - they have to be read here.
function _M.bans()
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

-- Called by the control plane after an admin saves, so the config loads now
-- instead of waiting for the poll timer
function _M.sync()
    local ok = config.sync()
    return json(ok and 200 or 502, { synced = ok, version = config.version() })
end

return _M
