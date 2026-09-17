-- moswaf.api - endpoint noi bo cua data plane (cong 8081, khong publish ra ngoai)
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

-- Dinh dang Prometheus, tien cam vao he thong giam sat san co
function _M.metrics()
    local stats = ngx.shared.moswaf_stats
    local cnt   = ngx.shared.moswaf_cnt
    local minute = math.floor(ngx.time() / 60) * 60

    local out = {
        "# HELP moswaf_config_version Phien ban cau hinh dang chay",
        "# TYPE moswaf_config_version gauge",
        "moswaf_config_version " .. config.version(),
        "# HELP moswaf_requests_total Request trong phut hien tai",
        "# TYPE moswaf_requests_total gauge",
        "moswaf_requests_total " .. (stats:get("t:" .. minute) or 0),
        "# HELP moswaf_blocked_total Request bi chan trong phut hien tai",
        "# TYPE moswaf_blocked_total gauge",
        "moswaf_blocked_total " .. (stats:get("b:" .. minute) or 0),
        "# HELP moswaf_challenged_total Request bi challenge trong phut hien tai",
        "# TYPE moswaf_challenged_total gauge",
        "moswaf_challenged_total " .. (stats:get("c:" .. minute) or 0),
        "# HELP moswaf_rules_active So rule dang bat",
        "# TYPE moswaf_rules_active gauge",
        "moswaf_rules_active " .. rules.count(),
        "# HELP moswaf_banned_ips So IP dang bi ban tam thoi",
        "# TYPE moswaf_banned_ips gauge",
        "moswaf_banned_ips " .. ipset.banned_count(),
        "# HELP moswaf_event_queue So su kien cho day di trong worker nay",
        "# TYPE moswaf_event_queue gauge",
        "moswaf_event_queue " .. log.pending(),
        "# HELP moswaf_counter_free_bytes Bo nho trong cua shared dict bo dem",
        "# TYPE moswaf_counter_free_bytes gauge",
        "moswaf_counter_free_bytes " .. (cnt:free_space() or 0),
        "",
    }

    ngx.status = 200
    ngx.header["Content-Type"] = "text/plain; version=0.0.4; charset=utf-8"
    ngx.print(table.concat(out, "\n"))
    return ngx.exit(200)
end

-- Control plane goi sau khi admin luu thay doi -> nap cau hinh ngay, khong doi timer
function _M.sync()
    local ok = config.sync()
    return json(ok and 200 or 502, { synced = ok, version = config.version() })
end

return _M
