-- moswaf.log - the log phase: ship attack events back to the control plane
--
-- Never write to the database from Lua, that would block the worker. Instead:
--   * events -> buffered in the worker -> LPUSHed to Redis in batches every second
--   * total/blocked/challenged counters -> per-minute shared dict -> Redis every 10s
-- The control plane drains the queue and writes it into Postgres.

local cjson  = require "cjson.safe"
local util   = require "moswaf.util"
local config = require "moswaf.config"

local stats = ngx.shared.moswaf_stats
local _M    = {}

local QUEUE_KEY   = "moswaf:events"
local QUEUE_MAX   = 200000       -- keeps the queue from growing without bound if the control plane dies
local BUF_MAX     = 2000
local FLUSH_EVERY = 1            -- seconds
local STATS_EVERY = 10           -- seconds

local buf, buf_n = {}, 0
local dropped = 0

local function minute_key(t)
    return math.floor((t or ngx.time()) / 60) * 60
end

-- --------------------------------------------------------------- record

function _M.run()
    local ctx = ngx.ctx.moswaf
    if not ctx then return end

    local action = ctx.action or "allow"
    local minute = minute_key()

    -- counters that feed the chart
    stats:incr("t:" .. minute, 1, 0, 300)
    if action == "deny" then
        stats:incr("b:" .. minute, 1, 0, 300)
    elseif action == "challenge" then
        stats:incr("c:" .. minute, 1, 0, 300)
    elseif action == "monitor" or action == "log" then
        stats:incr("m:" .. minute, 1, 0, 300)
    end

    -- only keep details for requests worth looking at
    local st = config.get().settings
    local interesting = (action ~= "allow" and action ~= "allow_white"
                         and action ~= "bypass" and action ~= "verify")
    if not interesting and not st.log_allowed then return end

    if buf_n >= BUF_MAX then
        dropped = dropped + 1
        return
    end

    buf_n = buf_n + 1
    buf[buf_n] = {
        ts        = ngx.time(),
        ray       = ctx.ray,
        site      = ctx.site,
        ip        = ctx.ip,
        method    = ngx.var.request_method,
        host      = ngx.var.host,
        uri       = util.truncate(ngx.var.request_uri, 1024),
        ua        = util.truncate(ctx.ua, 512),
        referer   = util.truncate(ngx.var.http_referer, 512),
        action    = action,
        reason    = ctx.reason,
        rule_id   = ctx.rule_id,
        rule_name = ctx.rule_name,
        severity  = ctx.severity,
        status    = ctx.status or tonumber(ngx.var.status) or 200,
        rps       = ctx.rps,
        rt        = tonumber(ngx.var.request_time) or 0,
        bytes     = tonumber(ngx.var.bytes_sent) or 0,
    }
end

-- --------------------------------------------------------------- shipping

local function flush_events()
    if buf_n == 0 then return end

    local batch, n = buf, buf_n
    buf, buf_n = {}, 0

    local red, err = util.redis()
    if not red then
        ngx.log(ngx.WARN, "moswaf: lost the redis connection, dropping ", n, " events: ", err)
        return
    end

    red:init_pipeline(n + 1)
    for i = 1, n do
        local encoded = cjson.encode(batch[i])
        if encoded then red:lpush(QUEUE_KEY, encoded) end
    end
    red:ltrim(QUEUE_KEY, 0, QUEUE_MAX - 1)

    local _, perr = red:commit_pipeline()
    util.redis_release(red)

    if perr then
        ngx.log(ngx.WARN, "moswaf: failed to ship events: ", perr)
    elseif dropped > 0 then
        ngx.log(ngx.WARN, "moswaf: dropped ", dropped, " events because the buffer was full")
        dropped = 0
    end
end

local function flush_stats()
    local now = ngx.time()
    local red, err = util.redis()
    if not red then
        ngx.log(ngx.WARN, "moswaf: could not ship statistics: ", err)
        return
    end

    red:init_pipeline()
    -- resend the last 3 minutes so nothing is lost when redis has just restarted
    for back = 0, 2 do
        local m = minute_key(now - back * 60)
        local total = stats:get("t:" .. m) or 0
        if total > 0 then
            red:hset("moswaf:stat:" .. m,
                     "total",     total,
                     "blocked",   stats:get("b:" .. m) or 0,
                     "challenged", stats:get("c:" .. m) or 0,
                     "monitored", stats:get("m:" .. m) or 0)
            red:expire("moswaf:stat:" .. m, 7200)
        end
    end
    local _, perr = red:commit_pipeline()
    util.redis_release(red)
    if perr then ngx.log(ngx.WARN, "moswaf: error shipping statistics: ", perr) end
end

local function every(delay, fn, name)
    local function tick(premature)
        if premature then return end
        local ok, err = pcall(fn)
        if not ok then ngx.log(ngx.ERR, "moswaf: ", name, " failed: ", err) end
        local ok2, err2 = ngx.timer.at(delay, tick)
        if not ok2 then ngx.log(ngx.ERR, "moswaf: could not schedule timer ", name, ": ", err2) end
    end
    local ok, err = ngx.timer.at(delay, tick)
    if not ok then ngx.log(ngx.ERR, "moswaf: could not schedule timer ", name, ": ", err) end
end

function _M.start_flush()
    every(FLUSH_EVERY, flush_events, "flush_events")
    if ngx.worker.id() == 0 then
        every(STATS_EVERY, flush_stats, "flush_stats")
    end
end

function _M.pending()
    return buf_n
end

return _M
