-- moswaf.log - the log phase: ship attack events back to the control plane
--
-- Never write to the database from Lua, that would block the worker. Instead:
--   * events -> buffered in the worker -> LPUSHed to Redis in batches every second
--   * total/blocked/challenged counters -> per-minute shared dict -> Redis every 10s
-- The control plane drains the queue and writes it into Postgres.

local cjson  = require "cjson.safe"
local util   = require "moswaf.util"
local config = require "moswaf.config"
local flood  = require "moswaf.flood"

local stats = ngx.shared.moswaf_stats
local _M    = {}

local QUEUE_KEY   = "moswaf:events"
local QUEUE_MAX   = 200000       -- keeps the queue from growing without bound if the control plane dies
local BUF_MAX     = 2000
local FLUSH_EVERY = 1            -- seconds
local STATS_EVERY = 10           -- seconds

local buf, buf_n = {}, 0
local dropped = 0

-- Which machine this data plane is. The per-minute counters are shipped as
-- absolute values with HSET, so two data planes writing the same key would
-- overwrite each other and the control plane would record whichever host was
-- busiest rather than the sum of them - a two-host deployment would under-report
-- its traffic by roughly half, silently. One key per host, summed on the way
-- into the database.
--
-- Resolved once: ngx.var is not available in every phase, and this never changes
-- while the process lives.
local HOST = (os.getenv("HOSTNAME") or "node"):gsub("[^%w%-%._]", "_")

local function minute_key(t)
    return math.floor((t or ngx.time()) / 60) * 60
end

local function hour_key(t)
    return math.floor((t or ngx.time()) / 3600) * 3600
end

-- Addresses and visitors seen since the last flush, held per worker.
--
-- Bounded on purpose. Under a flood from a hundred thousand addresses this table
-- is the one structure that would grow with the attack, so it stops growing: a
-- count that is too low is a bad statistic, a worker that runs out of memory is
-- an outage.
--
-- The cap applies between flushes, not across the hour - the table is emptied
-- every ten seconds once its contents are safely in the sketch, so the ceiling
-- is twenty thousand new addresses per ten seconds per worker rather than per
-- hour. Reaching it takes a flood large enough that an undercounted visitor
-- figure is the least of the problems.
local UNIQUE_MAX = 20000
local uniq_ip, uniq_ip_n = {}, 0
local uniq_visitor, uniq_visitor_n = {}, 0
local uniq_hour = 0

local function remember_unique(ip, ua)
    if not ip or ip == "" then return end

    local hour = hour_key()
    if hour ~= uniq_hour then
        uniq_ip, uniq_ip_n = {}, 0
        uniq_visitor, uniq_visitor_n = {}, 0
        uniq_hour = hour
    end

    if uniq_ip_n < UNIQUE_MAX and not uniq_ip[ip] then
        uniq_ip[ip] = true
        uniq_ip_n = uniq_ip_n + 1
    end

    local visitor = ip .. "\0" .. (ua or "")
    if uniq_visitor_n < UNIQUE_MAX and not uniq_visitor[visitor] then
        uniq_visitor[visitor] = true
        uniq_visitor_n = uniq_visitor_n + 1
    end
end

-- --------------------------------------------------------------- record

function _M.run()
    local ctx = ngx.ctx.moswaf
    if not ctx then return end

    local action = ctx.action or "allow"
    local minute = minute_key()
    local status = ctx.status or tonumber(ngx.var.status) or 200

    -- Tell the flood detector what the origin actually did. A request that the
    -- WAF answered itself - a block page, a challenge - says nothing about the
    -- origin's health, so only requests that were passed through are counted.
    if action == "allow" or action == "allow_white" or action == "bypass"
       or action == "monitor" or action == "log" then
        flood.observe_status(ctx.site or "", status)
    end

    -- counters that feed the chart
    stats:incr("t:" .. minute, 1, 0, 300)
    if action == "deny" then
        stats:incr("b:" .. minute, 1, 0, 300)
    elseif action == "challenge" then
        stats:incr("c:" .. minute, 1, 0, 300)
    elseif action == "monitor" or action == "log" then
        stats:incr("m:" .. minute, 1, 0, 300)
    end

    -- What the visitor was actually served. These are the numbers an operator
    -- reads to tell "we are under attack" from "our application is broken":
    -- a wall of 4xx is usually someone probing, a wall of 5xx is usually us.
    if status >= 400 and status < 500 then
        stats:incr("e4:" .. minute, 1, 0, 300)
        -- 4xx that MosWAF produced rather than the origin. The difference is the
        -- whole question when an error rate jumps: the WAF working, or the site
        -- turning visitors away.
        if action == "deny" then stats:incr("b4:" .. minute, 1, 0, 300) end
    elseif status >= 500 then
        stats:incr("e5:" .. minute, 1, 0, 300)
    end

    -- Page views: pages a person looked at, as opposed to every image, script and
    -- stylesheet the browser then fetched. Counted from the response content type
    -- rather than the path, because a URL tells you nothing reliable about what
    -- came back - a stylesheet request that 404s is served as HTML, and the path
    -- would have called it a stylesheet.
    --
    -- Only a successful response counts. An error page is HTML too, so counting
    -- content type alone made a site whose assets all 404 look like its busiest
    -- day: every missing file became a page view.
    if status < 400 then
        local ctype = ngx.var.sent_http_content_type
        if ctype and ctype:find("text/html", 1, true) then
            stats:incr("pv:" .. minute, 1, 0, 300)
        end
    end

    -- Unique addresses and unique visitors, remembered for the hour.
    --
    -- Deliberately no tracking cookie. A visitor is counted as an address and a
    -- User-Agent together, which is approximate - a household behind one address
    -- can look like one visitor - but a WAF that starts writing a cookie into
    -- every response is making a decision about the site owner's visitors that
    -- the site owner did not ask for. The approximation is the honest trade.
    remember_unique(ctx.ip, ctx.ua)

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
        status    = status,
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

-- Ship the hour's addresses and visitors as HyperLogLogs.
--
-- A plain count per worker cannot be added up - the same visitor is seen by
-- several workers and on several nginx instances - and keeping the raw sets in
-- Postgres to count them later would store every address of every flood. A
-- HyperLogLog merges across workers and hosts, answers "how many distinct" over
-- any span of hours by union, and costs a bounded few kilobytes whether the hour
-- had ten visitors or ten million.
--
-- Hourly rather than per minute on purpose: the dashboard asks about the last
-- hour, day or three days, and a union over 72 keys is cheap where a union over
-- 4320 is not.
local UNIQUE_TTL = 4 * 86400        -- outlives the longest range the dashboard offers

-- PFADD takes its members as arguments, and unpack() on a table of twenty
-- thousand overflows the LuaJIT stack, so the members go in batches.
local UNIQUE_BATCH = 500

local function pfadd_all(red, key, members)
    local n = #members
    if n == 0 then return end
    for i = 1, n, UNIQUE_BATCH do
        local chunk = {}
        for j = i, math.min(i + UNIQUE_BATCH - 1, n) do
            chunk[#chunk + 1] = members[j]
        end
        red:pfadd(key, unpack(chunk))
    end
    red:expire(key, UNIQUE_TTL)
end

-- Runs on every worker, unlike flush_stats.
--
-- The per-minute counters live in a shared dict, so one worker can ship them for
-- all of them and a second worker doing the same would only write the same
-- numbers again. The unique sets are the opposite: each worker accumulates its
-- own, in its own memory, from the requests it happened to handle. Shipping them
-- from worker 0 alone sent one worker's view and silently discarded the rest -
-- which on a multi-worker install is most of the traffic, and was why the
-- unique counts came back as zero.
--
-- Every worker adding to the same sketch is safe precisely because it is a
-- HyperLogLog: adding a member twice changes nothing.
local function flush_uniques()
    local now = ngx.time()
    local hour = hour_key(now)
    if hour ~= uniq_hour then return end       -- the hour rolled over mid-flush; next tick

    local ips = {}
    for ip in pairs(uniq_ip) do ips[#ips + 1] = ip end
    local visitors = {}
    for v in pairs(uniq_visitor) do visitors[#visitors + 1] = v end

    if #ips == 0 and #visitors == 0 then return end

    local red, err = util.redis()
    if not red then
        ngx.log(ngx.WARN, "moswaf: could not ship unique counts: ", err)
        return
    end
    red:init_pipeline()
    pfadd_all(red, "moswaf:uip:" .. hour, ips)
    pfadd_all(red, "moswaf:uv:" .. hour, visitors)
    local _, perr = red:commit_pipeline()
    util.redis_release(red)
    if perr then
        ngx.log(ngx.WARN, "moswaf: error shipping unique counts: ", perr)
        return                                   -- keep the sets; try again next tick
    end

    -- Cleared once sent. Re-sending the same addresses every ten seconds would
    -- move the whole set over the wire again and again for no gain: adding a
    -- member a HyperLogLog already holds changes nothing. Anyone still browsing
    -- is simply added again next tick, which is the same answer for less work.
    uniq_ip, uniq_ip_n = {}, 0
    uniq_visitor, uniq_visitor_n = {}, 0
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
            local key = "moswaf:stat:" .. m .. ":" .. HOST
            red:hset(key,
                     "total",      total,
                     "blocked",    stats:get("b:" .. m) or 0,
                     "challenged", stats:get("c:" .. m) or 0,
                     "monitored",  stats:get("m:" .. m) or 0,
                     "errors_4xx", stats:get("e4:" .. m) or 0,
                     "blocked_4xx", stats:get("b4:" .. m) or 0,
                     "errors_5xx", stats:get("e5:" .. m) or 0,
                     "page_views", stats:get("pv:" .. m) or 0)
            red:expire(key, 7200)
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
    -- Every worker: each holds its own set of addresses seen.
    every(STATS_EVERY, flush_uniques, "flush_uniques")
    -- Worker 0 only: these counters are in a shared dict, so one shipper is enough.
    if ngx.worker.id() == 0 then
        every(STATS_EVERY, flush_stats, "flush_stats")
    end
end

function _M.pending()
    return buf_n
end

return _M
