-- moswaf.log - pha log: day su kien tan cong ve control plane
--
-- Khong ghi thang vao DB tu Lua (se chan worker). Thay vao do:
--   * su kien -> buffer trong worker -> moi giay LPUSH sang Redis theo lo
--   * so dem tong/chan/challenge -> shared dict theo phut -> 10s day sang Redis
-- Control plane doc hang doi va ghi vao Postgres.

local cjson  = require "cjson.safe"
local util   = require "moswaf.util"
local config = require "moswaf.config"

local stats = ngx.shared.moswaf_stats
local _M    = {}

local QUEUE_KEY   = "moswaf:events"
local QUEUE_MAX   = 200000       -- chan hang doi phinh vo han khi control plane chet
local BUF_MAX     = 2000
local FLUSH_EVERY = 1            -- giay
local STATS_EVERY = 10           -- giay

local buf, buf_n = {}, 0
local dropped = 0

local function minute_key(t)
    return math.floor((t or ngx.time()) / 60) * 60
end

-- --------------------------------------------------------------- ghi nhan

function _M.run()
    local ctx = ngx.ctx.moswaf
    if not ctx then return end

    local action = ctx.action or "allow"
    local minute = minute_key()

    -- so dem cho bieu do
    stats:incr("t:" .. minute, 1, 0, 300)
    if action == "deny" then
        stats:incr("b:" .. minute, 1, 0, 300)
    elseif action == "challenge" then
        stats:incr("c:" .. minute, 1, 0, 300)
    elseif action == "monitor" or action == "log" then
        stats:incr("m:" .. minute, 1, 0, 300)
    end

    -- chi luu chi tiet nhung request dang chu y
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

-- --------------------------------------------------------------- day di

local function flush_events()
    if buf_n == 0 then return end

    local batch, n = buf, buf_n
    buf, buf_n = {}, 0

    local red, err = util.redis()
    if not red then
        ngx.log(ngx.WARN, "moswaf: mat ket noi redis, bo ", n, " su kien: ", err)
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
        ngx.log(ngx.WARN, "moswaf: day su kien that bai: ", perr)
    elseif dropped > 0 then
        ngx.log(ngx.WARN, "moswaf: da bo ", dropped, " su kien do buffer day")
        dropped = 0
    end
end

local function flush_stats()
    local now = ngx.time()
    local red, err = util.redis()
    if not red then
        ngx.log(ngx.WARN, "moswaf: khong day duoc thong ke: ", err)
        return
    end

    red:init_pipeline()
    -- day lai 3 phut gan nhat de khong mat so lieu khi redis vua khoi dong lai
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
    if perr then ngx.log(ngx.WARN, "moswaf: loi day thong ke: ", perr) end
end

local function every(delay, fn, name)
    local function tick(premature)
        if premature then return end
        local ok, err = pcall(fn)
        if not ok then ngx.log(ngx.ERR, "moswaf: ", name, " loi: ", err) end
        local ok2, err2 = ngx.timer.at(delay, tick)
        if not ok2 then ngx.log(ngx.ERR, "moswaf: khong dat timer ", name, ": ", err2) end
    end
    local ok, err = ngx.timer.at(delay, tick)
    if not ok then ngx.log(ngx.ERR, "moswaf: khong dat timer ", name, ": ", err) end
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
