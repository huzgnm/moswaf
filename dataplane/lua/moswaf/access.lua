-- moswaf.access - the access phase: allow / monitor / block / ban
--
-- Checks are ordered by cost: whatever is cheap and rejects the most requests
-- runs first, and signature scanning (the most CPU hungry step) runs last.
--
--   1. the challenge verify endpoint
--   2. the site protection mode (off / monitor / protect)
--   3. IP allowlist
--   4. temporary bans and the blocklist
--   5. per-IP rate limiting (flood protection)
--   6. under-attack mode -> force a JS challenge
--   7. signature scanning over URI / query / body / headers
--
-- The outcome is written to ngx.ctx.moswaf for the log phase to pick up.

local config    = require "moswaf.config"
local util      = require "moswaf.util"
local ipset     = require "moswaf.ipset"
local ratelimit = require "moswaf.ratelimit"
local rules     = require "moswaf.rules"
local challenge = require "moswaf.challenge"

local _M = {}

local BODY_METHODS = { POST = true, PUT = true, PATCH = true, DELETE = true }

-- Attackers URL-encode payloads to slip past the rules: "UNION ALL SELECT" is sent
-- as "UNION%20ALL%20SELECT", "<script>" as "%3Cscript%3E", and the more careful ones
-- double-encode ("%2520"). So normalise before scanning: join the raw value with its
-- decoded forms, and a rule matches at whichever layer the payload hides in.
local function expand(s)
    if not s or s == "" then return "" end
    local out, prev = s, s
    for _ = 1, 2 do
        local ok, decoded = pcall(ngx.unescape_uri, prev)
        if not ok or decoded == prev then break end
        out = out .. "\n" .. decoded
        prev = decoded
    end
    return out
end

-- --------------------------------------------------------------- responses

local function render_block(ctx, status)
    local html = config.block_html
        :gsub("{{RAY}}", ctx.ray or "-")
        :gsub("{{IP}}", ctx.ip or "-")
        :gsub("{{REASON}}", ctx.rule_name or ctx.reason or "-")
        :gsub("{{TIME}}", ngx.localtime())

    ngx.status = status
    ngx.header["Content-Type"]  = "text/html; charset=utf-8"
    ngx.header["Cache-Control"] = "no-store"
    ngx.header["X-MosWAF-Ray"]  = ctx.ray
    ngx.print(html)
    return ngx.exit(status)
end

-- Record a block decision. In monitor mode it is only logged and the request passes.
local function block(ctx, mode, reason, rule, status)
    ctx.reason   = reason
    ctx.severity = rule and rule.severity or ctx.severity or "medium"
    if rule then
        ctx.rule_id   = rule.id
        ctx.rule_name = rule.name
    end

    if mode == "monitor" then
        ctx.action = "monitor"
        return nil                      -- cho request di tiep
    end

    ctx.action = "deny"
    ctx.status = status or tonumber(config.get().settings.block_status) or 403
    return render_block(ctx, ctx.status)
end

local function do_challenge(ctx, mode, reason)
    ctx.reason = reason
    if mode == "monitor" then
        ctx.action = "monitor"
        return nil
    end
    ctx.action = "challenge"
    ctx.status = 503
    return challenge.serve(ctx.ip, ctx.ua, reason)
end

-- --------------------------------------------------------------- main

function _M.run()
    local conf = config.get()
    local st   = conf.settings

    local site_id = ngx.var.moswaf_site or ""
    local site    = conf.sites[site_id] or {}

    local ip  = util.client_ip(st)
    local ua  = ngx.var.http_user_agent or ""
    local uri = ngx.var.uri or "/"

    local ctx = {
        start   = ngx.now(),
        ray     = (ngx.var.request_id or ""):sub(1, 16),
        ip      = ip,
        ua      = ua,
        site    = site_id,
        action  = "allow",
    }
    ngx.ctx.moswaf = ctx

    -- 1. a visitor coming back from the challenge
    if uri == challenge.verify_uri then
        ctx.action = "verify"
        return challenge.handle_verify(ip, ua)
    end

    -- 2. protection mode
    local mode = site.mode or st.default_mode or "protect"
    if mode == "off" then
        ctx.action = "bypass"
        return
    end

    -- 3. allowlist: skip every remaining check
    if ipset.is_whitelisted(ip) then
        ctx.action = "allow_white"
        return
    end

    -- 4. currently banned, or on the blocklist
    local banned, breason = ipset.is_banned(ip)
    if banned then
        return block(ctx, mode, "banned:" .. tostring(breason), nil, 403)
    end
    if ipset.is_blacklisted(ip) then
        return block(ctx, mode, "blacklist", nil, 403)
    end

    -- 5. rate limiting
    -- A site value of 0 means "use the global limit". In Lua the number 0 is still
    -- truthy, so `tonumber(site.rate_rps) or global` would evaluate to 0 and switch
    -- rate limiting off entirely.
    local rps = tonumber(site.rate_rps) or 0
    if rps <= 0 then rps = tonumber(st.global_rate_rps) or 60 end

    local burst = tonumber(site.rate_burst) or 0
    if burst <= 0 then burst = tonumber(st.global_rate_burst) or 120 end
    local hit, rreason, c1, c10 = ratelimit.check(site_id ~= "" and site_id or "g", ip, rps, burst)
    ctx.rps = c1
    if hit then
        local violations = ratelimit.mark_violation(ip)
        -- repeat offender -> ban temporarily instead of rejecting request by request
        if violations >= 3 then
            ipset.ban_ip(ip, st.ban_seconds, rreason)
            return block(ctx, mode, "flood:" .. rreason .. ":" .. c1 .. "/" .. c10, nil, 429)
        end
        -- first offence: prefer a challenge so real people are not blocked by mistake
        if site.challenge ~= "off" then
            return do_challenge(ctx, mode, "flood:" .. rreason)
        end
        return block(ctx, mode, "flood:" .. rreason, nil, 429)
    end

    -- 6. under-attack mode, or a site that always challenges
    if st.under_attack or site.challenge == "always" then
        if not challenge.has_valid_cookie(ip, ua) then
            return do_challenge(ctx, mode, st.under_attack and "under_attack" or "site_challenge")
        end
    end

    -- 7. signature scanning
    local headers = ngx.req.get_headers(64)
    local scan = {
        -- nginx has already decoded and normalised $uri while $request_uri keeps the
        -- raw form; both are needed to catch ../ as well as encoding tricks
        uri     = expand((ngx.var.request_uri or uri) .. "\n" .. uri),
        args    = expand(ngx.var.args or ""),
        ua      = ua,
        cookie  = expand(ngx.var.http_cookie or ""),
        referer = expand(ngx.var.http_referer or ""),
        headers = headers,
    }

    if st.scan_body and BODY_METHODS[ngx.var.request_method] then
        local len = tonumber(ngx.var.http_content_length) or 0
        local max = tonumber(st.max_body_scan) or 65536
        if len > 0 and len <= max then
            ngx.req.read_body()
            scan.body = expand(ngx.req.get_body_data() or "")
        end
    end

    local matched = rules.scan(scan, site)
    if matched then
        local action = matched.action or "deny"
        if action == "log" then
            ctx.action    = "log"
            ctx.rule_id   = matched.id
            ctx.rule_name = matched.name
            ctx.severity  = matched.severity
            ctx.reason    = "rule"
            return
        elseif action == "challenge" then
            if challenge.has_valid_cookie(ip, ua) then return end
            ctx.rule_id   = matched.id
            ctx.rule_name = matched.name
            ctx.severity  = matched.severity
            return do_challenge(ctx, mode, "rule:" .. matched.id)
        elseif action == "ban" then
            ipset.ban_ip(ip, st.ban_seconds, "rule:" .. matched.id)
            return block(ctx, mode, "rule", matched, 403)
        else
            return block(ctx, mode, "rule", matched, nil)
        end
    end
end

return _M
