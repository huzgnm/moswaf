-- moswaf.access - pha access: quyet dinh cho qua / do / chan / ban
--
-- Thu tu kiem tra duoc sap xep theo chi phi tang dan: cai nao re va loai
-- duoc nhieu request nhat thi chay truoc, quet chu ky (dat CPU nhat) chay cuoi.
--
--   1. endpoint verify cua challenge
--   2. che do bao ve cua site (off / monitor / protect)
--   3. whitelist IP
--   4. ban tam thoi + blacklist
--   5. rate limit theo IP (chong flood)
--   6. che do "dang bi tan cong" -> ep JS challenge
--   7. quet chu ky tren URI / tham so / body / header
--
-- Ket qua ghi vao ngx.ctx.moswaf de pha log dung lai.

local config    = require "moswaf.config"
local util      = require "moswaf.util"
local ipset     = require "moswaf.ipset"
local ratelimit = require "moswaf.ratelimit"
local rules     = require "moswaf.rules"
local challenge = require "moswaf.challenge"

local _M = {}

local BODY_METHODS = { POST = true, PUT = true, PATCH = true, DELETE = true }

-- --------------------------------------------------------------- phan hoi

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

-- Ghi nhan quyet dinh chan. O che do monitor thi chi ghi log, van cho qua.
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

-- --------------------------------------------------------------- chinh

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

    -- 1. khach vua giai xong challenge
    if uri == challenge.verify_uri then
        ctx.action = "verify"
        return challenge.handle_verify(ip, ua)
    end

    -- 2. che do bao ve
    local mode = site.mode or st.default_mode or "protect"
    if mode == "off" then
        ctx.action = "bypass"
        return
    end

    -- 3. whitelist: bo qua moi kiem tra con lai
    if ipset.is_whitelisted(ip) then
        ctx.action = "allow_white"
        return
    end

    -- 4. dang bi ban / nam trong blacklist
    local banned, breason = ipset.is_banned(ip)
    if banned then
        return block(ctx, mode, "banned:" .. tostring(breason), nil, 403)
    end
    if ipset.is_blacklisted(ip) then
        return block(ctx, mode, "blacklist", nil, 403)
    end

    -- 5. rate limit
    local rps   = tonumber(site.rate_rps)   or tonumber(st.global_rate_rps)   or 60
    local burst = tonumber(site.rate_burst) or tonumber(st.global_rate_burst) or 120
    local hit, rreason, c1, c10 = ratelimit.check(site_id ~= "" and site_id or "g", ip, rps, burst)
    ctx.rps = c1
    if hit then
        local violations = ratelimit.mark_violation(ip)
        -- tai pham lien tuc -> ban tam thoi thay vi chan tung request
        if violations >= 3 then
            ipset.ban_ip(ip, st.ban_seconds, rreason)
            return block(ctx, mode, "flood:" .. rreason .. ":" .. c1 .. "/" .. c10, nil, 429)
        end
        -- lan dau: uu tien challenge de khong chan nham nguoi that
        if site.challenge ~= "off" then
            return do_challenge(ctx, mode, "flood:" .. rreason)
        end
        return block(ctx, mode, "flood:" .. rreason, nil, 429)
    end

    -- 6. che do dang bi tan cong / site bat challenge bat buoc
    if st.under_attack or site.challenge == "always" then
        if not challenge.has_valid_cookie(ip, ua) then
            return do_challenge(ctx, mode, st.under_attack and "under_attack" or "site_challenge")
        end
    end

    -- 7. quet chu ky
    local headers = ngx.req.get_headers(64)
    local scan = {
        uri     = uri,
        args    = ngx.var.args or "",
        ua      = ua,
        cookie  = ngx.var.http_cookie or "",
        referer = ngx.var.http_referer or "",
        headers = headers,
    }

    if st.scan_body and BODY_METHODS[ngx.var.request_method] then
        local len = tonumber(ngx.var.http_content_length) or 0
        local max = tonumber(st.max_body_scan) or 65536
        if len > 0 and len <= max then
            ngx.req.read_body()
            scan.body = ngx.req.get_body_data() or ""
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
