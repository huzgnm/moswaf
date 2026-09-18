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
--   6. under-attack mode, whether switched on by hand or by the flood detector
--   7. signature scanning over URI / query / body / headers
--
-- The outcome is written to ngx.ctx.moswaf for the log phase to pick up.

local config    = require "moswaf.config"
local util      = require "moswaf.util"
local ipset     = require "moswaf.ipset"
local ratelimit = require "moswaf.ratelimit"
local rules     = require "moswaf.rules"
local flood     = require "moswaf.flood"
local crawler   = require "moswaf.crawler"
local challenge = require "moswaf.challenge"
local auth      = require "moswaf.auth"
local geo       = require "moswaf.geo"

local _M = {}

local BODY_METHODS = { POST = true, PUT = true, PATCH = true, DELETE = true }

-- Attackers URL-encode payloads to slip past the rules: "UNION ALL SELECT" is sent
-- as "UNION%20ALL%20SELECT", "<script>" as "%3Cscript%3E", and the more careful ones
-- double-encode ("%2520"). So normalise before scanning: join the raw value with its
-- decoded forms, and a rule matches at whichever layer the payload hides in.
-- MAX_DECODE bounds the work, not the attack: peeling until the string stops
-- changing is what matters. Stopping at two layers meant "%252520" (three layers)
-- reached the origin untouched while one and two layers were blocked.
local MAX_DECODE = 5

local function expand(s)
    if not s or s == "" then return "" end
    local out, prev = s, s
    for _ = 1, MAX_DECODE do
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

-- ------------------------------------------------------- the login endpoint
--
-- The gate's own pages get a reduced access phase rather than none.
--
-- What they keep: the header strip, the blocklist and the temporary bans, and the
-- rate limit declared on the location itself. What they lose: the signature rules.
-- A password is allowed to contain the characters a SQL injection rule looks for -
-- "p'a--ss<script>" is a good password - and a rule that stopped somebody signing
-- in because of one would be the firewall blocking the person it protects, in a
-- way nobody would think to look for.
--
-- Losing the rules is safe here because this location does not reach the upstream.
-- It reads two form fields and hands them to one endpoint that expects exactly
-- those two, so there is no interpreter downstream for a payload to arrive at.
function _M.login()
    auth.strip_trusted_headers()

    local conf = config.get()
    local st   = conf.settings
    local ip   = util.client_ip(st)

    local ctx = {
        start  = ngx.now(),
        ray    = (ngx.var.request_id or ""):sub(1, 16),
        ip     = ip,
        ua     = ngx.var.http_user_agent or "",
        site   = ngx.var.moswaf_site or "",
        action = "login",
    }
    ngx.ctx.moswaf = ctx

    -- Counted like any other request, so that a flood aimed at the login page
    -- shows up in the same figures as a flood aimed anywhere else.
    flood.observe(ctx.site)

    if ipset.is_whitelisted(ip) then return end

    local banned, breason = ipset.is_banned(ip)
    if banned then
        ctx.reason = "banned:" .. tostring(breason)
        ctx.action = "deny"
        ctx.status = 403
        return render_block(ctx, 403)
    end
    if ipset.is_blacklisted(ip) then
        ctx.reason = "blacklist"
        ctx.action = "deny"
        ctx.status = 403
        return render_block(ctx, 403)
    end
end

-- --------------------------------------------------------------- main

function _M.run()
    -- Before anything else, and before any path out of this function.
    --
    -- Every X-MosWAF-* header means "the WAF established this", so one arriving
    -- from outside is somebody establishing it for themselves: X-MosWAF-User is an
    -- identity the upstream trusts, X-MosWAF-Token is the control plane's internal
    -- credential. They are removed on every request to every site, including sites
    -- with the gate switched off and sites in "off" mode - both of those return
    -- early below, and a request that returns early is exactly the one an attacker
    -- would pick to carry a forged header through.
    auth.strip_trusted_headers()

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

    -- 0. the login gate
    --
    -- Ahead of the protection mode and ahead of the allowlist, and neither is an
    -- oversight.
    --
    -- "Off" turns off the firewall - the rules, the rate limit, the challenge. It
    -- is what an operator reaches for at 3am to prove a false positive is theirs.
    -- If it also removed the password from the admin panel they put behind one,
    -- the tool for diagnosing a blocked customer would be the tool that exposes
    -- the site, and nothing in the name says so.
    --
    -- The allowlist is the same argument in the other direction: it means "this
    -- address is not an attacker", which is not the same as "this address is the
    -- person who knows the password". An office IP exempt from rate limiting must
    -- not be an office IP that skips signing in.
    --
    -- Costs nothing on the common path: a request with no cookie is refused before
    -- any signature is computed.
    if site.auth_enabled and auth.gated(uri, site) then
        local user_id, why = auth.verify(site_id, auth.cookie_value(),
                                         site.auth_users, ngx.time())
        if not user_id then
            ctx.action = "auth"
            ctx.reason = "auth:" .. (why or "denied")
            return auth.refuse(why)
        end
        ctx.auth_user = user_id
        auth.announce(user_id)
    end

    -- 1. protection mode
    local mode = site.mode or st.default_mode or "protect"
    if mode == "off" then
        ctx.action = "bypass"
        return
    end

    -- Count the request against the site total before anything can return. A
    -- flood is still a flood when most of it is being rejected, and the totals
    -- are what tells the difference between one noisy address and ten thousand.
    flood.observe(site_id)

    -- 2. allowlist: skip every remaining check
    if ipset.is_whitelisted(ip) then
        ctx.action = "allow_white"
        return
    end

    -- 3. currently banned, or on the blocklist
    local banned, breason = ipset.is_banned(ip)
    if banned then
        return block(ctx, mode, "banned:" .. tostring(breason), nil, 403)
    end
    if ipset.is_blacklisted(ip) then
        return block(ctx, mode, "blacklist", nil, 403)
    end

    -- 3b. a verified search engine
    --
    -- Deliberately after the ban and the blocklist. An operator who blocked an
    -- address meant to block it, and a list fetched from a third party must never
    -- overrule that - if a crawler range ever overlapped an address somebody had
    -- banned, the ban wins.
    --
    -- Verification exempts from the JS challenge and nothing else. A crawler
    -- cannot run JavaScript, so challenging one is the same as blocking it, and
    -- losing search engines during an attack is its own kind of damage. Rules,
    -- rate limiting and the flood defence all still apply below.
    local verified, faked = crawler.verify(ip, ua)
    if verified then
        ctx.crawler = verified
    elseif faked then
        -- Claimed a crawler the address does not back up. Recorded rather than
        -- blocked: the claim alone is not an attack, and blocking on it would be
        -- a way to get a competitor's monitoring cut off. The request carries on
        -- through every check as an ordinary visitor.
        ctx.fake_crawler = true
    end

    -- 3c. the country rule
    --
    -- After the allowlist, which is deliberate: an address somebody put on the
    -- allowlist is an address they want through, and "block this country except
    -- our partner in it" is the ordinary way this gets used. After the ban and
    -- blocklist too, so that an address refused for what it did is reported as
    -- that rather than as where it is.
    --
    -- And after crawler verification, which is the one that would otherwise go
    -- unnoticed: an allow rule naming one country refuses Googlebot, and a site
    -- silently leaving the search index is a far larger loss than whatever the
    -- rule was written to prevent. Verification is against published address
    -- ranges, not a user agent, so this cannot be claimed by an attacker.
    if not ctx.crawler and geo.refuses(site.geo_mode, conf.geo_sets and conf.geo_sets[site.geo_set], ip) then
        ctx.severity = "low"
        return block(ctx, mode, "geo:" .. site.geo_mode, nil, 403)
    end

    -- 4. a visitor coming back from the challenge
    --
    -- This sits after the ban and blocklist checks and before rate limiting, on
    -- purpose. Before them it was a free channel: a banned IP could still reach an
    -- endpoint that runs a SHA-256 and an HMAC per request, which made it the most
    -- expensive path in the whole engine to flood. After rate limiting it would be
    -- worse in the other direction - a legitimate visitor challenged *because* they
    -- crossed the threshold could never reach the endpoint that clears it, and would
    -- be stuck in a challenge loop. Repeat offenders still end up banned, and a ban
    -- does close this door.
    if uri == challenge.verify_uri then
        ctx.action = "verify"
        return challenge.handle_verify(ip, ua)
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
        -- The counters are unusable (shared dict exhausted). Challenge everyone
        -- rather than pass them through, but never escalate to a ban: the count
        -- that a ban would be based on does not mean anything right now.
        if rreason == ratelimit.DICT_FULL then
            return do_challenge(ctx, mode, "counters_unavailable")
        end

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

    -- 6. under-attack mode: switched on by hand, set on the site, or engaged by
    --    the flood detector on its own.
    --
    -- The per-IP limit above cannot see a distributed flood - that is the whole
    -- point of building one - so this is the layer that answers it. The check is
    -- one shared-dict read per request; the measurement behind it runs at most
    -- once a second per worker.
    local auto_reason
    if not st.under_attack and site.challenge ~= "always" then
        local engaged
        engaged, auto_reason = flood.evaluate(site_id, flood.threshold(site, st))
        if engaged then
            ctx.auto_flood = auto_reason or "flood"
        end
    end

    if (st.under_attack or site.challenge == "always" or ctx.auto_flood)
       and not ctx.crawler then
        if not challenge.has_valid_cookie(ip, ua) then
            local why = "site_challenge"
            if st.under_attack then
                why = "under_attack"
            elseif ctx.auto_flood then
                why = "auto_flood:" .. ctx.auto_flood
            end
            return do_challenge(ctx, mode, why)
        end
    end

    -- 7. signature scanning
    -- 64 was a hiding place: send 70 headers and the payload goes in number 65.
    -- nginx already caps how many headers it accepts through
    -- large_client_header_buffers, so reading them all is bounded.
    local headers = ngx.req.get_headers(0, true)
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
        local max = tonumber(st.max_body_scan) or 65536
        -- Two holes used to live here. A body larger than max was skipped whole
        -- instead of truncated, so padding a payload with 64KB of filler walked
        -- straight through; and a chunked request has no Content-Length, so
        -- `len > 0` was false and the body was never scanned at all.
        ngx.req.read_body()
        local body = ngx.req.get_body_data()
        if not body then
            -- nginx spilled the body to disk (client_body_buffer_size) - read the
            -- start of that file rather than giving up on it
            local path = ngx.req.get_body_file()
            if path then
                local f = io.open(path, "rb")
                if f then
                    body = f:read(max)
                    f:close()
                end
            end
        end
        if body and #body > 0 then
            scan.body = expand(#body > max and body:sub(1, max) or body)
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
