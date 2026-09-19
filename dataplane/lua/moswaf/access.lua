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
local rulesets  = require "moswaf.accessrules"

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

-- Substitute one placeholder.
--
-- The replacement is a function rather than a string because gsub reads "%1"
-- and friends in a replacement string as captures - a value containing a per
-- cent sign would be rewritten, or would raise "invalid use of '%'" and turn a
-- block page into a 500.
--
-- Escaped as well, even though every value put through it today is already
-- constrained - the ray is hex, the address has been through normalize_ip, the
-- time comes from nginx. That is the state of the callers now, not a property
-- of the function, and this is the last point before the bytes are a page.
local function fill(html, key, value)
    value = value or ""
    value = value:gsub("[&<>\"']", {
        ["&"] = "&amp;", ["<"] = "&lt;", [">"] = "&gt;",
        ['"'] = "&quot;", ["'"] = "&#39;",
    })
    return (html:gsub(key, function() return value end))
end

local function render_block(ctx, status)
    -- No reason is rendered. The rule that fired is in the attack log against
    -- this ray, which is where the operator reads it; on the page it would tell
    -- whoever is probing the site which signature caught them - and a rule name
    -- is operator-written text, so it is also the one value here that could
    -- carry markup.
    local html = config.block_html
    html = fill(html, "{{RAY}}", ctx.ray)
    html = fill(html, "{{IP}}", ctx.ip)
    html = fill(html, "{{TIME}}", ngx.localtime())

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

    -- Handed a challenge and never seen to answer one.
    --
    -- A browser is challenged once: it solves the proof of work, keeps the
    -- cookie, and is not asked again. So an address collecting challenge after
    -- challenge is one that is not answering them - and that cannot be produced
    -- by a page with too many assets, by a crowd sharing one carrier address, or
    -- by somebody clicking quickly, because every one of those answers the first
    -- one and stops being counted.
    --
    -- This is what a flood earns instead of a ban on request count. Being refused
    -- a lot proves nothing about anybody; being asked a lot and never replying
    -- does.
    local st = config.get().settings
    -- Somebody holding a solved challenge is never counted, wherever this was
    -- called from.
    --
    -- The accusation is "asked and never answered". A visitor carrying a valid
    -- cookie has answered, and counting them would turn the one signal a real
    -- person cannot produce into one they produce by being busy. Checked here
    -- rather than only at the call sites so that the sentence above this function
    -- is true of the function, and not merely true of the places that remembered.
    if not challenge.has_valid_cookie(ctx.ip, ctx.ua) then
        local unsolved = ratelimit.mark_challenge(ctx.ip)
        if unsolved >= ratelimit.CHALLENGE_BAN_AT then
            ipset.ban_ip(ctx.ip, st.ban_seconds, "unsolved_challenges:" .. unsolved)
        end
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

    -- Hand the upstream the address we decided on, not the one the socket came
    -- from. Behind a CDN those differ, and if the origin is told the second it
    -- logs, rate-limits and geolocates the CDN while the firewall does all three
    -- against the visitor - the same system disagreeing with itself about who is
    -- being served.
    --
    -- Assigned here rather than in nginx because this is the only place that knows
    -- the answer: it took the trusted-proxy walk to get it.
    -- pcall because writing an nginx variable that was never declared raises,
    -- and this runs on every request: a site whose config predates the `set`
    -- directive would answer 500 to everything rather than merely telling its
    -- upstream the wrong address. Generated configs always declare it; a
    -- hand-written one, or one left over from an older version, might not.
    pcall(function() ngx.var.moswaf_client_ip = ip end)

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
    -- Established here, once, before anything consults it: the country rule below
    -- exempts crawlers, and an access rule may be written on "is a verified
    -- crawler". Both read ctx.crawler rather than checking again, so fifty rules
    -- cost one verification.
    --
    -- What it is verified against matters more than when. crawler.verify compares
    -- the address to ranges the search engines publish; it is not a user-agent
    -- test. An access rule may say "allow verified crawlers" only because of that
    -- - were this a user-agent test, the same rule would read "allow anybody who
    -- types Googlebot into a header".
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

    -- 3c. the operator's own rules
    --
    -- Placed here on purpose: after the manual ban and blocklist, which must beat
    -- everything, and before the country rule, the rate limit, the challenge and
    -- the signature engine, which is what an "allow" rule exempts a request from.
    --
    -- What each action does, written out once so it is never a guess:
    --
    --   allow      stop checking. Skips the country rule, the rate limit, the JS
    --              challenge and the signature rules - exactly what the manual IP
    --              allowlist above already does, and no more. It does NOT skip the
    --              manual ban or blocklist, which ran before this.
    --   deny       refuse now, 403.
    --   challenge  ask for the proof-of-work, unless this is a verified crawler,
    --              which cannot run JavaScript - challenging one is blocking it.
    --   log        record the match and carry on through every check below.
    --
    -- "Allow" is only allowed to be written on the address or on a verified
    -- crawler; the control plane refuses the rest. The reason is that allow stops
    -- the firewall, so whoever controls the condition that fires it controls
    -- whether the firewall runs - and a path, a host, a method or a user agent is
    -- part of the request, which means the attacker writes it. "Allow if the user
    -- agent contains Mozilla" would not be a broad rule, it would be a back door
    -- opened by sending a header.
    local rule_hit
    if conf.access_rules and #conf.access_rules > 0 then
        rule_hit = rulesets.match(conf.access_rules, site_id,
                                  rulesets.subject(ip, ctx), conf.geo_sets)
    end
    if rule_hit then
        ctx.rule_id   = rule_hit.id
        ctx.rule_name = rule_hit.name
        -- Marks this as one of the operator's rules rather than a signature rule.
        -- Both write ctx.rule_id, and only these are counted per rule per day.
        ctx.rule_hit  = true
        local act = rule_hit.action
        if act == "allow" then
            ctx.action = "allow_rule"
            ctx.reason = "rule:" .. tostring(rule_hit.id)
            return
        elseif act == "deny" then
            return block(ctx, mode, "rule:" .. tostring(rule_hit.id), nil, 403)
        elseif act == "challenge" then
            if not ctx.crawler and not challenge.has_valid_cookie(ip, ua) then
                return do_challenge(ctx, mode, "rule:" .. tostring(rule_hit.id))
            end
        else -- log
            ctx.reason = "rule:" .. tostring(rule_hit.id)
        end
    end

    -- 3d. the country rule
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
        -- Has this visitor already proved they are a browser?
        --
        -- The rate limit is counted per address, and an address is not a person:
        -- behind a carrier NAT it is two hundred of them. So exceeding it says
        -- nothing about whoever sent this particular request, and if they have
        -- already solved a challenge it says nothing about them at all.
        local solved = challenge.has_valid_cookie(ip, ua)

        if rreason == ratelimit.DICT_FULL then
            if solved then
                return block(ctx, mode, "counters_unavailable", nil, 429)
            end
            return do_challenge(ctx, mode, "counters_unavailable")
        end

        -- Going over a rate limit does not earn a ban, and this is the whole
        -- shape of the thing.
        --
        -- Everybody goes over eventually. A page with forty assets is forty
        -- requests. A phone on a carrier NAT shares one address with two hundred
        -- other people, so the budget is not theirs, it is the crowd's. Somebody
        -- double-clicks. Treating that volume as an attack is how an administrator
        -- opening their own admin panel was banned for ten minutes with "flood"
        -- written in the log.
        --
        -- So: too much traffic is answered with a challenge, which a browser
        -- solves without its owner noticing and an unattended client does not.
        -- A ban is reserved for the signature engine, below, where being refused
        -- ten times in a minute means somebody is trying things rather than
        -- browsing.
        if site.challenge ~= "off" and not solved then
            return do_challenge(ctx, mode, "flood:" .. rreason)
        end

        -- Already solved, and still over the shared limit. Refused for this
        -- request and nothing more: no second proof of work - they have done it -
        -- and nothing counted against them, because the thing being counted is
        -- never answering, and they answered.
        --
        -- Without this, two hundred people sharing one carrier address would each
        -- be re-challenged on every over-limit request, and the address would
        -- collect thirty "unanswered" challenges in seconds - banning all two
        -- hundred of them for the crime of having solved it already. That is the
        -- same collective punishment this change exists to remove, reached by a
        -- different counter.
        -- The site has switched the challenge off, which is what an API-only site
        -- does - a client that cannot run JavaScript is not helped by being asked
        -- to. It is refused for this request and nothing more; as soon as the rate
        -- drops it is served again.
        return block(ctx, mode, "flood:" .. rreason .. ":" .. c1 .. "/" .. c10, nil, 429)
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
            -- A refusal by the signature engine is the thing worth counting.
            -- Somebody refused ten times in a minute is trying things, not
            -- browsing - no page load produces this, and no number of assets and
            -- no amount of carrier NAT produces it either.
            local attacks = ratelimit.mark_attack(ip)
            if attacks >= ratelimit.ATTACK_BAN_AT then
                ipset.ban_ip(ip, st.ban_seconds, "attacks:" .. attacks)
            end
            return block(ctx, mode, "rule", matched, nil)
        end
    end
end

return _M
