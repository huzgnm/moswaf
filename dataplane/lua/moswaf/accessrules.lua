-- moswaf.accessrules - the operator's own ordered allow and deny rules
--
-- Tried before the firewall's own checks, in order, and the first rule that
-- matches decides. Order is therefore part of the policy rather than a display
-- preference: two rules swapped are a different firewall.
--
-- A rule holds conditions that must ALL hold, and each condition holds values of
-- which ANY may match. "Or" between conditions is written as two rules, which
-- keeps the evaluation a straight line and keeps the dashboard readable.
--
-- Everything a condition can test is something the request phase has already
-- worked out. Nothing here costs a lookup, a parse or a round trip that was not
-- happening anyway - this runs on every request to a site that has any rules.

local util = require "moswaf.util"
local geo  = require "moswaf.geo"

local _M = {}

local lower = string.lower
local sub   = string.sub
local find  = string.find

-- --------------------------------------------------------------- one field

-- What a condition is tested against. Assembled once per request, not per rule,
-- because a site with fifty rules would otherwise read the same nginx variables
-- fifty times.
--
-- `crawler` is the verified crawler name or nil - the result of checking the
-- address against published ranges, never the user agent the request claims.
-- That distinction is the whole reason an allow rule may be written on it: if
-- this were a user-agent test, "allow verified crawlers" would mean "allow
-- anybody who types Googlebot into a header".
function _M.subject(ip, ctx)
    return {
        ip      = ip,
        crawler = ctx and ctx.crawler or nil,
        path    = ngx.var.uri or "/",
        host    = lower(ngx.var.http_host or ngx.var.host or ""),
        ua      = ngx.var.http_user_agent or "",
        method  = ngx.var.request_method or "",
    }
end

-- --------------------------------------------------------- one condition

-- Returns true when the condition holds.
--
-- A condition that cannot be evaluated - a country test with no address data
-- behind it - returns false, so the rule does not fire. That direction is
-- deliberate for both actions: a deny that cannot be evaluated lets the request
-- carry on to every other layer of the firewall, and an allow that cannot be
-- evaluated simply does not exempt anybody.
local function holds(cond, subj, sets)
    local field, op, vals = cond.field, cond.op, cond.values
    if type(vals) ~= "table" then return false end

    if field == "ip" then
        return util.ip_in_list(subj.ip, vals)

    elseif field == "method" then
        local m = subj.method
        for i = 1, #vals do
            if m == vals[i] then return true end
        end
        return false

    elseif field == "crawler" then
        local want = vals[1] == "true"
        return (subj.crawler ~= nil) == want

    elseif field == "country" then
        -- The published set covers exactly the countries this condition names, so
        -- "is the address in one of them" is a membership test rather than a lookup
        -- that returns a name.
        local set = sets and cond.set and sets[cond.set]
        if not set then return false end
        return geo.contains(set, subj.ip) == true

    elseif field == "path" then
        local p = subj.path
        for i = 1, #vals do
            local v = vals[i]
            if op == "prefix" then
                if sub(p, 1, #v) == v then return true end
            elseif op == "equals" then
                if p == v then return true end
            else -- contains
                if find(p, v, 1, true) then return true end
            end
        end
        return false

    elseif field == "host" then
        local h = subj.host
        for i = 1, #vals do
            local v = vals[i]
            if op == "equals" then
                if h == v then return true end
            else -- suffix
                -- Anchored on a dot so that "example.com" does not also match
                -- "notexample.com", which is a different site somebody else owns.
                if h == v or sub(h, -(#v + 1)) == "." .. v then return true end
            end
        end
        return false

    elseif field == "ua" then
        local u = subj.ua
        for i = 1, #vals do
            local v = vals[i]
            if op == "equals" then
                if u == v then return true end
            else -- contains
                if find(u, v, 1, true) then return true end
            end
        end
        return false
    end

    -- A field this version does not know. Refusing to match is the only safe
    -- answer: a rule written against a newer control plane must not fire here on
    -- a guess about what it meant.
    return false
end

-- ------------------------------------------------------------- one rule

local function matches(rule, subj, sets)
    local conds = rule.conditions
    if type(conds) ~= "table" or #conds == 0 then
        -- A rule with nothing to match on would fire on everything. The control
        -- plane refuses to store one; this is the second lock, because a rule that
        -- fires on everything is the firewall switched off or the site switched off
        -- depending only on its action.
        return false
    end
    for i = 1, #conds do
        if not holds(conds[i], subj, sets) then
            return false      -- short-circuit: the rest cannot rescue it
        end
    end
    return true
end

-- --------------------------------------------------------------- evaluate

--- Find the first rule that matches this request.
--
-- Returns the rule, or nil. The caller decides what the action means; this only
-- answers which rule speaks first.
--
-- site_id comes from the site being served - ngx.var.moswaf_site - and never from
-- the rule or the request. A rule written for one site must not be able to reach
-- another, which is the same isolation the session cookie needs and the same
-- mistake if it is taken from the wrong place.
function _M.match(rules, site_id, subj, sets)
    if type(rules) ~= "table" then return nil end
    for i = 1, #rules do
        local r = rules[i]
        if r.enabled ~= false
           and (r.site == "" or r.site == site_id)
           and matches(r, subj, sets) then
            return r
        end
    end
    return nil
end

-- Exposed for the dry-run endpoint, which answers "which rule would this request
-- hit" - the only way an operator can see that a rule near the top is quietly
-- shadowing everything below it.
_M.rule_matches = matches

return _M
