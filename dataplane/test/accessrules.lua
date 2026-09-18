-- Tests for moswaf.accessrules - the operator's own ordered allow and deny rules.
--
-- One action here can switch the firewall off, so most of what follows is about
-- that one. "Allow" means stop checking, which makes the condition that fires it
-- the condition that decides whether the firewall runs at all - and a condition
-- written on the path, the host, the method or the user agent is written on the
-- attacker's own request. "Allow if the user agent contains Mozilla" is not a
-- broad rule; it is a back door that any visitor opens by sending a header.
--
-- The control plane refuses to store those. These tests cover the half that runs
-- here: that a rule only fires when every condition really holds, that it cannot
-- reach a site it was not written for, and that a claimed crawler is not a
-- verified one.
--
--   luajit dataplane/test/accessrules.lua

local ROOT = arg[0]:match("^(.*)/test/accessrules%.lua$") or "dataplane"
package.path = ROOT .. "/lua/?.lua;" .. ROOT .. "/lua/?/init.lua;" .. package.path

package.loaded["resty.redis"] = {}

_G.ngx = {
    var = {}, req = { get_headers = function() return {} end },
    time = function() return 1700000000 end,
    log = function() end, ERR = 1, WARN = 2,
    encode_base64 = function(s) return s end,
    hmac_sha1 = function(_, m) return m end,
}

local rulesets = require "moswaf.accessrules"

-- ---------------------------------------------------------------- harness

local failures, total = {}, 0
local function check(name, ok, detail)
    total = total + 1
    if ok then io.write(".") else
        io.write("F")
        failures[#failures + 1] = name .. (detail and ("\n      " .. detail) or "")
    end
end

local function subject(t)
    return {
        ip      = t.ip or "203.0.113.5",
        crawler = t.crawler,
        path    = t.path or "/",
        host    = (t.host or "example.com"):lower(),
        ua      = t.ua or "Mozilla/5.0",
        method  = t.method or "GET",
    }
end

local function rule(t)
    return {
        id = t.id or "r1", name = t.name or "test", action = t.action or "deny",
        enabled = t.enabled ~= false, site = t.site or "",
        conditions = t.conditions,
    }
end

local function hit(rules, site, subj, sets)
    local r = rulesets.match(rules, site or "s1", subj, sets)
    return r and r.id or nil
end

local function v4(a, b, c, d) return a * 16777216 + b * 65536 + c * 256 + d end

-- =============================================================== matching

do
    local r = { rule({ id = "ip", conditions = {
        { field = "ip", op = "in_cidr", values = { "203.0.113.0/24" } } } }) }
    check("an address inside the range matches", hit(r, "s1", subject{ ip = "203.0.113.5" }) == "ip")
    check("an address outside does not",         hit(r, "s1", subject{ ip = "198.51.100.1" }) == nil)
    -- The fold this project keeps having to re-prove.
    check("the same address written as IPv6 matches",
        hit(r, "s1", subject{ ip = "::ffff:203.0.113.5" }) == "ip",
        "a dual-stack client must be the same client as over IPv4, or a rule " ..
        "applies to one socket and not the other")
end

do
    local r = { rule({ id = "m", conditions = {
        { field = "method", op = "in", values = { "POST", "PUT" } } } }) }
    check("any listed method matches",  hit(r, "s1", subject{ method = "PUT" }) == "m")
    check("an unlisted one does not",   hit(r, "s1", subject{ method = "GET" }) == nil)
end

do
    local r = { rule({ id = "p", conditions = {
        { field = "path", op = "prefix", values = { "/admin" } } } }) }
    check("a path prefix matches",          hit(r, "s1", subject{ path = "/admin/users" }) == "p")
    check("and matches the bare prefix",    hit(r, "s1", subject{ path = "/admin" }) == "p")
    check("an unrelated path does not",     hit(r, "s1", subject{ path = "/public" }) == nil)
end

do
    local r = { rule({ id = "h", conditions = {
        { field = "host", op = "suffix", values = { "example.com" } } } }) }
    check("a subdomain matches the suffix",  hit(r, "s1", subject{ host = "shop.example.com" }) == "h")
    check("the bare domain matches",         hit(r, "s1", subject{ host = "example.com" }) == "h")
    check("a lookalike domain does NOT",
        hit(r, "s1", subject{ host = "notexample.com" }) == nil,
        "\"notexample.com\" is a domain somebody else owns; a suffix test that " ..
        "is not anchored on a dot hands them whatever the rule grants")
end

-- ============================================================== crawlers

-- The condition that makes an allow rule safe to write at all. It reads the
-- result of checking the ADDRESS against published ranges - never the user agent,
-- which anybody can type.
do
    local r = { rule({ id = "c", action = "allow", conditions = {
        { field = "crawler", op = "is", values = { "true" } } } }) }

    check("a verified crawler matches",
        hit(r, "s1", subject{ crawler = "google" }) == "c")

    check("CLAIMING to be a crawler does not",
        hit(r, "s1", subject{ ua = "Mozilla/5.0 (compatible; Googlebot/2.1)" }) == nil,
        "the user agent says Googlebot and the address does not back it up. If " ..
        "this matched, \"allow verified crawlers\" would mean \"allow anybody who " ..
        "types Googlebot into a header\" - the firewall switched off by one line")

    local rf = { rule({ id = "nc", conditions = {
        { field = "crawler", op = "is", values = { "false" } } } }) }
    check("\"is not a crawler\" matches an ordinary visitor",
        hit(rf, "s1", subject{}) == "nc")
    check("and does not match a verified one",
        hit(rf, "s1", subject{ crawler = "bing" }) == nil)
end

-- ======================================================= all must hold

do
    local r = { rule({ id = "and", conditions = {
        { field = "method", op = "in",     values = { "POST" } },
        { field = "path",   op = "prefix", values = { "/api" } },
    } }) }
    check("both conditions holding matches",
        hit(r, "s1", subject{ method = "POST", path = "/api/x" }) == "and")
    check("only the first holding does not",
        hit(r, "s1", subject{ method = "POST", path = "/other" }) == nil)
    check("only the second holding does not",
        hit(r, "s1", subject{ method = "GET", path = "/api/x" }) == nil)
end

-- A condition with no values, or a rule with no conditions, would otherwise hold
-- vacuously - and a rule that holds for everything is the firewall switched off or
-- the site switched off, depending only on its action.
check("a rule with no conditions never matches",
    hit({ rule({ id = "empty", conditions = {} }) }, "s1", subject{}) == nil,
    "an empty condition list is true of every request")
check("a rule whose conditions are missing never matches",
    hit({ rule({ id = "nil", conditions = nil }) }, "s1", subject{}) == nil)
check("a condition with no values never matches",
    hit({ rule({ id = "nv", conditions = {
        { field = "path", op = "prefix", values = {} } } }) }, "s1", subject{}) == nil)
check("a condition on a field this version does not know never matches",
    hit({ rule({ id = "unk", conditions = {
        { field = "referer", op = "contains", values = { "x" } } } }) }, "s1", subject{}) == nil,
    "a rule written against a newer control plane must not fire here on a guess " ..
    "about what it meant")

-- ========================================================== ordering

do
    local rules = {
        rule({ id = "first",  action = "allow", conditions = {
            { field = "ip", op = "in_cidr", values = { "203.0.113.0/24" } } } }),
        rule({ id = "second", action = "deny", conditions = {
            { field = "ip", op = "in_cidr", values = { "203.0.113.5/32" } } } }),
    }
    check("the first matching rule decides",
        hit(rules, "s1", subject{ ip = "203.0.113.5" }) == "first",
        "both rules match this address; with first-match-wins the one above " ..
        "settles it, which is exactly how a rule near the top shadows the rest")

    -- Disabled rules are skipped rather than matched, so switching one off really
    -- does hand the decision to whatever is below it.
    rules[1].enabled = false
    check("a disabled rule is skipped and the next one decides",
        hit(rules, "s1", subject{ ip = "203.0.113.5" }) == "second")
end

-- ========================================================== site scope

do
    local rules = {
        rule({ id = "siteA", site = "sAAA", conditions = {
            { field = "path", op = "prefix", values = { "/" } } } }),
        rule({ id = "global", site = "", conditions = {
            { field = "path", op = "prefix", values = { "/only-global" } } } }),
    }
    check("a rule written for one site fires there", hit(rules, "sAAA", subject{}) == "siteA")
    check("and NOT on another site",
        hit(rules, "sBBB", subject{}) == nil,
        "a rule belonging to one site reached another. This is the same isolation " ..
        "the session cookie needs, and the same mistake: the site has to come from " ..
        "the site being served, never from the rule")
    check("a global rule fires on any site",
        hit(rules, "sZZZ", subject{ path = "/only-global" }) == "global")

    -- "" means every site. A site whose id somehow was the empty string must not
    -- become the one site that global rules are scoped to.
    check("a global rule still fires when the served site id is empty",
        hit(rules, "", subject{ path = "/only-global" }) == "global")
end

-- ============================================================= country

do
    local VN = {
        v4 = { v4(14, 160, 0, 0), v4(14, 191, 255, 255) },
        v6 = {},
    }
    local sets = { ["VN"] = VN }
    local r = { rule({ id = "geo", conditions = {
        { field = "country", op = "in", values = { "VN" }, set = "VN" } } }) }

    check("an address in the named country matches",
        hit(r, "s1", subject{ ip = "14.177.0.1" }, sets) == "geo")
    check("an address elsewhere does not",
        hit(r, "s1", subject{ ip = "8.8.8.8" }, sets) == nil)

    -- The ranges could not be built - no dataset yet, or a country the data does
    -- not contain. The condition cannot be answered, so the rule must not fire.
    check("a country condition with no published set never matches",
        hit(r, "s1", subject{ ip = "14.177.0.1" }, {}) == nil,
        "with no ranges there is nothing to test against; firing anyway would " ..
        "mean deciding on a country nobody established")
    check("and the same with no sets at all",
        hit(r, "s1", subject{ ip = "14.177.0.1" }, nil) == nil)
end

-- ============================================================= nonsense

for _, bad in ipairs({
    { rules = nil },
    { rules = "not a table" },
    { rules = { "not a rule" } },
    { rules = { rule({ conditions = { { field = "ip", op = "in_cidr", values = "no" } } }) } },
    { rules = { rule({ conditions = { {} } }) } },
}) do
    local ok = pcall(rulesets.match, bad.rules, "s1", subject{}, {})
    check("malformed published rules do not raise", ok,
        "a bad rule in the published config must not turn every request into a 500")
end

-- =================================================================== report

io.write("\n")
if #failures > 0 then
    io.write("\n", #failures, " of ", total, " checks failed:\n")
    for _, f in ipairs(failures) do io.write("  - ", f, "\n") end
    os.exit(1)
end
io.write(total, " checks passed\n")
