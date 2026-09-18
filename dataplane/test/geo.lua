-- Tests for moswaf.geo - blocking and allowing by country.
--
-- The whole feature has one failure mode worth fearing, and it is not "an
-- attacker gets through". It is "the site goes dark": an allow rule that refuses
-- everybody. There are several ordinary ways to reach that state without anyone
-- asking for it - the dataset has not downloaded yet, the visitor's address is
-- not in it, the address is IPv6 and the rule only covers IPv4 - and in every one
-- of them the request looks exactly like a visitor from a country that was not
-- listed.
--
-- So most of what follows checks that an unanswerable question is answered "let
-- them through" rather than "not in the list".
--
--   luajit dataplane/test/geo.lua

local ROOT = arg[0]:match("^(.*)/test/geo%.lua$") or "dataplane"
package.path = ROOT .. "/lua/?.lua;" .. ROOT .. "/lua/?/init.lua;" .. package.path

package.loaded["resty.redis"] = {}

_G.ngx = {
    var = {}, req = { get_headers = function() return {} end },
    time = function() return 1700000000 end,
    log = function() end, ERR = 1, WARN = 2,
    encode_base64 = function(s) return s end,
    hmac_sha1 = function(_, m) return m end,
}

local geo = require "moswaf.geo"

-- ---------------------------------------------------------------- harness

local failures, total = {}, 0
local function check(name, ok, detail)
    total = total + 1
    if ok then io.write(".") else
        io.write("F")
        failures[#failures + 1] = name .. (detail and ("\n      " .. detail) or "")
    end
end

local function v4(a, b, c, d) return a * 16777216 + b * 65536 + c * 256 + d end

-- What the control plane publishes: merged, sorted, interleaved bounds, with the
-- country labels already thrown away.
local VN = {
    v4 = { v4(14, 160, 0, 0), v4(14, 191, 255, 255),
           v4(113, 160, 0, 0), v4(113, 191, 255, 255) },
    v6 = { "2401d80000000000" .. "0000000000000000",
           "2401d800ffffffff" .. "ffffffffffffffff" },
}

-- A rule covering IPv4 only, which is what several real countries produce -
-- the dataset has no IPv6 allocation for them.
local V4_ONLY = { v4 = { v4(8, 8, 8, 0), v4(8, 8, 8, 255) }, v6 = {} }

-- ============================================================== membership

check("an address inside a range is found",   geo.contains(VN, "14.177.0.1") == true)
check("the first address of a range is found", geo.contains(VN, "14.160.0.0") == true)
check("the last address of a range is found",  geo.contains(VN, "14.191.255.255") == true)
check("an address just below is not",          geo.contains(VN, "14.159.255.255") == false)
check("an address just above is not",          geo.contains(VN, "14.192.0.0") == false)
check("the second range is searched too",      geo.contains(VN, "113.170.5.5") == true)
check("the gap between two ranges is not in",  geo.contains(VN, "50.0.0.1") == false)
check("an IPv6 address inside a range is found", geo.contains(VN, "2401:d800::5") == true)
check("an IPv6 address outside is not",          geo.contains(VN, "2606:4700::1") == false)

-- The bug class this project keeps finding. The same visitor arriving over a
-- dual-stack socket must be placed in the same country as over a v4 one; under an
-- allow rule the difference is being let in or being refused.
check("a mapped IPv4 address is searched as IPv4",
    geo.contains(VN, "::ffff:14.177.0.1") == true,
    "::ffff:14.177.0.1 is 14.177.0.1; searching the IPv6 table for it finds " ..
    "nothing, and under an allow rule that refuses a visitor who would have been " ..
    "let in a moment earlier over IPv4")
check("and the hex spelling of the same thing too",
    geo.contains(VN, "::ffff:0eb1:0001") == true)

-- =============================================== the unanswerable questions

for _, case in ipairs({
    { "no set at all",            nil,        "14.177.0.1" },
    { "an empty table",           {},         "14.177.0.1" },
    { "a set with empty lists",   { v4 = {}, v6 = {} }, "14.177.0.1" },
    { "an address that will not parse", VN,   "not an address" },
    { "an empty address",         VN,         "" },
    { "nil for an address",       VN,         nil },
}) do
    local name, set, ip = case[1], case[2], case[3]
    check("unanswerable, not false: " .. name, geo.contains(set, ip) == nil,
        "contains() returned " .. tostring(geo.contains(set, ip)) .. ". Under an " ..
        "allow rule, false means refuse - so answering false here refuses a " ..
        "visitor because of a missing dataset or a parsing failure")
end

-- A rule holding IPv4 ranges and no IPv6 ones is normal, not broken. For an IPv6
-- visitor it is a question with no answer, which is not the same as "no".
check("an IPv4-only rule cannot answer for an IPv6 visitor",
    geo.contains(V4_ONLY, "2401:d800::5") == nil)

-- ================================================================ verdicts

check("block mode refuses a listed country",     geo.refuses("block", VN, "14.177.0.1") == true)
check("block mode lets everyone else through",   geo.refuses("block", VN, "8.8.8.8") == false)
check("allow mode lets a listed country in",     geo.refuses("allow", VN, "14.177.0.1") == false)
check("allow mode refuses everyone else",        geo.refuses("allow", VN, "8.8.8.8") == true)

check("no mode means no rule", geo.refuses("off", VN, "8.8.8.8") == false)
for _, m in ipairs({ "", "Block", "ALLOW", "deny", "yes" }) do
    check("an unrecognised mode refuses nobody: " .. m,
        geo.refuses(m, VN, "8.8.8.8") == false,
        "a mode string that is not exactly \"block\" or \"allow\" must do nothing; " ..
        "guessing at it is how a typo in a config becomes an outage")
end

-- THE ONE THAT MATTERS.
--
-- Every way of failing to place an address has to let the visitor through, under
-- BOTH modes. Under block that is obvious. Under allow it is the difference
-- between a firewall feature and a site that is down for a fraction of its
-- visitors, reported as "it works for me".
do
    local cases = {
        { "no dataset published yet", nil },
        { "an empty set",             { v4 = {}, v6 = {} } },
    }
    for _, c in ipairs(cases) do
        check("allow mode lets traffic through when it cannot decide: " .. c[1],
            geo.refuses("allow", c[2], "14.177.0.1") == false,
            "with no ranges, every address is \"not in the list\" - so an allow " ..
            "rule would refuse every visitor on earth, and the only sign of it is " ..
            "a traffic graph at zero")
        check("block mode too: " .. c[1],
            geo.refuses("block", c[2], "14.177.0.1") == false)
    end

    check("an unparseable address is let through under allow",
        geo.refuses("allow", VN, "garbage") == false)
    check("an IPv6 visitor is let through by an IPv4-only allow rule",
        geo.refuses("allow", V4_ONLY, "2401:d800::5") == false,
        "several real countries have no IPv6 ranges in the dataset; refusing " ..
        "IPv6 visitors because of that would take out everyone on a modern mobile " ..
        "network")
end

-- ================================================================ nonsense

for _, bad in ipairs({
    "999.999.999.999", "1.2.3", "1.2.3.4.5", "1.2.3.4:80", "<script>",
    "::ffff:", ":::", string.rep("f", 5000), "14.177.0.1/24",
}) do
    local ok, res = pcall(geo.refuses, "allow", VN, bad)
    check("nonsense is handled without raising: " .. bad:sub(1, 20),
        ok and res == false, ok and ("returned " .. tostring(res)) or tostring(res))
end

local ok = pcall(geo.contains, { v4 = "not a table", v6 = 7 }, "8.8.8.8")
check("a malformed published set does not raise", ok)

-- =================================================================== report

io.write("\n")
if #failures > 0 then
    io.write("\n", #failures, " of ", total, " checks failed:\n")
    for _, f in ipairs(failures) do io.write("  - ", f, "\n") end
    os.exit(1)
end
io.write(total, " checks passed\n")
