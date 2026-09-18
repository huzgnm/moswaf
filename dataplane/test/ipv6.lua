-- Tests for IPv6 prefix matching in the block and allow lists.
--
-- Before this, IPv6 entries were compared as strings. Putting 2001:db8::/32 in
-- the blocklist therefore matched one address - the one literally spelled
-- "2001:db8::/32", which is not an address at all - so the range blocked
-- nothing. No error, no warning: the operator saw the entry in the list and
-- believed a /32 was blocked.
--
-- The other half is canonical form. An IPv6 address has many spellings, and a
-- list that compares spellings rather than addresses is a list you walk around
-- by writing the same host differently.
--
--   luajit dataplane/test/ipv6.lua

local ROOT = arg[0]:match("^(.*)/test/ipv6%.lua$") or "dataplane"
package.path = ROOT .. "/lua/?.lua;" .. ROOT .. "/lua/?/init.lua;" .. package.path

-- util.lua pulls in resty.redis at load time; nothing here calls it.
package.loaded["resty.redis"] = {}

_G.ngx = {
    log = function() end, WARN = 2, ERR = 3,
    re = { find = function() return nil end },
    var = {},
}

local util = require "moswaf.util"

local failures, total = {}, 0
local function check(name, ok, detail)
    total = total + 1
    if ok then io.write(".") else
        io.write("F")
        failures[#failures + 1] = name .. (detail and ("\n      " .. detail) or "")
    end
end

-- ------------------------------------------------------------ parsing

do
    local g = util.ipv6_groups("2001:db8::1")
    check(":: expands to the missing zero groups",
        g and #g == 8 and g[1] == 0x2001 and g[2] == 0x0db8 and g[8] == 1 and g[4] == 0,
        "got " .. (g and table.concat(g, ":") or "nil"))

    check("a full address parses",
        (util.ipv6_groups("2001:0db8:0000:0000:0000:0000:0000:0001") or {})[8] == 1)

    check("an embedded IPv4 tail parses",
        (util.ipv6_groups("::ffff:1.2.3.4") or {})[7] == 0x0102)

    check("an IPv4 address is not IPv6", util.ipv6_groups("1.2.3.4") == nil)
    check("nonsense is not IPv6", util.ipv6_groups("hello") == nil)
    check("too many groups is rejected",
        util.ipv6_groups("1:2:3:4:5:6:7:8:9") == nil)
    check("a group that is too large is rejected",
        util.ipv6_groups("12345::1") == nil)
end

-- ------------------------------------------------------------ prefixes

do
    check("an address inside a /32",
        util.ipv6_in_prefix("2001:db8:1234::5", "2001:db8::", 32))
    check("an address outside a /32",
        not util.ipv6_in_prefix("2001:db9::1", "2001:db8::", 32))

    -- A /64 is the usual size handed to one customer, so getting the boundary
    -- right is the difference between blocking a subscriber and blocking a city.
    check("inside a /64", util.ipv6_in_prefix("2001:db8:0:1::abcd", "2001:db8:0:1::", 64))
    check("outside a /64", not util.ipv6_in_prefix("2001:db8:0:2::abcd", "2001:db8:0:1::", 64))

    -- A prefix that does not land on a group boundary is where a groups-based
    -- comparison is easiest to get wrong.
    check("inside a /33", util.ipv6_in_prefix("2001:db8:7fff::1", "2001:db8::", 33))
    check("outside a /33", not util.ipv6_in_prefix("2001:db8:8000::1", "2001:db8::", 33))
    check("inside a /127", util.ipv6_in_prefix("2001:db8::1", "2001:db8::", 127))
    check("outside a /127", not util.ipv6_in_prefix("2001:db8::2", "2001:db8::", 127))

    check("/0 matches everything", util.ipv6_in_prefix("2001:db8::1", "::", 0))
    check("/128 is one address", util.ipv6_in_prefix("2001:db8::1", "2001:db8::1", 128))
    check("/128 excludes the neighbour", not util.ipv6_in_prefix("2001:db8::2", "2001:db8::1", 128))

    check("a prefix length above 128 is refused",
        not util.ipv6_in_prefix("2001:db8::1", "2001:db8::", 129))
end

-- ------------------------------------------------------------ the lists

do
    local list = { "2001:db8::/32" }

    check("an IPv6 prefix in the list actually matches",
        (util.ip_in_list("2001:db8:1::99", list)),
        "this is the bug: a /32 in the blocklist used to match nothing at all")

    check("an address outside the prefix does not match",
        not util.ip_in_list("2001:dba::1", list))

    -- The same host, spelled several ways. A list that compares spellings is a
    -- list an attacker re-spells their way out of.
    local exact = { "2001:db8::1" }
    for _, spelling in ipairs({
        "2001:db8::1",
        "2001:0db8:0000:0000:0000:0000:0000:0001",
        "2001:DB8::1",
        "2001:db8:0:0:0:0:0:1",
    }) do
        check("the same host written as " .. spelling .. " still matches",
            (util.ip_in_list(spelling, exact)),
            "one spelling of an address is not a different address")
    end

    check("a different host does not match the exact entry",
        not util.ip_in_list("2001:db8::2", exact))

    -- IPv4 must keep working exactly as before.
    check("IPv4 CIDR still matches", (util.ip_in_list("10.1.2.3", { "10.0.0.0/8" })))
    check("IPv4 outside the range still does not",
        not util.ip_in_list("11.1.2.3", { "10.0.0.0/8" }))
    check("an IPv4 address is not matched by an IPv6 prefix",
        not util.ip_in_list("1.2.3.4", { "2001:db8::/32" }))
    check("an IPv6 address is not matched by an IPv4 prefix",
        not util.ip_in_list("2001:db8::1", { "10.0.0.0/8" }))

    check("an empty list matches nothing", not util.ip_in_list("2001:db8::1", {}))
    check("a malformed entry is ignored rather than fatal",
        not util.ip_in_list("2001:db8::1", { "not-an-address/64", "::/nope" }))
end

-- ------------------------------------------------------------ report

io.write("\n\n")
if #failures == 0 then
    print(string.format("%d/%d checks passed", total, total))
    print("\n  an IPv6 prefix in the block or allow list now matches the range it names")
    print("  the same host written several ways is still the same host")
    os.exit(0)
end
print(string.format("%d of %d checks FAILED:\n", #failures, total))
for _, f in ipairs(failures) do print("  - " .. f) end
os.exit(1)
