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

-- ------------------------------------------------ IPv4 written as IPv6
--
-- "::ffff:1.2.3.4" is 1.2.3.4. A dual-stack socket hands every IPv4 client to the
-- application in that form, and a forwarded header can carry it whatever the
-- socket is - so if the two spellings do not meet, one host holds two identities
-- and an address ban is walked around by writing the address differently.
--
-- The two halves could not meet by construction: ipv4_to_int rejects the mapped
-- form for containing a colon, and ipv6_groups rejects the dotted form for having
-- two groups. Every IPv4 entry in either list returned false for the mapped form,
-- silently.

do
    check("a mapped address normalises to the IPv4 address it is",
        util.normalize_ip("::ffff:1.2.3.4") == "1.2.3.4",
        "got " .. tostring(util.normalize_ip("::ffff:1.2.3.4")))

    check("the uppercase spelling folds too",
        util.normalize_ip("::FFFF:1.2.3.4") == "1.2.3.4")
    check("the fully written out spelling folds too",
        util.normalize_ip("0:0:0:0:0:ffff:1.2.3.4") == "1.2.3.4")
    check("the hex spelling of the same thing folds too",
        util.normalize_ip("::ffff:102:304") == "1.2.3.4",
        "got " .. tostring(util.normalize_ip("::ffff:102:304")))

    -- The blocklist, from both directions.
    check("a mapped client is caught by an IPv4 /32",
        (util.ip_in_list("::ffff:1.2.3.4", { "1.2.3.4/32" })),
        "a banned host walked away by writing its address as IPv6")
    check("a mapped client is caught by an IPv4 /24",
        (util.ip_in_list("::ffff:1.2.3.4", { "1.2.3.0/24" })))
    check("a mapped client is caught by a bare IPv4 entry",
        (util.ip_in_list("::ffff:1.2.3.4", { "1.2.3.4" })))
    check("a dotted client is caught by an entry written in mapped form",
        (util.ip_in_list("1.2.3.4", { "::ffff:1.2.3.4" })),
        "an allowlist written in mapped form would not recognise its own client")
    check("a mapped prefix is the IPv4 prefix it covers",
        (util.ip_in_list("1.2.3.9", { "::ffff:1.2.3.0/120" })),
        "::ffff:1.2.3.0/120 is 1.2.3.0/24")

    check("a mapped client outside the range is still outside it",
        not util.ip_in_list("::ffff:9.9.9.9", { "1.2.3.0/24" }))

    -- Private ranges have to be visible through the mapped form as well.
    check("mapped loopback is private", util.is_private_ip("::ffff:127.0.0.1"))
    check("mapped RFC1918 is private", util.is_private_ip("::ffff:10.0.0.1"))
    check("a mapped public address is not private", not util.is_private_ip("::ffff:8.8.8.8"))

    -- The deprecated IPv4-compatible form is deliberately NOT folded: ::1 is the
    -- IPv6 loopback, and folding that shape would turn it into 0.0.0.1 - an
    -- address nobody wrote, matching lists nobody meant.
    check("::1 stays the IPv6 loopback and does not become 0.0.0.1",
        util.normalize_ip("::1") == "::1",
        "got " .. tostring(util.normalize_ip("::1")))
    check("an IPv4-compatible address is not folded",
        util.normalize_ip("::1.2.3.4") ~= "1.2.3.4")

    -- And a real IPv6 address must not be mistaken for a mapped one.
    check("a real IPv6 address is untouched",
        util.normalize_ip("2001:db8::1") == "2001:db8::1")
    check("ffff in the wrong group is not a mapped address",
        util.unmap_ipv4("::ffff:0:1.2.3.4") == nil,
        "only ::ffff:0:0/96 is the mapped range")
end

-- A parser that invents an address out of a string that is not one.
--
-- The splitter used to drop empty pieces, so a second "::" inside a half, a
-- leading ":" and a trailing one all vanished instead of being refused: "::ffff:"
-- came back as ::ffff and "1::2::3" as 1::2:3. Neither string is an address, and
-- an address neither of them names is what every decision downstream - the
-- blocklist included - would then have been made about.
for _, bad in ipairs({
    "::ffff:",      -- trailing colon
    ":::",          -- three
    "1::2::3",      -- two "::" is never valid
    ":1:2:3:4:5:6:7",
    "1:2:3:4:5:6:7:",
    "::ffff::1",
    "1:::2",
}) do
    check("a string that is not an address is refused: " .. bad,
        util.ipv6_groups(bad) == nil,
        "ipv6_groups accepted it and produced eight groups, which means every " ..
        "check downstream was made about an address nobody sent")
end

-- And the valid spellings still parse, including the awkward ones.
for _, good in ipairs({ "::", "::1", "1::", "2001:db8::1",
                        "1:2:3:4:5:6:7:8", "::ffff:1.2.3.4",
                        "0:0:0:0:0:ffff:1.2.3.4" }) do
    check("a valid address still parses: " .. good,
        util.ipv6_groups(good) ~= nil,
        "the stricter splitter refused an address that is perfectly legal")
end

-- ------------------------------------------------------------ report

io.write("\n\n")
if #failures == 0 then
    print(string.format("%d/%d checks passed", total, total))
    print("\n  an IPv6 prefix in the block or allow list now matches the range it names")
    print("  the same host written several ways is still the same host")
    print("  an IPv4 client arriving as ::ffff:1.2.3.4 is that IPv4 client everywhere")
    os.exit(0)
end
print(string.format("%d of %d checks FAILED:\n", #failures, total))
for _, f in ipairs(failures) do print("  - " .. f) end
os.exit(1)
