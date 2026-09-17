-- Tests for the pure-Lua parts of the data plane engine.
--
-- The engine normally only runs inside OpenResty, so this harness stubs the small
-- slice of the `ngx` API the modules under test actually touch. That is enough to
-- cover the IP parsing and client-IP resolution logic, which is where the engine
-- decides *who* a request is from - and therefore whose ban, blocklist entry and
-- rate-limit counter apply.
--
--   luajit dataplane/test/run.lua      (or: make lua-test)

local ROOT = arg[0]:match("^(.*)/test/run%.lua$") or "dataplane"
package.path = ROOT .. "/lua/?.lua;" .. ROOT .. "/lua/?/init.lua;" .. package.path

-- ------------------------------------------------------------------ ngx stub

local stub = {
    remote_addr = "203.0.113.10",
    headers     = {},
}

_G.ngx = {
    var = setmetatable({}, {
        __index = function(_, k)
            if k == "remote_addr" then return stub.remote_addr end
            return nil
        end,
    }),
    req = {
        get_headers = function() return stub.headers end,
    },
    time          = function() return 1758000000 end,
    now           = function() return 1758000000 end,
    encode_base64 = function(s) return s end,
    hmac_sha1     = function(_, msg) return msg end,
    log           = function() end,
    ERR = 1, WARN = 2, NOTICE = 3,
}

-- util.lua pulls in resty.redis at load time; nothing here calls it.
package.loaded["resty.redis"] = {}

local util = require "moswaf.util"

-- ------------------------------------------------------------------ harness

local failures, warnings, total = {}, {}, 0

local function check(name, ok, detail)
    total = total + 1
    if ok then
        io.write(".")
    else
        io.write("F")
        failures[#failures + 1] = name .. (detail and ("\n      " .. detail) or "")
    end
end

-- soft: a documented, still-open gap. It is surfaced but does not fail the run, so
-- the suite stays green in CI while the gap is not forgotten. Promote to check()
-- once it is fixed.
local function soft(name, ok, detail)
    total = total + 1
    if ok then
        io.write(".")
    else
        io.write("w")
        warnings[#warnings + 1] = name .. (detail and ("\n      " .. detail) or "")
    end
end

local function eq(name, got, want)
    check(name, got == want, string.format("got %s, want %s", tostring(got), tostring(want)))
end

-- ------------------------------------------------------------------ ipv4_to_int

eq("ipv4_to_int: ordinary address", util.ipv4_to_int("192.168.1.1"), 3232235777)
eq("ipv4_to_int: zero", util.ipv4_to_int("0.0.0.0"), 0)
eq("ipv4_to_int: broadcast", util.ipv4_to_int("255.255.255.255"), 4294967295)
eq("ipv4_to_int: octet over 255 rejected", util.ipv4_to_int("256.1.1.1"), nil)
eq("ipv4_to_int: not an address", util.ipv4_to_int("not-an-ip"), nil)
eq("ipv4_to_int: IPv6 rejected", util.ipv4_to_int("2001:db8::1"), nil)

-- ------------------------------------------------------------------ normalize_ip
--
-- ipv4_to_int still parses "01.2.3.4" and "1.2.3.4" to the same integer, so they
-- match the same CIDR. The identity problem was that bans and rate-limit counters
-- key on the raw string, giving one host many keys. normalize_ip (added in PR #5)
-- is what closes that: every key must go through it first.

eq("normalize_ip: zero-padded octets collapse", util.normalize_ip("010.000.000.007"), "10.0.0.7")
eq("normalize_ip: already canonical is unchanged", util.normalize_ip("10.0.0.7"), "10.0.0.7")
eq("normalize_ip: surrounding whitespace trimmed", util.normalize_ip("  1.2.3.4  "), "1.2.3.4")
eq("normalize_ip: IPv4 port stripped", util.normalize_ip("1.2.3.4:5678"), "1.2.3.4")
eq("normalize_ip: IPv6 brackets stripped", util.normalize_ip("[2001:db8::1]:443"), "2001:db8::1")
eq("normalize_ip: octet over 255 rejected", util.normalize_ip("999.1.1.1"), nil)
eq("normalize_ip: empty input", util.normalize_ip(""), nil)

-- Fixed in PR #7: IPv6 is rewritten into the single form of RFC 5952, so every
-- spelling of a host is one ban and counter key.
eq("normalize_ip: IPv6 loopback canonical form", util.normalize_ip("0:0:0:0:0:0:0:1"), "::1")
eq("normalize_ip: IPv6 leading zeros dropped",
    util.normalize_ip("2001:0db8:0000:0000:0000:0000:0000:0001"), "2001:db8::1")
eq("normalize_ip: IPv6 uppercase lowered", util.normalize_ip("2001:DB8::1"), "2001:db8::1")
eq("normalize_ip: IPv6 zone index dropped", util.normalize_ip("fe80::1%eth0"), "fe80::1")
eq("normalize_ip: IPv6 all zeros", util.normalize_ip("0:0:0:0:0:0:0:0"), "::")
eq("normalize_ip: IPv4-mapped IPv6 folded into groups",
    util.normalize_ip("::ffff:1.2.3.4"), util.normalize_ip("::ffff:102:304"))
eq("normalize_ip: malformed IPv6 group rejected", util.normalize_ip("2001:db8::gggg"), nil)
eq("normalize_ip: too many IPv6 groups rejected",
    util.normalize_ip("1:2:3:4:5:6:7:8:9"), nil)

check("normalize_ip: IPv6 forms collapse to one key",
    util.normalize_ip("::1") == util.normalize_ip("0:0:0:0:0:0:0:1"),
    "::1 and 0:0:0:0:0:0:0:1 are the same host but normalize_ip returns each " ..
    "verbatim, so an IPv6 client still gets two ban/counter keys")

-- ------------------------------------------------------- challenge redirect

-- The verify endpoint redirects to wherever ?r= points once the proof of work is
-- accepted. Checking only for a leading "/" and a second character that is not "/"
-- left "/\\evil.example" through, which browsers read as protocol-relative and
-- follow off-site: the challenge became an open redirect.
check("redirect: ordinary path accepted", util.is_local_path("/products?id=1"))
check("redirect: root accepted", util.is_local_path("/"))
check("redirect: protocol-relative // rejected", not util.is_local_path("//evil.example"))
check("redirect: backslash form rejected", not util.is_local_path("/\\evil.example"))
check("redirect: absolute URL rejected", not util.is_local_path("https://evil.example"))
check("redirect: scheme anywhere rejected", not util.is_local_path("/redir?u=https://evil.example"))
check("redirect: newline rejected", not util.is_local_path("/ok\nLocation: https://evil.example"))
check("redirect: empty rejected", not util.is_local_path(""))
check("redirect: non-string rejected", not util.is_local_path(nil))

-- ------------------------------------------------------------------ parse_cidr

local from, to = util.parse_cidr("10.0.0.0/8")
eq("parse_cidr: /8 start", from, 167772160)
eq("parse_cidr: /8 end", to, 184549375)

from, to = util.parse_cidr("192.168.1.100")
eq("parse_cidr: bare address is a /32", from, to)

from = util.parse_cidr("10.0.0.0/33")
eq("parse_cidr: prefix over 32 rejected", from, nil)

from, to = util.parse_cidr("0.0.0.0/0")
eq("parse_cidr: /0 covers everything (start)", from, 0)
eq("parse_cidr: /0 covers everything (end)", to, 4294967295)

-- ------------------------------------------------------------------ ip_in_list

check("ip_in_list: inside the range", util.ip_in_list("10.1.2.3", { "10.0.0.0/8" }) == true)
check("ip_in_list: outside the range", util.ip_in_list("11.1.2.3", { "10.0.0.0/8" }) == false)
check("ip_in_list: empty list", util.ip_in_list("10.1.2.3", {}) == false)
check("ip_in_list: exact IPv6 match", util.ip_in_list("2001:db8::1", { "2001:db8::1" }) == true)

-- ------------------------------------------------------------------ client_ip

local function client_ip(peer, headers, settings)
    stub.remote_addr = peer
    stub.headers = headers or {}
    return util.client_ip(settings)
end

eq("client_ip: no real_ip_header configured -> use the peer",
    client_ip("203.0.113.10", { ["X-Forwarded-For"] = "1.2.3.4" }, { real_ip_header = "" }),
    "203.0.113.10")

eq("client_ip: header configured but absent -> use the peer",
    client_ip("203.0.113.10", {}, {
        real_ip_header = "X-Forwarded-For", trusted_proxies = { "203.0.113.0/24" },
    }),
    "203.0.113.10")

eq("client_ip: peer outside the trusted list -> ignore the header",
    client_ip("198.51.100.7", { ["X-Forwarded-For"] = "1.2.3.4" }, {
        real_ip_header = "X-Forwarded-For", trusted_proxies = { "203.0.113.0/24" },
    }),
    "198.51.100.7")

-- An empty trusted list must NOT mean "trust everyone". The header cannot be
-- believed when there is no way to tell our own proxies from a forged hop.
eq("client_ip: empty trusted list falls back to the peer",
    client_ip("198.51.100.7", { ["X-Forwarded-For"] = "1.2.3.4" }, {
        real_ip_header = "X-Forwarded-For", trusted_proxies = {},
    }),
    "198.51.100.7")

-- The load-bearing case (finding #6b, fixed in PR #5). A CDN *appends* to
-- X-Forwarded-For, so with a real client at 198.51.100.7 behind a trusted proxy at
-- 203.0.113.10 the header reads
--     <whatever the client sent>, 198.51.100.7
-- Reading right to left, skipping the trusted hop, yields the real client. Reading
-- left to right (the old bug) would return the attacker-supplied "1.2.3.4".
eq("client_ip: XFF is read right to left, skipping trusted hops",
    client_ip("203.0.113.10", {
        ["X-Forwarded-For"] = "1.2.3.4, 198.51.100.7",
    }, {
        real_ip_header  = "X-Forwarded-For",
        trusted_proxies = { "203.0.113.0/24" },
    }),
    "198.51.100.7")

-- The spoofed entry must not win even when several trusted proxies are chained.
eq("client_ip: real client survives a chain of trusted proxies",
    client_ip("203.0.113.10", {
        ["X-Forwarded-For"] = "1.2.3.4, 198.51.100.7, 203.0.113.20, 203.0.113.10",
    }, {
        real_ip_header  = "X-Forwarded-For",
        trusted_proxies = { "203.0.113.0/24" },
    }),
    "198.51.100.7")

-- A zero-padded forgery is normalised, so it cannot become a second identity.
eq("client_ip: forged hop is normalised, not taken verbatim",
    client_ip("203.0.113.10", {
        ["X-Forwarded-For"] = "1.2.3.4, 010.000.000.007",
    }, {
        real_ip_header  = "X-Forwarded-For",
        trusted_proxies = { "203.0.113.0/24" },
    }),
    "10.0.0.7")

-- ------------------------------------------------------------------ const_eq

check("const_eq: equal strings", util.const_eq("abc123", "abc123") == true)
check("const_eq: different strings", util.const_eq("abc123", "abc124") == false)
check("const_eq: different lengths", util.const_eq("abc", "abcd") == false)
check("const_eq: non-string input", util.const_eq(nil, "abc") == false)

-- ------------------------------------------------------------------ is_private_ip

check("is_private_ip: 10/8", util.is_private_ip("10.1.2.3") == true)
check("is_private_ip: 192.168/16", util.is_private_ip("192.168.1.1") == true)
check("is_private_ip: 172.16/12", util.is_private_ip("172.16.0.1") == true)
check("is_private_ip: 172.32 is public", util.is_private_ip("172.32.0.1") == false)
check("is_private_ip: public address", util.is_private_ip("8.8.8.8") == false)

-- ------------------------------------------------------------------ report

io.write("\n\n")

if #warnings > 0 then
    print(string.format("%d known gap(s) (not failing the run):", #warnings))
    for _, w in ipairs(warnings) do
        print("  ~ " .. w)
    end
    print("")
end

if #failures == 0 then
    print(string.format("%d/%d checks passed (%d warning(s))", total - #warnings, total, #warnings))
    os.exit(0)
end

print(string.format("%d of %d checks FAILED:\n", #failures, total))
for _, f in ipairs(failures) do
    print("  - " .. f)
end
os.exit(1)
