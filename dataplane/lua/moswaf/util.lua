-- moswaf.util - shared helpers for the engine
local redis  = require "resty.redis"
local bit    = require "bit"

local sub, find, byte, format = string.sub, string.find, string.byte, string.format
local tonumber, tostring, type = tonumber, tostring, type

local _M = {}

local REDIS_HOST = os.getenv("MOSWAF_REDIS_HOST") or "redis"
local REDIS_PORT = tonumber(os.getenv("MOSWAF_REDIS_PORT") or "6379")
local REDIS_PASS = os.getenv("MOSWAF_REDIS_PASSWORD") or ""

-- ---------------------------------------------------------------- redis

-- lua-resty-redis builds a method per command from a fixed list, and the
-- HyperLogLog commands are not on it: red:pfadd(...) is a nil call, which the
-- flush timer's pcall swallows, so the unique-visitor counts came back as zero
-- with nothing in the log to say why. add_commands generates the missing ones.
-- Called once here rather than per connection; a second call is harmless.
--
-- Guarded because add_commands is itself a recent addition to the library, and
-- because the unit tests stub resty.redis with only the handful of methods they
-- need - an unguarded call made every Lua suite fail to load.
if type(redis.add_commands) == "function" then
    redis.add_commands("pfadd", "pfcount", "pfmerge")
end

function _M.redis()
    local red = redis:new()
    red:set_timeouts(1000, 1000, 1000)
    local ok, err = red:connect(REDIS_HOST, REDIS_PORT)
    if not ok then
        return nil, "connect: " .. tostring(err)
    end
    if REDIS_PASS ~= "" and red:get_reused_times() == 0 then
        local ok2, err2 = red:auth(REDIS_PASS)
        if not ok2 then
            red:close()
            return nil, "auth: " .. tostring(err2)
        end
    end
    return red
end

function _M.redis_release(red)
    if not red then return end
    -- return it to the pool instead of closing, so we avoid a fresh handshake each time
    local ok = red:set_keepalive(30000, 64)
    if not ok then pcall(function() red:close() end) end
end

-- ---------------------------------------------------------------- IP

-- "1.2.3.4" -> a 32 bit integer, or nil when it is not IPv4
-- A zero-padded octet is not the address it looks like.
--
-- "01.2.3.4" reads as 1.2.3.4 here but as an octal literal to some resolvers and
-- as an error to others, so accepting it means agreeing with nobody in
-- particular. What makes it matter is that a blocklist and the thing it is
-- compared against must never disagree about which host a string names: one
-- spelling accepted here and refused elsewhere is a ban written around by adding
-- a zero.
local function octet(s)
    if #s > 1 and s:sub(1, 1) == "0" then return nil end
    local n = tonumber(s)
    if not n or n > 255 then return nil end
    return n
end

function _M.ipv4_to_int(ip)
    local a, b, c, d = ip:match("^(%d+)%.(%d+)%.(%d+)%.(%d+)$")
    if not a then return nil end
    a, b, c, d = octet(a), octet(b), octet(c), octet(d)
    if not a or not b or not c or not d then return nil end
    return a * 16777216 + b * 65536 + c * 256 + d
end

-- Parse "10.0.0.0/8" or "1.2.3.4" into an integer {from, to} range.
--
-- Strict, and deliberately stricter than it needs to be for the callers it has
-- today. Everything currently reaching here has already been through Go's own
-- parser and been rewritten in canonical form, so the loose spellings never
-- arrive - but "no caller passes it" is a property of today's callers, not of
-- this function, and the one that would matter is quiet: "1.2.3.4/00" read as a
-- prefix length of zero is every address on the internet. Behind an allow rule
-- that is the firewall switched off, entered as a typo.
--
-- So a mask with a leading zero is refused rather than read as decimal, the same
-- way a padded octet is, and for the same reason: a spelling this accepts and
-- another parser refuses is a difference of opinion about which hosts a string
-- names.
function _M.parse_cidr(cidr)
    local addr, bits = cidr:match("^([%d%.]+)/(%d+)$")
    if not addr then
        local n = _M.ipv4_to_int(cidr)
        if not n then return nil end
        return n, n
    end
    if #bits > 1 and bits:sub(1, 1) == "0" then return nil end
    local base = _M.ipv4_to_int(addr)
    bits = tonumber(bits)
    if not base or not bits or bits < 0 or bits > 32 then return nil end
    if bits == 0 then return 0, 4294967295 end
    local size = 2 ^ (32 - bits)
    local from = base - (base % size)
    return from, from + size - 1
end

-- "::ffff:1.2.3.4" is 1.2.3.4. Fold it, or the host has two identities.
--
-- A dual-stack socket hands every IPv4 client to the application in this form,
-- and an X-Forwarded-For header can carry it whatever the socket is. Without
-- folding, the two spellings never meet: ipv4_to_int rejects the mapped form for
-- containing a colon, ipv6_groups rejects the dotted form for having two groups,
-- so a blocklist entry of 1.2.3.4 matches one of them and not the other. That is
-- an address ban walked around by writing the address differently - the same
-- class as zero-padded IPv4 octets and uncompressed IPv6, one layer further down.
--
-- Only ::ffff:0:0/96 is folded. The deprecated IPv4-compatible form (::1.2.3.4)
-- deliberately is not: ::1 is the IPv6 loopback, and folding that shape would
-- turn it into 0.0.0.1, inventing an address nobody wrote.
function _M.unmap_ipv4(v)
    local g = _M.ipv6_groups(v)
    if not g then return nil end
    if g[1] ~= 0 or g[2] ~= 0 or g[3] ~= 0 or g[4] ~= 0 or g[5] ~= 0 or g[6] ~= 0xffff then
        return nil
    end
    return format("%d.%d.%d.%d",
        math.floor(g[7] / 256), g[7] % 256,
        math.floor(g[8] / 256), g[8] % 256)
end

-- One entry from a list, in whichever family it really belongs to. A mapped
-- prefix is an IPv4 prefix: ::ffff:1.2.3.0/120 covers exactly 1.2.3.0/24.
local function unmap_entry(item)
    local addr, bits = item:match("^(.+)/(%d+)$")
    if not addr then
        return _M.unmap_ipv4(item) or item
    end
    local v4 = _M.unmap_ipv4(addr)
    bits = tonumber(bits)
    if not v4 or not bits or bits < 96 then return item end
    return v4 .. "/" .. (bits - 96)
end

-- Does an IPv6 address fall inside a prefix?
--
-- Compared group by group rather than as one number: an IPv6 address is 128 bits
-- and Lua numbers are doubles, so anything that turns the whole address into a
-- single value loses the low half silently - and losing the low half is exactly
-- what makes two different hosts look like the same one.
function _M.ipv6_in_prefix(ip, prefix, bits)
    local a = _M.ipv6_groups(ip)
    local b = _M.ipv6_groups(prefix)
    if not a or not b then return false end
    if bits < 0 or bits > 128 then return false end

    local full = math.floor(bits / 16)
    for i = 1, full do
        if a[i] ~= b[i] then return false end
    end

    local rest = bits % 16
    if rest > 0 then
        local shift = 2 ^ (16 - rest)
        if math.floor(a[full + 1] / shift) ~= math.floor(b[full + 1] / shift) then
            return false
        end
    end
    return true
end

-- list: an array of CIDR/IP strings, already normalised by the control plane
--
-- IPv6 entries used to be compared as strings, so a prefix in the list matched
-- nothing at all: adding 2001:db8::/32 to the blocklist blocked one address that
-- was literally spelled "2001:db8::/32", which is no address. An operator who
-- blocked a /64 got silence rather than an error, and believed the range was
-- blocked.
function _M.ip_in_list(ip, list)
    if not list or #list == 0 then return false end

    -- Fold before comparing, on both sides: the address being tested and every
    -- entry it is tested against can each be written in the mapped form.
    ip = _M.unmap_ipv4(ip) or ip

    local n = _M.ipv4_to_int(ip)
    local v6 = (not n) and _M.ipv6_groups(ip) or nil

    for i = 1, #list do
        local original = list[i]
        local item = unmap_entry(original)

        if n then
            local from, to = _M.parse_cidr(item)
            if from and n >= from and n <= to then return true, original end
        elseif v6 then
            local prefix, bits = item:match("^(.+)/(%d+)$")
            if prefix then
                if _M.ipv6_in_prefix(ip, prefix, tonumber(bits)) then return true, original end
            elseif _M.normalize_ip(item) == _M.normalize_ip(ip) then
                -- Compared in canonical form: 2001:db8::1 and 2001:0db8:0:0:0:0:0:1
                -- are one host, and a blocklist that disagrees is a blocklist that
                -- can be stepped around by writing the address differently.
                return true, original
            end
        end

        if item == ip then return true, original end
    end
    return false
end

-- Is this address one that no stranger on the internet can be arriving from?
--
-- The name says "private", but the question it has to answer is wider than RFC
-- 1918: it is "could a real visitor legitimately have this address". Loopback,
-- link-local, carrier NAT space and multicast are all "no" for different reasons,
-- and every one of them is an address that should never be acted on as if it
-- were a visitor.
--
-- It used to cover four IPv4 ranges and answer "no" to every IPv6 address at all,
-- because it parsed as IPv4 and gave up when that failed. That was enough while
-- nothing depended on it. It is not enough for deciding what may be dropped in
-- the kernel, where "::1 is not private" would mean the machine's own loopback
-- could be queued for a drop.
function _M.is_private_ip(ip)
    if type(ip) ~= "string" then return false end

    local n = _M.ipv4_to_int(_M.unmap_ipv4(ip) or ip)
    if n then
        return (n <= 16777215)                         -- 0.0.0.0/8, "this network"
            or (n >= 167772160  and n <= 184549375)    -- 10/8
            or (n >= 1681915904 and n <= 1686110207)   -- 100.64/10, carrier NAT
            or (n >= 2130706432 and n <= 2147483647)   -- 127/8, loopback
            or (n >= 2851995648 and n <= 2852061183)   -- 169.254/16, link local
            or (n >= 2886729728 and n <= 2887778303)   -- 172.16/12
            or (n >= 3232235520 and n <= 3232301055)   -- 192.168/16
            or (n >= 3758096384)                       -- 224/4 multicast and above
    end

    local g = _M.ipv6_groups(ip)
    if not g then return false end

    -- ::1 and :: - the loopback and the unspecified address.
    local all_zero = true
    for i = 1, 7 do
        if g[i] ~= 0 then all_zero = false break end
    end
    if all_zero and (g[8] == 0 or g[8] == 1) then return true end

    if g[1] >= 0xfe80 and g[1] <= 0xfebf then return true end   -- fe80::/10 link local
    if g[1] >= 0xfc00 and g[1] <= 0xfdff then return true end   -- fc00::/7  unique local
    return false
end

-- Canonicalise an address so that one client cannot own several identities.
--
-- "01.2.3.4" and "1.2.3.4" are the same host and match the same CIDR, but as raw
-- strings they are different keys - and bans, the blocklist and the rate-limit
-- counters are all keyed on this string. Padding an octet was enough to walk away
-- from a ban. A port and IPv6 brackets are stripped for the same reason.
-- Rewrite an IPv6 address into the single form of RFC 5952: lowercase, no leading
-- zeros in a group, and the longest run of zero groups collapsed to "::".
--
-- "::1" and "0:0:0:0:0:0:0:1" are the same host written two ways. Returned verbatim
-- they are two different ban and counter keys, which is the same one-host-many-
-- identities problem as a zero-padded IPv4 octet, one layer down.
-- Parse an IPv6 address into its eight 16-bit groups, or nil when it is not one.
--
-- Exposed because prefix matching needs the groups, and because a second parser
-- written next to this one would be a second parser to keep in agreement with
-- it: a blocklist and a canonical form that disagree about what an address is
-- are a way around the blocklist.
function _M.ipv6_groups(v)
    if type(v) ~= "string" then return nil end
    v = v:lower():gsub("%%.*$", "")   -- drop a zone index such as %eth0

    -- An embedded IPv4 tail (::ffff:1.2.3.4) becomes two hex groups
    local head, a, b, c, d = v:match("^(.-)(%d+)%.(%d+)%.(%d+)%.(%d+)$")
    if head then
        a, b, c, d = tonumber(a), tonumber(b), tonumber(c), tonumber(d)
        if a > 255 or b > 255 or c > 255 or d > 255 then return nil end
        v = head .. format("%x:%x", a * 256 + b, c * 256 + d)
    end

    local left, right = v:match("^(.-)::(.*)$")
    local groups = {}

    -- Split one half on ":" WITHOUT skipping empty pieces.
    --
    -- gmatch("[^:]+") was here, and it silently swallowed them: a second "::"
    -- inside a half, a leading ":" or a trailing one simply vanished, so "::ffff:"
    -- parsed as "::ffff" and "1::2::3" - neither of which is an address - each came
    -- back as a perfectly ordinary set of eight groups. A parser that invents an
    -- address out of a string that is not one is the dangerous kind of lenient:
    -- every decision downstream, the blocklist included, is then made about an
    -- address nobody sent.
    local function push(part)
        if part == "" then return true end   -- an empty half either side of "::"
        local start = 1
        while true do
            local sep = part:find(":", start, true)
            local g = sep and part:sub(start, sep - 1) or part:sub(start)
            if g == "" or #g > 4 or not g:match("^%x+$") then return false end
            groups[#groups + 1] = tonumber(g, 16)
            if not sep then return true end
            start = sep + 1
        end
    end

    if left then
        local head_groups = {}
        if not push(left) then return nil end
        for i = 1, #groups do head_groups[i] = groups[i] end

        groups = {}
        if not push(right) then return nil end
        local tail_groups = groups

        local fill = 8 - #head_groups - #tail_groups
        if fill < 0 then return nil end

        groups = {}
        for _, g in ipairs(head_groups) do groups[#groups + 1] = g end
        for _ = 1, fill do groups[#groups + 1] = 0 end
        for _, g in ipairs(tail_groups) do groups[#groups + 1] = g end
    else
        if not push(v) then return nil end
    end

    if #groups ~= 8 then return nil end
    for i = 1, 8 do
        if groups[i] > 0xffff then return nil end
    end
    return groups
end

local function normalize_ipv6(v)
    local groups = _M.ipv6_groups(v)
    if not groups then return nil end

    -- Longest run of zero groups, at least two long, leftmost on a tie
    local best_start, best_len, run_start, run_len = nil, 0, nil, 0
    for i = 1, 9 do
        if i <= 8 and groups[i] == 0 then
            run_start = run_start or i
            run_len = run_len + 1
        else
            if run_len > best_len then best_start, best_len = run_start, run_len end
            run_start, run_len = nil, 0
        end
    end

    local out = {}
    for i = 1, 8 do out[i] = format("%x", groups[i]) end

    if best_len >= 2 then
        local head = table.concat(out, ":", 1, best_start - 1)
        local tail = best_start + best_len <= 8
            and table.concat(out, ":", best_start + best_len, 8) or ""
        return head .. "::" .. tail
    end
    return table.concat(out, ":")
end

function _M.normalize_ip(v)
    if not v or v == "" then return nil end
    v = v:match("^%s*(.-)%s*$")

    local bracketed = v:match("^%[(.+)%]")   -- [2001:db8::1]:443
    if bracketed then v = bracketed end

    local host = v:match("^([%d%.]+):%d+$")  -- 1.2.3.4:5678
    if host then v = host end

    local a, b, c, d = v:match("^(%d+)%.(%d+)%.(%d+)%.(%d+)$")
    if a then
        a, b, c, d = tonumber(a), tonumber(b), tonumber(c), tonumber(d)
        if a > 255 or b > 255 or c > 255 or d > 255 then return nil end
        return format("%d.%d.%d.%d", a, b, c, d)
    end

    if find(v, ":", 1, true) then
        -- An IPv4 client arriving over a dual-stack socket, or named that way in a
        -- forwarded header, is still that IPv4 client. Canonicalise it to the one
        -- form everything else keys on - bans, the counters and both lists - so a
        -- host cannot hold two identities at once.
        local mapped = _M.unmap_ipv4(v)
        if mapped then return mapped end
        return normalize_ipv6(v)
    end
    return nil
end

-- Resolve the real client IP according to the config (a CDN or proxy in front of MosWAF)
--
-- The header has to be read RIGHT to LEFT. Proxies *append* to X-Forwarded-For, so
-- the leftmost entry is whatever the client sent - a value it makes up. Sending
--     X-Forwarded-For: 1.2.3.4
-- through a CDN produces "1.2.3.4, <real client>", and taking the leftmost entry
-- handed the attacker its own identity: bans, the blocklist and the rate-limit
-- counters all keyed on a value it chose per request, even with trusted_proxies
-- configured correctly.
--
-- Correct walk: start at the rightmost entry, skip our own proxies, and the first
-- address that is not one of them is the client.
function _M.client_ip(settings)
    local peer = _M.normalize_ip(ngx.var.remote_addr) or "0.0.0.0"
    local header = settings and settings.real_ip_header
    if not header or header == "" then return peer end

    -- No trusted list means no way to tell our proxies from a forged hop, so the
    -- header cannot be believed at all.
    local trusted = settings.trusted_proxies
    if not trusted or #trusted == 0 then return peer end
    if not _M.ip_in_list(peer, trusted) then return peer end

    local v = ngx.req.get_headers()[header]
    if type(v) == "table" then v = v[#v] end   -- the hop closest to us wins
    if not v or v == "" then return peer end

    local hops = {}
    for part in v:gmatch("[^,]+") do
        local ip = _M.normalize_ip(part)
        if ip then hops[#hops + 1] = ip end
    end
    if #hops == 0 then return peer end

    for i = #hops, 1, -1 do
        if not _M.ip_in_list(hops[i], trusted) then
            return hops[i]
        end
    end

    -- Every hop is one of ours: the leftmost entry is the client the first proxy saw
    return hops[1]
end

-- ---------------------------------------------------------------- strings

local b64u_map = { ["+"] = "-", ["/"] = "_", ["="] = "" }

function _M.b64url(s)
    return (ngx.encode_base64(s):gsub("[%+/=]", b64u_map))
end

function _M.hmac(secret, msg)
    return _M.b64url(ngx.hmac_sha1(secret, msg))
end

function _M.now()
    return ngx.time()
end

function _M.truncate(s, n)
    if not s then return "" end
    s = tostring(s)
    if #s <= n then return s end
    return sub(s, 1, n) .. "..."
end

-- constant time string comparison, to resist timing attacks on the signature
function _M.const_eq(a, b)
    if type(a) ~= "string" or type(b) ~= "string" then return false end
    if #a ~= #b then return false end
    local diff = 0
    for i = 1, #a do
        diff = bit.bor(diff, bit.bxor(byte(a, i), byte(b, i)))
    end
    return diff == 0
end

-- Only a path on this site may be redirected to.
--
-- Checking for a leading "/" and a second character that is not "/" was not enough:
-- browsers read "/\\evil.example" as protocol-relative and follow it off-site, which
-- turns the challenge into an open redirect an attacker can point anywhere. A
-- backslash in that position is rejected now, along with control characters and
-- anything carrying a scheme.
function _M.is_local_path(v)
    if type(v) ~= "string" or v == "" or #v > 2048 then return false end
    if v:sub(1, 1) ~= "/" then return false end

    local second = v:sub(2, 2)
    if second == "/" or second == "\\" then return false end

    if v:find("[%c]") then return false end          -- CR, LF, NUL and friends
    if v:lower():find("://", 1, true) then return false end

    return true
end

function _M.hex(s)
    return (s:gsub(".", function(c) return format("%02x", byte(c)) end))
end

return _M
