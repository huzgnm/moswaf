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
function _M.ipv4_to_int(ip)
    local a, b, c, d = ip:match("^(%d+)%.(%d+)%.(%d+)%.(%d+)$")
    if not a then return nil end
    a, b, c, d = tonumber(a), tonumber(b), tonumber(c), tonumber(d)
    if a > 255 or b > 255 or c > 255 or d > 255 then return nil end
    return a * 16777216 + b * 65536 + c * 256 + d
end

-- Parse "10.0.0.0/8" or "1.2.3.4" into an integer {from, to} range
function _M.parse_cidr(cidr)
    local addr, bits = cidr:match("^([%d%.]+)/(%d+)$")
    if not addr then
        local n = _M.ipv4_to_int(cidr)
        if not n then return nil end
        return n, n
    end
    local base = _M.ipv4_to_int(addr)
    bits = tonumber(bits)
    if not base or not bits or bits < 0 or bits > 32 then return nil end
    if bits == 0 then return 0, 4294967295 end
    local size = 2 ^ (32 - bits)
    local from = base - (base % size)
    return from, from + size - 1
end

-- list: an array of CIDR/IP strings, already normalised by the control plane
function _M.ip_in_list(ip, list)
    if not list or #list == 0 then return false end
    local n = _M.ipv4_to_int(ip)
    for i = 1, #list do
        local item = list[i]
        if n then
            local from, to = _M.parse_cidr(item)
            if from and n >= from and n <= to then return true, item end
        end
        if item == ip then return true, item end   -- IPv6 or an exact match
    end
    return false
end

function _M.is_private_ip(ip)
    local n = _M.ipv4_to_int(ip)
    if not n then return false end
    return (n >= 167772160  and n <= 184549375)    -- 10/8
        or (n >= 2886729728 and n <= 2887778303)   -- 172.16/12
        or (n >= 3232235520 and n <= 3232301055)   -- 192.168/16
        or (n >= 2130706432 and n <= 2147483647)   -- 127/8
end

-- Canonicalise an address so that one client cannot own several identities.
--
-- "01.2.3.4" and "1.2.3.4" are the same host and match the same CIDR, but as raw
-- strings they are different keys - and bans, the blocklist and the rate-limit
-- counters are all keyed on this string. Padding an octet was enough to walk away
-- from a ban. A port and IPv6 brackets are stripped for the same reason.
function _M.normalize_ip(v)
    if not v or v == "" then return nil end
    v = v:match("^%s*(.-)%s*$")

    local bracketed = v:match("^%[(.+)%]")   -- [2001:db8::1]:443
    if bracketed then return bracketed end

    local host = v:match("^([%d%.]+):%d+$")  -- 1.2.3.4:5678
    if host then v = host end

    local a, b, c, d = v:match("^(%d+)%.(%d+)%.(%d+)%.(%d+)$")
    if a then
        a, b, c, d = tonumber(a), tonumber(b), tonumber(c), tonumber(d)
        if a > 255 or b > 255 or c > 255 or d > 255 then return nil end
        return format("%d.%d.%d.%d", a, b, c, d)
    end

    if find(v, ":", 1, true) then return v end   -- IPv6
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

function _M.hex(s)
    return (s:gsub(".", function(c) return format("%02x", byte(c)) end))
end

return _M
