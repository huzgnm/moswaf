-- moswaf.ja4 - the TLS client fingerprint, computed from the ClientHello
--
-- What it is for: telling apart clients that all claim to be the same browser.
-- A user agent is a string anybody can type; the shape of a TLS handshake is
-- decided by the library that made it, so a Python script announcing itself as
-- Chrome still handshakes like Python.
--
-- What it is NOT: proof of who anybody is. The ClientHello is built by the
-- client, so it is something the client chooses - harder to choose than a header,
-- because it takes a library that can imitate one (utls, curl-impersonate), but
-- chosen all the same. That is why a fingerprint may be used to refuse a request
-- and never to exempt one: refusing something an attacker controls costs them an
-- attempt, while exempting it hands them the switch.
--
-- Built to FoxIO's JA4 specification rather than to something of our own, because
-- an invented formula would drift: browsers reshuffle their extensions between
-- releases (which is what broke JA3 and why JA4 sorts them), and a fingerprint
-- that changes when Chrome updates turns an operator's rule into one that quietly
-- stops matching.
--
--   https://github.com/FoxIO-LLC/ja4  (JA4 itself: BSD-3-Clause)

local ssl_clt = require "ngx.ssl.clienthello"
local sha256  = require "resty.sha256"
local str     = require "resty.string"

local _M = {}

local format, byte, sub = string.format, string.byte, string.sub
local concat, sort = table.concat, table.sort

-- How many entries of any one list will be read.
--
-- The ClientHello is written by the client and reaches this on every new
-- connection - which under a flood is every request. A hello stuffed with
-- thousands of ciphers would have us building and sorting thousands of strings
-- before a single byte of HTTP has been read, for a client that is not real: no
-- implementation offers anything near this many, and the count that ends up in
-- the fingerprint is capped at 99 regardless.
--
-- Stopping early changes the fingerprint of such a hello compared with an
-- implementation that reads it all. That is the right trade: the only thing that
-- sends one is something trying to make this expensive, and it should be cheap
-- to answer rather than accurate about.
local MAX_LIST = 256

-- ------------------------------------------------------------------ GREASE
--
-- Values reserved to keep middleboxes honest: a client sprinkles them through
-- its cipher and extension lists precisely so that anything which chokes on an
-- unknown value is found early. They are noise by design and change per
-- connection, so a fingerprint that counted them would differ every time.
--
-- The pattern is 0x?A?A with both nibbles equal - 0x0A0A, 0x1A1A ... 0xFAFA.
local function is_grease(v)
    return (v % 256) == (math.floor(v / 256))    -- high byte == low byte
        and (v % 16) == 10                        -- and both are ?A
end

-- ----------------------------------------------------------------- version

-- Two characters for the highest version the client will accept.
--
-- Read from supported_versions when it is there, because from TLS 1.3 onward the
-- legacy version field is frozen at 1.2 and lies by design.
local VERSION = {
    [0x0304] = "13", [0x0303] = "12", [0x0302] = "11", [0x0301] = "10",
    [0x0300] = "s3", [0x0002] = "s2",
    [0xfeff] = "d1", [0xfefd] = "d2", [0xfefc] = "d3",
}

local function version_string(versions)
    local best
    if type(versions) == "table" then
        for i = 1, #versions do
            local v = versions[i]
            if type(v) == "number" and not is_grease(v) then
                if not best or v > best then best = v end
            end
        end
    end
    if best then return VERSION[best] or "00" end

    -- No supported_versions extension. The specification says to fall back to the
    -- ClientHello's own version field, which OpenResty does not expose - but it
    -- does not need to here: this server offers only TLS 1.2 and 1.3, so a client
    -- that reaches this point without the extension is a TLS 1.2 client. Anything
    -- older is refused by the handshake a moment later and never becomes a request
    -- for a rule to be evaluated against.
    return "12"
end

-- -------------------------------------------------------------------- ALPN

-- The first and last alphanumeric characters of the first protocol offered.
-- "h2" stays "h2"; "http/1.1" becomes "h1".
local function alpn_chars(raw)
    if not raw or #raw < 4 then return "00" end

    -- uint16 list length, then (uint8 length, bytes) repeated. Only the first
    -- entry matters.
    local n = byte(raw, 3)
    if not n or n == 0 or #raw < 3 + n then return "00" end
    local first = sub(raw, 4, 3 + n)
    if #first == 0 then return "00" end

    local function alnum(c)
        local b = byte(c)
        return (b >= 0x30 and b <= 0x39) or (b >= 0x41 and b <= 0x5a)
            or (b >= 0x61 and b <= 0x7a)
    end

    local a, z = sub(first, 1, 1), sub(first, -1)
    if alnum(a) and alnum(z) then
        return a .. z
    end
    -- A protocol name that is not printable is reported through its hex, so that
    -- two different unprintable names do not collapse into the same two
    -- characters.
    local hex = str.to_hex(first)
    return sub(hex, 1, 1) .. sub(hex, -1)
end

-- ------------------------------------------------------- signature algorithms

-- uint16 list length, then uint16 values. Kept in the order they were sent,
-- unlike everything else here, because that order is itself characteristic of
-- the library that produced it.
local function sig_algs(raw)
    local out = {}
    if not raw or #raw < 2 then return out end
    for i = 3, #raw - 1, 2 do
        if #out >= MAX_LIST then break end
        local v = byte(raw, i) * 256 + byte(raw, i + 1)
        if not is_grease(v) then
            out[#out + 1] = format("%04x", v)
        end
    end
    return out
end

-- -------------------------------------------------------------------- hash

-- Twelve characters of SHA-256, lowercase.
--
-- An empty list hashes to twelve zeroes rather than to the hash of an empty
-- string: the specification asks for it, and the reason is legibility - "nothing
-- was sent" should look like nothing, not like an ordinary-looking hash that
-- happens always to be the same one.
local ZERO12 = "000000000000"

local function hash12(s)
    if s == "" then return ZERO12 end
    local h = sha256:new()
    if not h then return ZERO12 end
    h:update(s)
    return sub(str.to_hex(h:final()), 1, 12)
end

-- Two digits, and never more. A client offering more than ninety-nine ciphers is
-- not a client anybody has to distinguish by the exact number.
local function count2(n)
    if n > 99 then return "99" end
    return format("%02d", n)
end

-- ----------------------------------------------------------------- compute

--- Compute the JA4 fingerprint of the handshake now being negotiated.
--
-- Must be called from ssl_client_hello_by_lua. Returns the fingerprint, or nil
-- and a reason - and a missing fingerprint has to stay missing rather than
-- becoming a default, because a rule matching "the fingerprint we use when we
-- could not read one" would match every client whose handshake we failed to
-- parse, which is not a group anybody meant to name.
function _M.compute()
    local ciphers, err = ssl_clt.get_client_hello_ciphers()
    if not ciphers then return nil, err or "no ciphers" end

    local exts, eerr = ssl_clt.get_client_hello_ext_present()
    if not exts then return nil, eerr or "no extensions" end

    -- OpenResty removes GREASE from both of these already; filtered again rather
    -- than trusted, because the count is part of the fingerprint and one extra
    -- entry changes it for every client of that library.
    local cipher_hex = {}
    for i = 1, #ciphers do
        if #cipher_hex >= MAX_LIST then break end
        local c = ciphers[i]
        if not is_grease(c) then cipher_hex[#cipher_hex + 1] = format("%04x", c) end
    end

    local ext_hex, ext_count = {}, 0
    local has_sni = false
    for i = 1, #exts do
        if i > MAX_LIST then break end
        local e = exts[i]
        if not is_grease(e) then
            ext_count = ext_count + 1          -- SNI and ALPN are counted here
            if e == 0x0000 then has_sni = true end
            -- ...but left out of the hash below, because they say where the client
            -- was going rather than what it is. Dropping them is what makes one
            -- application produce the same fingerprint across every domain it
            -- talks to.
            if e ~= 0x0000 and e ~= 0x0010 then
                ext_hex[#ext_hex + 1] = format("%04x", e)
            end
        end
    end

    sort(cipher_hex)
    sort(ext_hex)

    local versions = ssl_clt.get_supported_versions()
    local alpn = alpn_chars(ssl_clt.get_client_hello_ext(0x0010))
    local sigs = sig_algs(ssl_clt.get_client_hello_ext(0x000d))

    local a = "t" .. version_string(versions)
        .. (has_sni and "d" or "i")
        .. count2(#cipher_hex) .. count2(ext_count) .. alpn

    local b = hash12(concat(cipher_hex, ","))

    local c_input = concat(ext_hex, ",")
    if #sigs > 0 then
        c_input = c_input .. "_" .. concat(sigs, ",")
    end
    local c = hash12(c_input)

    return a .. "_" .. b .. "_" .. c
end

-- Exposed for the tests, which drive the pieces directly: the whole of compute()
-- needs a live TLS handshake, and the parts that are worth being wrong about -
-- GREASE, ALPN, the counts, the sort - do not.
_M._is_grease      = is_grease
_M._alpn_chars     = alpn_chars
_M._sig_algs       = sig_algs
_M._version_string = version_string
_M._count2         = count2
_M._hash12         = hash12

return _M
