-- Tests for moswaf.ja4 - the TLS client fingerprint.
--
-- A fingerprint is only worth anything if it is the SAME one everybody else
-- computes. An implementation that is self-consistent but wrong produces rules
-- that look right, match nothing, and never say why - so the expected values
-- below were produced OUTSIDE this code (sha256 from the shell) rather than by
-- running the thing under test and writing down what it said.
--
-- Built against FoxIO's JA4 specification:
--   https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4.md
--
--   luajit dataplane/test/ja4.lua

local ROOT = arg[0]:match("^(.*)/test/ja4%.lua$") or "dataplane"
package.path = ROOT .. "/lua/?.lua;" .. ROOT .. "/lua/?/init.lua;" .. package.path

-- ------------------------------------------------------------------ stubs

-- What the handshake said. Rewritten per case.
local hello = {}

package.loaded["ngx.ssl.clienthello"] = {
    get_client_hello_ciphers     = function() return hello.ciphers end,
    get_client_hello_ext_present = function() return hello.exts end,
    get_supported_versions       = function() return hello.versions end,
    get_client_hello_ext         = function(t) return hello.raw and hello.raw[t] end,
}

-- resty.sha256 and resty.string are OpenResty modules. SHA-256 is supplied here
-- by a small pure-Lua implementation so the expected values can be the real ones
-- - a stubbed digest would only prove the code is consistent with itself, which
-- is the one thing that does not matter about a fingerprint.
local band, bor, bxor, bnot = bit.band, bit.bor, bit.bxor, bit.bnot
local rshift, lshift, rol = bit.rshift, bit.lshift, bit.rol

local K = {
  0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
  0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
  0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
  0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
  0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
  0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
  0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
  0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2,
}

local function sha256_hex(msg)
    local h = {0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
               0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19}
    local len = #msg
    msg = msg .. "\128" .. string.rep("\0", (55 - len) % 64)
           .. string.rep("\0", 4) .. string.char(
               band(rshift(len * 8, 24), 0xff), band(rshift(len * 8, 16), 0xff),
               band(rshift(len * 8, 8), 0xff), band(len * 8, 0xff))

    for i = 1, #msg, 64 do
        local w = {}
        for j = 0, 15 do
            local a, b, c, d = msg:byte(i + j * 4, i + j * 4 + 3)
            w[j + 1] = bor(lshift(a, 24), lshift(b, 16), lshift(c, 8), d)
        end
        for j = 17, 64 do
            local s0 = bxor(rol(w[j - 15], 25), rol(w[j - 15], 14), rshift(w[j - 15], 3))
            local s1 = bxor(rol(w[j - 2], 15), rol(w[j - 2], 13), rshift(w[j - 2], 10))
            w[j] = band(w[j - 16] + s0 + w[j - 7] + s1, 0xffffffff)
        end
        local a, b, c, d, e, f, g, hh = h[1], h[2], h[3], h[4], h[5], h[6], h[7], h[8]
        for j = 1, 64 do
            local S1 = bxor(rol(e, 26), rol(e, 21), rol(e, 7))
            local ch = bxor(band(e, f), band(bnot(e), g))
            local t1 = band(hh + S1 + ch + K[j] + w[j], 0xffffffff)
            local S0 = bxor(rol(a, 30), rol(a, 19), rol(a, 10))
            local mj = bxor(band(a, b), band(a, c), band(b, c))
            local t2 = band(S0 + mj, 0xffffffff)
            hh, g, f, e = g, f, e, band(d + t1, 0xffffffff)
            d, c, b, a = c, b, a, band(t1 + t2, 0xffffffff)
        end
        h[1] = band(h[1] + a, 0xffffffff); h[2] = band(h[2] + b, 0xffffffff)
        h[3] = band(h[3] + c, 0xffffffff); h[4] = band(h[4] + d, 0xffffffff)
        h[5] = band(h[5] + e, 0xffffffff); h[6] = band(h[6] + f, 0xffffffff)
        h[7] = band(h[7] + g, 0xffffffff); h[8] = band(h[8] + hh, 0xffffffff)
    end
    -- bit.tohex, not string.format("%08x"): LuaJIT's bit operations return a
    -- SIGNED 32-bit result, so any word at or above 2^31 comes out negative and
    -- %x prints it as sixteen f-padded characters instead of eight. The digest
    -- then shifts and every comparison after it is against garbage - which is
    -- exactly what this harness caught on its first run.
    local out = {}
    for i = 1, 8 do out[i] = bit.tohex(h[i]) end
    return table.concat(out)
end

package.loaded["resty.sha256"] = {
    new = function()
        return { update = function(self, s) self.buf = (self.buf or "") .. s end,
                 final  = function(self) return self.buf or "" end }
    end,
}
package.loaded["resty.string"] = {
    to_hex = function(s)
        -- final() above returns the message rather than a digest, so the hashing
        -- happens here. Only this pairing matters; the module under test sees the
        -- same two calls it makes in production.
        return sha256_hex(s)
    end,
}

_G.ngx = { log = function() end, ERR = 1, WARN = 2 }

local ja4 = require "moswaf.ja4"

-- ---------------------------------------------------------------- harness

local failures, total = {}, 0
local function check(name, ok, detail)
    total = total + 1
    if ok then io.write(".") else
        io.write("F")
        failures[#failures + 1] = name .. (detail and ("\n      " .. detail) or "")
    end
end
local function eq(name, got, want, why)
    check(name, got == want,
        "got " .. tostring(got) .. ", want " .. tostring(want) ..
        (why and ("\n      " .. why) or ""))
end

-- ===================================================== the whole fingerprint
--
-- The expected hashes were produced with `shasum -a 256` from the shell, not by
-- this code. That is the whole point: a fingerprint has to agree with every other
-- implementation, and a test that asks the code to confirm itself proves only
-- that it is consistent.
--
--   printf '1301,1302,1303,c02b'         | shasum -a 256  -> 39e807bd56df...
--   printf '000d,0017,002b_0403,0804'    | shasum -a 256  -> f9b7c94aa166...
do
    hello = {
        -- GREASE mixed in, as a real browser sends it
        ciphers  = { 0x0a0a, 0x1301, 0x1302, 0x1303, 0xc02b },
        exts     = { 0x1a1a, 0x0000, 0x0010, 0x000d, 0x002b, 0x0017 },
        versions = { 0x2a2a, 0x0304, 0x0303 },
        raw = {
            [0x0010] = "\0\3\2h2",                        -- ALPN: "h2"
            [0x000d] = "\0\4\4\3\8\4",                    -- sig algs: 0403, 0804
        },
    }
    local fp = ja4.compute()
    eq("the fingerprint matches an independently computed one",
       fp, "t13d0405h2_39e807bd56df_f9b7c94aa166",
       "the two hashes here came from shasum in the shell. If this fails, this " ..
       "implementation disagrees with every other JA4 implementation - rules " ..
       "written against fingerprints from anywhere else would match nothing, " ..
       "and nothing would say why")
end

-- ============================================================ part A pieces

eq("GREASE is left out of the cipher count",
   ja4._count2(4), "04")
eq("a count above ninety-nine is capped",
   ja4._count2(500), "99")
eq("and ninety-nine itself is not",
   ja4._count2(99), "99")

eq("the version comes from supported_versions, highest first",
   ja4._version_string({ 0x0303, 0x0304, 0x0a0a }), "13",
   "0x0a0a is GREASE and must not be read as a version - it is larger than " ..
   "every real one, so taking the maximum without filtering picks the noise")
eq("TLS 1.2 is reported as 12",
   ja4._version_string({ 0x0303 }), "12")
eq("a missing supported_versions means TLS 1.2 here",
   ja4._version_string(nil), "12",
   "this server offers only 1.2 and 1.3, so a client without the extension is " ..
   "a 1.2 client; anything older never completes a handshake")
eq("a version nobody knows is not guessed at",
   ja4._version_string({ 0x9999 }), "00")

-- ------------------------------------------------------------------- ALPN

eq("h2 stays h2",            ja4._alpn_chars("\0\3\2h2"), "h2")
eq("http/1.1 becomes h1",    ja4._alpn_chars("\0\9\8http/1.1"), "h1")
eq("a single character is doubled... or rather is itself twice",
   ja4._alpn_chars("\0\2\1x"), "xx")
eq("no ALPN extension is 00",     ja4._alpn_chars(nil), "00")
eq("an empty ALPN list is 00",    ja4._alpn_chars("\0\0"), "00")
eq("a zero-length first entry is 00", ja4._alpn_chars("\0\1\0"), "00")

-- ------------------------------------------------------- signature algorithms

do
    local s = ja4._sig_algs("\0\6\4\3\8\4\10\10")
    eq("signature algorithms are read in order", table.concat(s, ","), "0403,0804",
       "0x0a0a is GREASE and must be dropped; the rest keep the order they were " ..
       "sent in, which is itself characteristic of the library that sent them")
    eq("no extension means none", #ja4._sig_algs(nil), 0)
end

-- ----------------------------------------------------------------- GREASE

do
    local official = { 0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a,
                       0x8a8a, 0x9a9a, 0xaaaa, 0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa }
    local all = true
    for _, v in ipairs(official) do
        if not ja4._is_grease(v) then all = false end
    end
    check("every reserved GREASE value is recognised", all,
        "a GREASE value counted as a real one changes the fingerprint of every " ..
        "client of that library, and changes it differently per connection")

    local none = true
    for _, v in ipairs({ 0x1301, 0x1302, 0xc02b, 0x0000, 0x0010, 0x000d, 0x002b,
                         0x0a0b, 0x0b0a, 0xabab, 0x0a1a }) do
        if ja4._is_grease(v) then none = false end
    end
    check("and no real value is mistaken for one", none,
        "dropping a real cipher or extension would make two different clients " ..
        "share a fingerprint")
end

-- --------------------------------------------------------------- empty lists

eq("an empty list hashes to zeroes, not to the hash of nothing",
   ja4._hash12(""), "000000000000",
   "\"nothing was sent\" has to look like nothing. The hash of an empty string " ..
   "is an ordinary-looking value that happens always to be the same one, which " ..
   "reads as a real fingerprint")

-- ================================================== SNI and ALPN are excluded

-- The same client talking to two different domains, over two different ALPNs,
-- must produce the same c section - that is the whole reason those two are left
-- out of it.
do
    local function fp_with(sni, alpn_raw)
        local exts = { 0x000d, 0x002b, 0x0017 }
        if sni then table.insert(exts, 0x0000) end
        table.insert(exts, 0x0010)
        hello = {
            ciphers = { 0x1301, 0xc02b },
            exts = exts,
            versions = { 0x0304 },
            raw = { [0x0010] = alpn_raw, [0x000d] = "\0\2\4\3" },
        }
        return ja4.compute()
    end

    local a = fp_with(true, "\0\3\2h2")
    local b = fp_with(false, "\0\9\8http/1.1")
    local ca = a:match("_([^_]+)$")
    local cb = b:match("_([^_]+)$")
    eq("the same client fingerprints the same whatever domain it asked for", ca, cb,
       "SNI and ALPN are deliberately kept out of the third section. If they " ..
       "leak into it, one application produces a different fingerprint per site " ..
       "it visits, and a rule written from one of them matches none of the rest")

    check("but they still change the first section", a:sub(1, 10) ~= b:sub(1, 10),
        "the counts and the ALPN characters live in section a, and they should " ..
        "differ here")
end

-- ============================================== unreadable handshakes stay nil

do
    hello = { ciphers = nil, exts = { 0x000d } }
    local fp = ja4.compute()
    check("a handshake whose ciphers cannot be read has no fingerprint", fp == nil,
        "returned " .. tostring(fp) .. ". A fallback value would become a real " ..
        "fingerprint that matches every client we failed to parse - a group " ..
        "nobody meant to name in a rule")

    hello = { ciphers = { 0x1301 }, exts = nil }
    check("nor one whose extensions cannot be read", ja4.compute() == nil)
end

-- ============================================ a hostile ClientHello is cheap

-- The ClientHello is written by the client and reaches this on every new
-- connection - under a flood, that is every request. A hello stuffed with
-- thousands of ciphers would have us building and sorting thousands of strings
-- before a byte of HTTP has been read.
--
-- No real client offers anything near this many, and the count that reaches the
-- fingerprint is capped at 99 anyway, so there is nothing to lose by stopping.
do
    local many = {}
    for i = 1, 5000 do many[i] = 0x1300 + (i % 200) end
    local manyext = {}
    for i = 1, 5000 do manyext[i] = 0x0100 + (i % 200) end

    hello = {
        ciphers = many,
        exts = manyext,
        versions = { 0x0304 },
        raw = { [0x000d] = string.rep("\4\3", 5000) },
    }

    local t0 = os.clock()
    local ok, fp = pcall(ja4.compute)
    local spent = os.clock() - t0

    check("an absurd ClientHello does not raise", ok, tostring(fp))
    check("and still produces a fingerprint", ok and type(fp) == "string",
        "a hello that cannot be fingerprinted is fine; one that crashes the " ..
        "handshake handler is not")
    check("and is answered quickly", spent < 0.5,
        string.format("took %.3fs. This runs per connection, so an attacker who " ..
        "can make it slow can make every new connection slow", spent))

    -- The same absurd hello twice gives the same answer: whatever the cap does,
    -- it has to be deterministic, or a rule written against it would match only
    -- sometimes.
    local _, fp2 = pcall(ja4.compute)
    check("and the answer is the same every time", fp == fp2)
end

-- =================================================================== report

io.write("\n")
if #failures > 0 then
    io.write("\n", #failures, " of ", total, " checks failed:\n")
    for _, f in ipairs(failures) do io.write("  - ", f, "\n") end
    os.exit(1)
end
io.write(total, " checks passed\n")
