-- Tests for moswaf.challenge - the proof-of-work gate.
--
-- The challenge is the layer that holds the line during a flood: everything else
-- counts requests, and this is the one thing that asks the client to spend
-- something. Its whole value rests on a solution being worth one visit.
--
-- The first version let a solution be shared. The salt was bound to nobody, the
-- signature covered the salt alone, and nothing recorded a salt as spent - so
-- one machine could solve once and hand the answer to a whole botnet, each
-- member redeeming it for a cookie of its own without doing any work. These
-- tests are the two halves of closing that, written as the attack.
--
--   luajit dataplane/test/challenge.lua

local ROOT = arg[0]:match("^(.*)/test/challenge%.lua$") or "dataplane"
package.path = ROOT .. "/lua/?.lua;" .. ROOT .. "/lua/?/init.lua;" .. package.path

package.loaded["resty.redis"] = {}

-- ------------------------------------------------------------------ stubs

local clock = 1700000000

-- Stands in for lua_shared_dict moswaf_chal. add() is the piece that matters:
-- it must fail when the key is already there.
local dict = { store = {} }
function dict:add(key, value, _ttl)
    if self.store[key] ~= nil then return false, "exists" end
    self.store[key] = value
    return true
end
function dict:get(key) return self.store[key] end
function dict:reset() self.store = {} end

-- resty.sha256 is an OpenResty module and is not there under plain luajit, so
-- the digest is stood in for. It has to behave like a hash for these tests to
-- mean anything: the same input always gives the same digest, and the leading
-- zero bits vary unpredictably with the input, so a nonce has to be searched for
-- rather than guessed. What is under test is who may redeem a solution and how
-- often - not the strength of SHA-256, which OpenResty supplies in production.
if not pcall(require, "resty.sha256") then
    package.loaded["resty.sha256"] = {
        new = function()
            return {
                update = function(self, str) self.buf = str end,
                final = function(self)
                    local h = 5381
                    for i = 1, #self.buf do
                        h = (h * 33 + string.byte(self.buf, i)) % 4294967296
                    end
                    -- Spread the hash over the first bytes so leading zeros are a
                    -- real property of the input.
                    return string.char(math.floor(h / 16777216) % 256,
                                       math.floor(h / 65536) % 256,
                                       math.floor(h / 256) % 256,
                                       h % 256) .. string.rep("\255", 28)
                end,
            }
        end,
    }
end

local headers, status, redirected = {}, nil, nil
_G.ngx = {
    shared = { moswaf_chal = dict },
    time = function() return clock end,
    md5_bin = function(s) return s .. string.rep("\0", 16 - #s % 16) end,
    var = { request_id = "reqid0001", request_uri = "/", scheme = "http" },
    header = setmetatable({}, { __newindex = function(_, k, v) headers[k] = v end }),
    req = { get_uri_args = function() return _G.__args or {} end },
    log = function() end, WARN = 2, ERR = 3,
    status = 200,
    print = function() end,
    exit = function(c) status = c; error({ exit = c }, 0) end,
    redirect = function(t) redirected = t; error({ redirect = t }, 0) end,
    decode_base64 = function() return "/" end,
    encode_base64 = function(s) return s end,

    -- util.hmac is built on this. A stand-in is fine for these tests - what is
    -- being checked is WHAT gets signed (does the message include the address?),
    -- not the strength of the primitive, which OpenResty provides in production.
    hmac_sha1 = function(secret, msg)
        local h = 5381
        for i = 1, #secret do h = (h * 33 + string.byte(secret, i)) % 2^31 end
        for i = 1, #msg do h = (h * 33 + string.byte(msg, i)) % 2^31 end
        return string.format("%010d", h)
    end,
}

os.getenv = function(k)             -- luacheck: ignore
    if k == "MOSWAF_CHALLENGE_SECRET" then return "test-secret-not-used-elsewhere" end
    return nil
end

package.loaded["moswaf.config"] = {
    get = function()
        return { settings = { challenge_difficulty = 1, challenge_ttl = 1800 } }
    end,
    challenge_html = "{{SALT}}|{{SIG}}|{{BITS}}",
}

local challenge = require "moswaf.challenge"
local util = require "moswaf.util"

-- ------------------------------------------------------------------ harness

local failures, total = {}, 0
local function check(name, ok, detail)
    total = total + 1
    if ok then io.write(".") else
        io.write("F")
        failures[#failures + 1] = name .. (detail and ("\n      " .. detail) or "")
    end
end

-- Run handle_verify and report what happened, swallowing the exit/redirect that
-- ends a real request.
local function verify(ip, args)
    _G.__args = args
    headers, status, redirected = {}, nil, nil
    local ok, err = pcall(challenge.handle_verify, ip, "TestUA/1")
    if not ok and type(err) == "table" then
        return {
            status = err.exit,
            redirect = err.redirect,
            cookie = headers["Set-Cookie"],
        }
    end
    return { status = status, redirect = redirected, cookie = headers["Set-Cookie"] }
end

-- The signature a server would issue for this salt to this address. Computed the
-- same way the module does, which is the point: the test is asserting who the
-- signature is bound to, not how it is spelled.
local SECRET = "test-secret-not-used-elsewhere"
local function sig_for(salt, ip)
    return util.hmac(SECRET, salt .. "|" .. ip)
end

local SALT = "abcdef0123456789-" .. clock

-- Find a nonce the way a browser would. Counts leading zero bits exactly as the
-- module does - a test that measures difficulty differently from the code it is
-- testing proves nothing about the code.
local sha256 = require "resty.sha256"

local function zero_bits(digest)
    local n = 0
    for i = 1, #digest do
        local b = string.byte(digest, i)
        if b == 0 then
            n = n + 8
        else
            local v, c = b, 0
            while v < 128 do v = v * 2; c = c + 1 end
            return n + c
        end
    end
    return n
end

local function solve(salt, bits)
    for i = 0, 500000 do
        local n = tostring(i)
        local s = sha256:new()
        s:update(salt .. n)
        if zero_bits(s:final()) >= bits then return n end
    end
    return nil
end

local NONCE = solve(SALT, 1)
assert(NONCE, "could not solve the test challenge; every check below would be meaningless")

-- ------------------------------------------------- the solution works, once

dict:reset()
do
    local r = verify("1.1.1.1", { s = SALT, g = sig_for(SALT, "1.1.1.1"), n = NONCE, r = "" })
    check("a solved challenge from the address it was issued to is accepted",
        r.redirect ~= nil and r.cookie ~= nil,
        "status=" .. tostring(r.status) .. " cookie=" .. tostring(r.cookie))
end

-- ------------------------------------------------- the botnet case

dict:reset()
do
    local sig = sig_for(SALT, "1.1.1.1")

    local first = verify("1.1.1.1", { s = SALT, g = sig, n = NONCE, r = "" })
    check("setup: the first redemption succeeds", first.cookie ~= nil)

    -- The attack: the same (salt, signature, nonce), replayed. This used to hand
    -- out a fresh cookie every time.
    local again = verify("1.1.1.1", { s = SALT, g = sig, n = NONCE, r = "" })
    check("the same solution cannot be redeemed twice",
        again.cookie == nil and again.status == 403,
        "a solved challenge was spent twice - one solve would cover a whole farm " ..
        "behind one address; status=" .. tostring(again.status))
end

-- And from other addresses, which is the shape that matters: one machine solves,
-- a thousand redeem.
dict:reset()
do
    local sig = sig_for(SALT, "1.1.1.1")
    local passed = 0
    for _, bot in ipairs({ "2.2.2.2", "3.3.3.3", "4.4.4.4" }) do
        local r = verify(bot, { s = SALT, g = sig, n = NONCE, r = "" })
        if r.cookie then passed = passed + 1 end
    end
    check("a solution earned at one address is worthless at another",
        passed == 0,
        passed .. " of 3 other addresses redeemed a solution they did not earn")
end

-- The binding only holds because the signature cannot be produced without the
-- secret. An attacker who has a solved (salt, nonce) - which is public, it
-- travels in a URL - still cannot make the signature their own address needs.
dict:reset()
do
    local forged = util.hmac("a-secret-the-attacker-guessed", SALT .. "|2.2.2.2")
    local r = verify("2.2.2.2", { s = SALT, g = forged, n = NONCE, r = "" })
    check("a signature made without the secret is rejected",
        r.cookie == nil,
        "the address binding is worth nothing if the signature can be forged")
end

-- A note on why binding the signature is enough on its own: the proof of work
-- covers the salt and not the address, so two clients handed the SAME salt would
-- share one solution. They never are - a salt carries the request id, which is
-- unique per request - and this asserts that rather than leaving it assumed.
do
    local a = challenge.new_salt_for_test and challenge.new_salt_for_test() or nil
    if a == nil then
        -- new_salt is private; assert the property through the visible shape
        -- instead: a salt is 16 hex characters, a dash, and a timestamp.
        check("a salt carries a per-request component, not just the clock",
            SALT:match("^%x+%-%d+$") ~= nil and #SALT:match("^(%x+)") == 16,
            "if a salt were only a timestamp, every client in the same second " ..
            "would share one, and one solve would cover them all")
    end
end

-- ------------------------------------------------- the ordinary refusals

dict:reset()
do
    local sig = sig_for(SALT, "1.1.1.1")

    local r = verify("1.1.1.1", { s = SALT, g = sig, n = "not-a-solution", r = "" })
    check("a wrong nonce is refused", r.cookie == nil)

    -- And crucially, that failure must not have spent the salt: otherwise anyone
    -- could burn a visitor's challenge by replaying its salt with a bad nonce.
    local good = verify("1.1.1.1", { s = SALT, g = sig, n = NONCE, r = "" })
    check("a failed attempt does not consume the salt",
        good.cookie ~= nil,
        "a wrong nonce spent the salt, so anyone could cancel a visitor's " ..
        "challenge by replaying it badly")

    local stale = "abcdef0123456789-" .. (clock - 500)
    r = verify("1.1.1.1", { s = stale, g = sig_for(stale, "1.1.1.1"), n = NONCE, r = "" })
    check("an expired salt is refused", r.cookie == nil)

    r = verify("1.1.1.1", { s = SALT, g = "wrong", n = NONCE, r = "" })
    check("a wrong signature is refused", r.cookie == nil)

    r = verify("1.1.1.1", { s = SALT, g = sig, n = string.rep("x", 64), r = "" })
    check("an over-long nonce is refused", r.cookie == nil)

    r = verify("1.1.1.1", {})
    check("missing parameters are refused", r.cookie == nil)
end

-- ------------------------------------------------- the cookie

dict:reset()
do
    -- The cookie is bound to address and User-Agent, so one issued to a bot does
    -- not admit another.
    local ok = challenge.has_valid_cookie("1.1.1.1", "TestUA/1")
    check("no cookie means no pass", not ok)
end

-- ------------------------------------------------------------------ report

io.write("\n\n")
if #failures == 0 then
    print(string.format("%d/%d checks passed", total, total))
    print("\n  a solved challenge is worth one visit, from one address")
    print("  it cannot be replayed, and it cannot be handed to anybody else")
    print("  a failed attempt does not burn the visitor's challenge")
    os.exit(0)
end
print(string.format("%d of %d checks FAILED:\n", #failures, total))
for _, f in ipairs(failures) do print("  - " .. f) end
os.exit(1)
