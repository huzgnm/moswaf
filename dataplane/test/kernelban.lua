-- Tests for moswaf.kernelban - the last of the three steps before a kernel drop.
--
-- This is the only part of the firewall that can make a machine unreachable, so
-- most of what follows is about the ways it must refuse to act:
--
--   it must not escalate somebody who was banned and went away
--   it must not escalate the same address twice
--   it must not escalate a private address, whatever it is told
--   it must not escalate when it cannot reach the queue - it must leave things
--     exactly as they were, which is "banned, at this layer"
--
-- The never-drop list that actually matters lives in the host agent, because that
-- is the process that can lock somebody out. The checks here are the ones this
-- side can make cheaply, and their value is that a bad address never enters the
-- queue at all.
--
--   luajit dataplane/test/kernelban.lua

local ROOT = arg[0]:match("^(.*)/test/kernelban%.lua$") or "dataplane"
package.path = ROOT .. "/lua/?.lua;" .. ROOT .. "/lua/?/init.lua;" .. package.path

-- ------------------------------------------------------------------ stubs

-- What was pushed onto the queue, and whether the queue was reachable at all.
local pushed, redis_up = {}, true

local fake_redis = {
    init_pipeline   = function() end,
    rpush           = function(_, _, payload) pushed[#pushed + 1] = payload end,
    ltrim           = function() end,
    commit_pipeline = function() return {}, nil end,
}

package.loaded["resty.redis"] = {}

-- cjson is an OpenResty module; encode keeps the table so the test can read the
-- fields rather than parse them back out of a string.
local encoded = {}
package.loaded["cjson.safe"] = {
    encode = function(t) encoded[#encoded + 1] = t; return "json" end,
    decode = function() return nil end,
}

_G.ngx = {
    time = function() return 1700000000 end,
    log = function() end, ERR = 1, WARN = 2, NOTICE = 3,
    shared = {},
    req = { get_headers = function() return {} end },
    var = {},
    encode_base64 = function(s) return s end,
    hmac_sha1 = function(_, m) return m end,
}

local util = require "moswaf.util"
util.redis = function()
    if not redis_up then return nil, "connection refused" end
    return fake_redis
end
util.redis_release = function() end

local kernelban = require "moswaf.kernelban"

-- A stand-in for the ban counters. Only the two calls kernelban makes.
local counts = {}
local ipset = {
    note_ban_hit = function(ip)
        counts[ip] = (counts[ip] or 0) + 1
        return counts[ip]
    end,
}

-- ---------------------------------------------------------------- harness

local failures, total = {}, 0
local function check(name, ok, detail)
    total = total + 1
    if ok then io.write(".") else
        io.write("F")
        failures[#failures + 1] = name .. (detail and ("\n      " .. detail) or "")
    end
end

local function reset()
    pushed, encoded, counts, redis_up = {}, {}, {}, true
end

local K = kernelban.ESCALATE_AT

-- ======================================================= only the persistent

do
    reset()
    -- Banned, refused once, went away. This is most banned addresses.
    kernelban.note_and_maybe_escalate(ipset, "203.0.113.5", 600)
    check("one request after a ban does not reach the kernel", #pushed == 0,
        "a kernel rule is for traffic that has been told no and is continuing, " ..
        "not for everything that was ever refused")

    -- Still knocking, but not enough yet.
    reset()
    for _ = 1, K - 1 do
        kernelban.note_and_maybe_escalate(ipset, "203.0.113.5", 600)
    end
    check("one short of the threshold still does not", #pushed == 0,
        "queued after " .. (K - 1) .. " hits, threshold is " .. K)

    -- And the one that crosses it.
    local crossed = kernelban.note_and_maybe_escalate(ipset, "203.0.113.5", 600)
    check("the request that crosses the threshold does", #pushed == 1 and crossed == true)
end

-- THE ONE THAT MATTERS FOR COST.
--
-- An address at three hundred hits must queue one request, not two hundred and
-- fifty-one. Queuing per request would add work to the exact path this feature
-- exists to take work off - and it would do it under a flood, which is the only
-- time it happens.
do
    reset()
    for _ = 1, K * 6 do
        kernelban.note_and_maybe_escalate(ipset, "203.0.113.7", 600)
    end
    check("an address well past the threshold is queued exactly once", #pushed == 1,
        "queued " .. #pushed .. " times for one address. Every extra one is work " ..
        "added to the request path during a flood, which is the opposite of what " ..
        "this is for")
end

-- ================================================ addresses that never travel

for _, ip in ipairs({
    "127.0.0.1", "::1",
    "10.0.0.5", "192.168.1.10", "172.16.4.2",   -- private
    "169.254.1.1",                              -- link local
    "fd00::1",                                  -- unique local
}) do
    reset()
    for _ = 1, K do
        kernelban.note_and_maybe_escalate(ipset, ip, 600)
    end
    check("a private address is never queued for a kernel drop: " .. ip,
        #pushed == 0,
        "queued " .. ip .. ". The host agent has its own never-drop list and that " ..
        "is the one that counts, but an address that never enters the queue " ..
        "cannot be mishandled by anything downstream")
end

-- ================================================== nothing fails towards drop

do
    reset()
    redis_up = false
    local ok = true
    for _ = 1, K do
        local _, err = pcall(kernelban.note_and_maybe_escalate, ipset, "203.0.113.9", 600)
        if err ~= nil and type(err) ~= "boolean" then ok = false end
    end
    check("an unreachable queue does not raise", ok)
    check("and queues nothing", #pushed == 0)
end

do
    reset()
    check("a ban with no time left is not escalated",
        kernelban.request_drop("203.0.113.5", 0, "x") == false,
        "a kernel rule with no lifetime is either instantly gone or never gone; " ..
        "neither is what the ban said")
    check("nor one with a negative remainder",
        kernelban.request_drop("203.0.113.5", -5, "x") == false)
    check("nor a missing address",
        kernelban.request_drop(nil, 600, "x") == false)
    check("nor an empty one",
        kernelban.request_drop("", 600, "x") == false)
end

-- ==================================================== what is actually queued

do
    reset()
    kernelban.request_drop("203.0.113.5", 437, "persistent")
    local ev = encoded[1]
    check("the queued request names the address", ev and ev.ip == "203.0.113.5")
    check("and carries the remaining ban time, not a fresh one", ev and ev.ttl == 437,
        "the kernel rule has to expire when the ban does. One duration, one " ..
        "meaning: what the dashboard says about a ban is true of the kernel rule " ..
        "too, and neither outlives the other")
    check("and says what it is", ev and ev.op == "drop")

    reset()
    kernelban.request_release("203.0.113.5")
    check("a release is queued too", encoded[1] and encoded[1].op == "release",
        "lifting a ban in one place and leaving it in the other is the failure " ..
        "the dashboard cannot see: it reports the ban gone while the packets are " ..
        "still being discarded")
end

-- =================================================================== report

io.write("\n")
if #failures > 0 then
    io.write("\n", #failures, " of ", total, " checks failed:\n")
    for _, f in ipairs(failures) do io.write("  - ", f, "\n") end
    os.exit(1)
end
io.write(total, " checks passed\n")
