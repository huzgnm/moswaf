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

-- Nothing here publishes anything back: these tests are about what this side
-- sends and what it concludes from an empty answer, so an agent that has said
-- nothing is the state being modelled.
local fake_redis = {
    init_pipeline   = function() end,
    rpush           = function(_, _, payload) pushed[#pushed + 1] = payload end,
    ltrim           = function() end,
    hgetall         = function() end,
    lrange          = function() end,
    hmget           = function() end,
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

-- A stand-in for the counter dict. Only the three calls kernelban makes, and no
-- expiry: every test that cares about time passes it in explicitly, so a stub
-- clock here would be a second source of truth about when things happened.
local dict = {}
local fake_cnt = {
    get    = function(_, k) return dict[k] end,
    set    = function(_, k, v) dict[k] = v; return true end,
    delete = function(_, k) dict[k] = nil end,
}

local NOW = 1700000000

_G.ngx = {
    time = function() return NOW end,
    log = function() end, ERR = 1, WARN = 2, NOTICE = 3,
    shared = { moswaf_cnt = fake_cnt },
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
    for k in pairs(dict) do dict[k] = nil end
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

-- ============================================== what the dashboard is told
--
-- The dashboard cannot see a kernel rule. It is on the host, in another process,
-- behind a privilege boundary the proxy does not cross - so everything it shows
-- about kernel enforcement it shows because these functions said so.
--
-- Which makes one failure worse than all the others: reporting a ban as enforced
-- in the kernel when it is not. Somebody reads that, believes the machine is
-- protected, and stops looking. Every check below is about a state that must not
-- be rounded up into a more reassuring one.

do
    reset()

    -- Nothing was ever asked for. Most bans, forever.
    local e = kernelban.enforcement("203.0.113.9", {}, NOW)
    check("a ban nobody escalated reports userspace enforcement",
        e.enforcement == "lua" and e.stuck == false)

    -- Asked for, not yet confirmed.
    kernelban.note_and_maybe_escalate(ipset, "203.0.113.9", 600)
    for _ = 1, K - 1 do kernelban.note_and_maybe_escalate(ipset, "203.0.113.9", 600) end
    e = kernelban.enforcement("203.0.113.9", {}, NOW)
    check("an escalation that was queued reports pending, not kernel",
        e.enforcement == "kernel_pending" and e.enforcement_since == NOW,
        "got " .. tostring(e.enforcement) .. ". Pending means asked for; kernel " ..
        "means the agent confirmed it. Collapsing the two would have the " ..
        "dashboard claim protection that was requested and never applied")

    -- Confirmed by the agent.
    e = kernelban.enforcement("203.0.113.9",
        { applied = { ["203.0.113.9"] = NOW - 30 } }, NOW)
    check("once the agent confirms it, it reports kernel",
        e.enforcement == "kernel" and e.enforcement_since == NOW - 30)
    check("and a confirmed drop is never stuck", e.stuck == false)

    -- Refused by the agent's never-drop list.
    e = kernelban.enforcement("203.0.113.9",
        { refused = { ["203.0.113.9"] = "the management address" } }, NOW)
    check("an address the agent refused says so, and says why",
        e.enforcement == "kernel_refused" and
        e.refused_reason == "the management address",
        "a decision must not read as a fault. This one is the agent doing its " ..
        "job - refusing to lock the operator out of their own machine - and " ..
        "reporting it as a stuck escalation would send somebody hunting a bug " ..
        "that is the feature")
    check("and a refusal is not stuck either", e.stuck == false,
        "nothing is waiting; the answer arrived and it was no")
end

-- "I found nothing" and "I could not look" must never be the same answer.
--
-- Every field of kernel_state is empty in both cases. The only thing that tells
-- them apart is `reachable`, and a caller that ignores it concludes there is no
-- kernel at precisely the moment it has lost the ability to know - which is how
-- an unban comes to clear the ban list while the kernel goes on dropping.
do
    reset()
    local s = kernelban.kernel_state({ "203.0.113.5" })
    check("a queue that answered is reachable, even with nothing in it",
        s.reachable == true and s.health == nil)

    redis_up = false
    s = kernelban.kernel_state({ "203.0.113.5" })
    check("a queue that could not be reached says so", s.reachable == false)
    check("and is otherwise indistinguishable from an empty one",
        s.health == nil and next(s.applied) == nil and #s.orphans == 0,
        "which is exactly why the flag has to exist: there is no other field " ..
        "a caller could check")
end

-- stuck: asked for, and the agent has had its chance.
do
    reset()
    for _ = 1, K do kernelban.note_and_maybe_escalate(ipset, "203.0.113.11", 600) end

    local health = { resync_every = "60" }

    -- One reconcile interval is the ordinary case: an event queued just after a
    -- cycle started waits out the rest of it. Calling that stuck would light a
    -- warning on every escalation, and a warning that is always on is off.
    local e = kernelban.enforcement("203.0.113.11", { health = health }, NOW + 90)
    check("an escalation waiting out one reconcile cycle is not stuck",
        e.stuck == false, "90s with a 60s resync is one missed cycle at most")

    e = kernelban.enforcement("203.0.113.11", { health = health }, NOW + 121)
    check("one that has outlived two cycles is", e.stuck == true,
        "the agent has had two full chances and the address is still not in the " ..
        "kernel. Something is wrong and the person reading the page is the one " ..
        "who can fix it")

    -- A very short resync must not make everything look stuck.
    e = kernelban.enforcement("203.0.113.11",
        { health = { resync_every = "1" } }, NOW + 25)
    check("an implausibly short resync interval does not make everything stuck",
        e.stuck == false,
        "the floor exists so a misconfigured interval cannot turn the warning " ..
        "into noise on every row")
end

-- The agent's own state.
do
    reset()
    local s = kernelban.agent_status({}, NOW)
    check("no agent reports absent, not broken", s.present == false,
        "most installations have no host agent at all. Reporting one that is " ..
        "down would have somebody debugging a component they never installed")

    s = kernelban.agent_status({ health = {
        seen_at = "x", seen_unix = tostring(NOW - 10), applied = "42",
        resync_every = "60",
    } }, NOW)
    check("a recent agent is present and not stale",
        s.present == true and s.stale == false and s.applied == 42)
    check("and is not reported as failing", s.failing == false)

    s = kernelban.agent_status({ health = {
        seen_unix = tostring(NOW - 300), applied = "42", resync_every = "60",
    } }, NOW)
    check("an agent that has missed several cycles is stale", s.stale == true)

    -- -1 is the agent saying "I ran and could not read the ban list".
    s = kernelban.agent_status({ health = {
        seen_unix = tostring(NOW), applied = "-1", resync_every = "60",
    } }, NOW)
    check("an agent that ran and failed says so", s.failing == true)
    check("and does not report a negative number of addresses", s.applied == nil,
        "passing -1 through as a count would have the dashboard render '-1 " ..
        "addresses in the kernel', which is not a thing and teaches the reader " ..
        "to distrust the number next to it")
end

-- Releasing, and the marker that must not be cleared early.
do
    reset()
    for _ = 1, K do kernelban.note_and_maybe_escalate(ipset, "203.0.113.13", 600) end
    check("the escalation left a marker", kernelban.pending_since("203.0.113.13") == NOW)

    redis_up = false
    local ok = kernelban.request_release("203.0.113.13")
    check("a release that could not be queued reports failure", ok == false)
    check("and leaves the marker in place",
        kernelban.pending_since("203.0.113.13") == NOW,
        "clearing it on a failed release would leave an address the dashboard " ..
        "thinks nobody ever escalated, while the kernel goes on dropping it - " ..
        "invisible in every list, with no row to press unban on")

    redis_up = true
    ok = kernelban.request_release("203.0.113.13")
    check("a release that was queued clears it", ok == true and
        kernelban.pending_since("203.0.113.13") == nil)
end

-- release_all: one event, not one per address.
do
    reset()
    check("releasing everything is queued", kernelban.request_release_all() == true)
    check("as a single event", #pushed == 1 and encoded[1].op == "release_all",
        "unbanning all during a flood may be tens of thousands of addresses " ..
        "and the queue is capped at ten thousand. One event per address would " ..
        "silently drop the releases at the far end of exactly the list somebody " ..
        "is trying to clear")

    redis_up = false
    check("and reports failure when the queue is unreachable",
        kernelban.request_release_all() == false)
end

-- =================================================================== report

io.write("\n")
if #failures > 0 then
    io.write("\n", #failures, " of ", total, " checks failed:\n")
    for _, f in ipairs(failures) do io.write("  - ", f, "\n") end
    os.exit(1)
end
io.write(total, " checks passed\n")
