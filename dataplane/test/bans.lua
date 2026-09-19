-- Tests for the ban listing endpoint.
--
-- One number in it used to be a lie: total was the length of the list returned,
-- so once there were more bans than fit in a page the list was short AND the
-- count agreed with the short list. An operator had no way to know they were
-- looking at part of it.
--
--   luajit dataplane/test/bans.lua

local ROOT = arg[0]:match("^(.*)/test/bans%.lua$") or "dataplane"
package.path = ROOT .. "/lua/?.lua;" .. ROOT .. "/lua/?/init.lua;" .. package.path

package.loaded["resty.redis"] = {}

-- What the host agent has published, and whether it can be reached at all.
--
-- Three states matter and they are not interchangeable: no agent installed (most
-- installations), an agent that has published something, and an agent that exists
-- but whose queue is unreachable right now. The last one is where unban has to
-- refuse rather than half-succeed.
local agent_health, redis_up = nil, true
local applied_set, refused_set, orphan_list = {}, {}, {}
local feed = {}

local NULL = setmetatable({}, { __tostring = function() return "null" end })

local fake_redis = { _q = {} }
function fake_redis:init_pipeline() self._q = {} end
function fake_redis:hgetall(k)
    local t = {}
    if k == "moswaf:kernel_agent" and agent_health then
        for f, v in pairs(agent_health) do t[#t + 1] = f; t[#t + 1] = v end
    end
    self._q[#self._q + 1] = t
end
function fake_redis:lrange(k)
    local t = {}
    if k == "moswaf:kernel_orphans" then
        for i, v in ipairs(orphan_list) do t[i] = v end
    end
    self._q[#self._q + 1] = t
end
function fake_redis:hmget(k, ...)
    local src = (k == "moswaf:kernel_applied") and applied_set or refused_set
    local fields, out = { ... }, {}
    for i = 1, #fields do out[i] = src[fields[i]] or NULL end
    self._q[#self._q + 1] = out
end
function fake_redis:rpush(_, payload) feed[#feed + 1] = payload end
function fake_redis:ltrim() end
function fake_redis:commit_pipeline() return self._q, nil end

local store = {}
local dict = {}
function dict:get(k) return store[k] end
function dict:ttl(k) return store[k] and 600 or nil end
function dict:set(k, v) store[k] = v; return true end
function dict:delete(k) store[k] = nil end
function dict:flush_all() store = {} end
function dict:get_keys(n)
    local out = {}
    for k in pairs(store) do
        out[#out + 1] = k
        if n and n > 0 and #out >= n then break end
    end
    return out
end

_G.ngx = {
    shared = { moswaf_ban = dict, moswaf_conf = dict, moswaf_cnt = dict,
               moswaf_stats = dict, moswaf_flood = dict, moswaf_chal = dict,
               moswaf_locks = dict },
    req = { get_headers = function() return { ["X-MosWAF-Token"] = "t" } end,
            get_uri_args = function() return _G.URI_ARGS or {} end,
            read_body = function() end,
            get_body_data = function() return nil end },
    var = {}, header = {},
    say = function() end, print = function() end,
    exit = function() end, log = function() end,
    time = function() return 1700000000 end, now = function() return 1700000000 end,
    ERR = 1, WARN = 2, NOTICE = 3, HTTP_OK = 200,
    encode_base64 = function(s) return s end, hmac_sha1 = function(_, m) return m end,
    status = 200,
    -- rules.lua compiles its signatures against ngx.re at load time; nothing here
    -- runs them, so a stand-in is enough to get the module loaded.
    re = { find = function() return nil end, match = function() return nil end },
    worker = { id = function() return 0 end, count = function() return 1 end },
    timer = { at = function() return true end },
    localtime = function() return "2026-09-19 00:00:00" end,
    unescape_uri = function(s) return s end,
}
os.getenv = function(k)  -- luacheck: ignore
    if k == "MOSWAF_INTERNAL_TOKEN" then return "t" end
    return nil
end

-- cjson is an OpenResty module and is not there under plain luajit. The endpoint
-- only needs it to serialise, and what these tests check is the numbers it puts
-- in - so encode keeps the table instead of turning it into text.
local encoded
package.loaded["cjson.safe"] = {
    -- Returns the table rather than a string, so what gets pushed onto the ban
    -- feed can be read as fields instead of parsed back out of text. Nothing
    -- downstream in these tests treats it as a string.
    encode = function(t) encoded = t; return t end,
    decode = function() return nil end,
}

local util = require "moswaf.util"
util.redis = function()
    if not redis_up then return nil, "connection refused" end
    return fake_redis
end
util.redis_release = function() end

local api = require "moswaf.api"

local failures, total = {}, 0
local function check(name, ok, detail)
    total = total + 1
    if ok then io.write(".") else
        io.write("F")
        failures[#failures + 1] = name .. (detail and ("\n      " .. detail) or "")
    end
end

local function list(n)
    store = {}
    for i = 1, n do dict:set("b:10.0." .. math.floor(i / 256) .. "." .. (i % 256), "auto") end
    encoded = nil
    api.bans()
    return encoded or {}
end

-- Under the page size everything is known, so the count is exact.
do
    local r = list(5)
    check("a short list returns every ban", #r.items == 5)
    check("and reports the real total",     r.total == 5)
    check("and does not claim truncation",  r.truncated == false)
end

-- Over it, the list is cut - and has to say so.
do
    local r = list(1500)
    check("a long list is cut to the page size", #r.items == 1000,
        "returned " .. #r.items)
    check("and says it was cut", r.truncated == true,
        "the list is short and nothing in the answer admits it; an operator " ..
        "reading it has no way to know they are seeing part of the bans")
    check("and does not report a total it cannot know", r.total == nil,
        "total = " .. tostring(r.total) .. ". Reporting the length of the cut " ..
        "list as the total is the bug this test exists for: it does not merely " ..
        "omit information, it states a wrong number that reads as the answer")
    check("shown says how many came back", r.shown == 1000)
end

-- Exactly a page is not truncated, and the boundary is the easy place to be off
-- by one in the direction that lies.
do
    local r = list(1000)
    check("exactly one page is not reported as cut", r.truncated == false)
    check("and its total is exact", r.total == 1000)
end

-- =============================================== what is enforcing each ban
--
-- A ban can be refused in userspace, or discarded by the kernel, or waiting for
-- an agent that has not answered. The dashboard cannot see the kernel - it is on
-- the host, in another process - so these fields are the only way it can tell
-- those apart, and the only failure that really costs anything is reporting a ban
-- as kernel-enforced when it is not: somebody reads that, believes the machine is
-- protected, and stops looking.

local function reset_kernel()
    agent_health, redis_up = nil, true
    applied_set, refused_set, orphan_list, feed = {}, {}, {}, {}
    _G.URI_ARGS = nil
end

do
    reset_kernel()
    local r = list(3)
    for _, it in ipairs(r.items) do
        check("with no agent every ban reports userspace enforcement",
            it.enforcement == "lua" and it.stuck == false,
            "got " .. tostring(it.enforcement))
        break
    end
    check("and the agent is reported absent rather than broken",
        r.kernel_agent and r.kernel_agent.present == false,
        "most installations have no host agent. Reporting one that is down " ..
        "would have somebody debugging a component they never installed")
    check("and no orphan list is invented", r.kernel_orphans == nil)
end

do
    reset_kernel()
    agent_health = { seen_at = "2026-09-19T00:00:00Z", seen_unix = "1700000000",
                     applied = "1", resync_every = "60" }
    applied_set["10.0.0.1"] = "1699999900"
    orphan_list = { "198.51.100.77" }

    local r = list(3)
    local by_ip = {}
    for _, it in ipairs(r.items) do by_ip[it.ip] = it end

    check("a ban the agent confirmed reports kernel enforcement",
        by_ip["10.0.0.1"] and by_ip["10.0.0.1"].enforcement == "kernel")
    check("with the time it took effect",
        by_ip["10.0.0.1"] and by_ip["10.0.0.1"].enforcement_since == 1699999900)
    check("while the others still report userspace only",
        by_ip["10.0.0.2"] and by_ip["10.0.0.2"].enforcement == "lua",
        "one confirmed address must not colour the rest of the page")
    check("the agent is reported present", r.kernel_agent.present == true)
    check("an address the kernel drops with no ban behind it is surfaced",
        r.kernel_orphans and r.kernel_orphans[1] == "198.51.100.77",
        "that address cannot reach the site and appears in no list. Without " ..
        "this it is invisible to everyone including the person it happened to")
    check("and is not counted as a ban",
        r.shown == 3 and r.total == 3,
        "orphans are not bans; counting them would make the numbers disagree " ..
        "with the list they are counting")
end

-- The agent's own call asks for the whole list and must not be enriched: it is
-- reading this to decide what the kernel should hold.
do
    reset_kernel()
    agent_health = { seen_unix = "1700000000", applied = "1", resync_every = "60" }
    store = {}
    dict:set("b:10.0.0.1", "auto")
    _G.URI_ARGS = { limit = "0" }
    encoded = nil
    api.bans()
    local r = encoded or {}
    check("the agent's own full-list call is not told about the kernel",
        r.kernel_agent == nil and r.items[1].enforcement == nil,
        "answering its question with its own last answer, at the cost of a " ..
        "Redis round trip on the one caller that needs none")
    check("but it is still told the list is complete", r.complete == true)
end

-- ========================================================== lifting a ban
--
-- A ban can live in two places and this endpoint has to end it in both. If the
-- kernel step fails, the honest answer is to keep the whole ban: still refused,
-- still listed, still removable, and what the screen says is true.
--
-- The alternative - clear the dict and hope - produces a state nothing in the
-- product can see: the dashboard shows the address as free, the kernel goes on
-- discarding its packets, the address is in no list to retry, and the person it
-- happened to gets a connection that times out with no page and no explanation.

local function unban(ip)
    _G.URI_ARGS = { ip = ip }
    encoded, ngx.status = nil, 200
    api.unban()
    return ngx.status, encoded or {}
end

do
    reset_kernel()
    store = {}; dict:set("b:203.0.113.9", "auto")

    local status, body = unban("203.0.113.9")
    check("with no agent, an unban is the ordinary one", status == 200 and
        body.unbanned == "203.0.113.9")
    check("and says no kernel step was needed", body.kernel_release == "not needed")
    check("and the ban is gone", store["b:203.0.113.9"] == nil)
    check("and nothing was queued", #feed == 0)
end

do
    reset_kernel()
    agent_health = { seen_unix = "1700000000", applied = "1", resync_every = "60" }
    applied_set["203.0.113.9"] = "1699999900"
    store = {}; dict:set("b:203.0.113.9", "auto")

    local status, body = unban("203.0.113.9")
    check("with an agent, the release is queued", status == 200 and #feed == 1 and
        feed[1].op == "release" and feed[1].ip == "203.0.113.9")
    check("and only then is the ban cleared", store["b:203.0.113.9"] == nil)
    check("and the answer says queued, not done",
        body.kernel_release == "queued",
        "the agent removes it in the next moment, not this one. Saying 'done' " ..
        "is the difference between a dashboard that is slightly behind and one " ..
        "that is wrong")
end

-- THE ONE THAT MATTERS.
do
    reset_kernel()
    agent_health = { seen_unix = "1700000000", applied = "1", resync_every = "60" }
    applied_set["203.0.113.9"] = "1699999900"
    store = {}; dict:set("b:203.0.113.9", "auto")

    -- The state is read while Redis is up; the release is attempted after it goes
    -- away. That is the real sequence - nothing warns you in between.
    local saw_agent = require("moswaf.kernelban").kernel_state({ "203.0.113.9" })
    check("the address is known to be in the kernel", saw_agent.applied["203.0.113.9"] ~= nil)

    redis_up = false
    local status, body = unban("203.0.113.9")
    check("an unban that cannot reach the kernel is refused", status == 409,
        "answered " .. tostring(status))
    check("with a code the dashboard can act on",
        body.code == "kernel_unban_failed" and body.still_blocked == true)
    check("AND THE BAN IS LEFT WHOLE", store["b:203.0.113.9"] ~= nil,
        "this is the entire point of the ordering. Clearing the dict here " ..
        "leaves an address the dashboard shows as free while the kernel goes " ..
        "on dropping it - in no list, with no row to press unban on, for as " ..
        "long as the kernel timeout runs")

    -- And once Redis is back, the same call works.
    redis_up = true
    status = unban("203.0.113.9")
    check("and it succeeds once the queue is reachable again", status == 200 and
        store["b:203.0.113.9"] == nil)
end

-- Unbanning everything is one event, not one per address.
do
    reset_kernel()
    agent_health = { seen_unix = "1700000000", applied = "9", resync_every = "60" }
    store = {}
    for i = 1, 9 do dict:set("b:10.0.0." .. i, "auto") end

    local status = unban("*")
    check("releasing everything is a single event", status == 200 and #feed == 1 and
        feed[1].op == "release_all",
        "unbanning all during a flood may be tens of thousands of addresses " ..
        "and the queue is capped. One event per address would silently drop " ..
        "the releases at the far end of exactly the list somebody is clearing")

    reset_kernel()
    agent_health = { seen_unix = "1700000000", applied = "9", resync_every = "60" }
    store = {}
    for i = 1, 9 do dict:set("b:10.0.0." .. i, "auto") end
    redis_up = false
    local s2 = unban("*")
    check("and it too is refused rather than half-done when the queue is gone",
        s2 == 409)
    check("leaving every ban in place", store["b:10.0.0.1"] ~= nil)
end

io.write("\n")
if #failures > 0 then
    io.write("\n", #failures, " of ", total, " checks failed:\n")
    for _, f in ipairs(failures) do io.write("  - ", f, "\n") end
    os.exit(1)
end
io.write(total, " checks passed\n")
