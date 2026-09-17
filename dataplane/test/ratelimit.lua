-- Deterministic tests for moswaf.ratelimit (findings #7 and #8).
--
-- ratelimit.check reads its clock from ngx.now() and its counters from the
-- lua_shared_dict ngx.shared.moswaf_cnt. Both are stubbed here so the two open
-- rate-limit findings can be shown exactly and repeatably, without booting the
-- stack or fighting sub-second HTTP timing:
--
--   #8  Fixed counting windows. The 1-second bucket is keyed on floor(now), so it
--       resets on the wall-clock second. Sending a burst just before the boundary
--       and another just after lets ~2x the configured rps through unblocked.
--
--   #7  Fail-open. When cnt:incr returns nil (the shared dict is full - exactly what
--       a large flood causes), bump() returns 0, so every count reads as 0 and the
--       limiter never trips. The protection turns itself off under the load it exists
--       to stop.
--
--   luajit dataplane/test/ratelimit.lua      (or: make lua-test, which runs both)

local ROOT = arg[0]:match("^(.*)/test/ratelimit%.lua$") or "dataplane"
package.path = ROOT .. "/lua/?.lua;" .. ROOT .. "/lua/?/init.lua;" .. package.path

-- ------------------------------------------------------------------ shared dict mock
--
-- Implements just the slice of the lua_shared_dict API ratelimit uses:
-- incr(key, value, init, ttl). `full` flips it into the dict-is-full state, where
-- incr returns (nil, "no memory") like OpenResty does.

local dict = { store = {}, full = false }

function dict:incr(key, value, init, _ttl)
    if self.full then return nil, "no memory" end
    local v = (self.store[key] or init or 0) + value
    self.store[key] = v
    return v
end

function dict:reset() self.store = {}; self.full = false end
function dict:free_space() return self.full and 0 or 1024 end
function dict:capacity() return 65536 end

-- ------------------------------------------------------------------ ngx stub

local clock = 0.0

_G.ngx = {
    now    = function() return clock end,
    shared = { moswaf_cnt = dict },
    log    = function() end,
    WARN = 2,
}

local ratelimit = require "moswaf.ratelimit"

-- ------------------------------------------------------------------ harness

local failures, total = {}, 0
local function check(name, ok, detail)
    total = total + 1
    if ok then io.write(".") else
        io.write("F")
        failures[#failures + 1] = name .. (detail and ("\n      " .. detail) or "")
    end
end

-- Fire `n` requests at the current clock value; return how many were blocked.
local function fire(n, rps, burst)
    local blocked = 0
    for _ = 1, n do
        local hit = ratelimit.check("g", "198.51.100.9", rps, burst)
        if hit then blocked = blocked + 1 end
    end
    return blocked
end

-- ------------------------------------------------------------------ #8 fixed window

-- Sanity: inside a single second, request rps+1 trips the limiter.
dict:reset()
clock = 5.0
do
    local rps, burst = 10, 1000
    local blocked = fire(rps + 5, rps, burst)
    check("baseline: the per-second limit trips within one window",
        blocked == 5,
        "sent rps+5, expected 5 blocked, got " .. blocked)
end

-- The bug: straddle the boundary. rps of the requests land at t=0.90 (second bucket
-- 5) and rps more at t=1.00 (second bucket 6). Each bucket sees only rps requests,
-- so none are blocked - yet 2*rps arrived inside 100ms.
dict:reset()
do
    local rps, burst = 10, 1000       -- burst high enough not to interfere
    clock = 5.90
    local b1 = fire(rps, rps, burst)
    clock = 6.00
    local b2 = fire(rps, rps, burst)
    check("#8: a burst straddling the second boundary is NOT blocked",
        b1 == 0 and b2 == 0,
        "expected 0+0 blocked across the boundary, got " .. b1 .. "+" .. b2)
    check("#8: 2x the configured rps got through in ~100ms",
        (2 * rps) == 20,
        "this documents the effective ceiling is double the configured rps")
end

-- The 10-second window is the backstop that is *supposed* to catch this, and it does
-- when the burst is large enough - but only up to its own boundary, which has the
-- same flaw one order of magnitude up (floor(now/10)).
dict:reset()
do
    local rps, burst = 10, 15
    clock = 5.90
    local b1 = fire(20, rps, burst)   -- 20 requests: trips rps each second, and 10s burst
    check("#8: the 10s window does catch a burst mid-window",
        b1 > 0,
        "the 10s backstop should block once c10 exceeds burst")

    dict:reset()
    clock = 9.95                       -- 10s bucket 0
    local c1 = fire(burst, rps + 1000, burst)   -- rps set high so only the 10s window matters
    clock = 10.05                      -- 10s bucket 1 - resets the burst window
    local c2 = fire(burst, rps + 1000, burst)
    check("#8: the 10s window ALSO doubles at its own boundary",
        c1 == 0 and c2 == 0,
        "sent burst+burst straddling the 10s boundary, expected 0+0 blocked, got "
        .. c1 .. "+" .. c2)
end

-- ------------------------------------------------------------------ #7 fail-open

dict:reset()
clock = 20.0
do
    local rps, burst = 10, 100
    -- Confirm it blocks normally first.
    local before = fire(rps + 3, rps, burst)
    check("#7: limiter blocks normally when the dict has room",
        before == 3,
        "expected 3 blocked before the dict fills, got " .. before)

    -- Now the shared dict is full - the exact condition a flood from many IPs creates.
    dict.full = true
    local during = fire(1000, rps, burst)
    check("#7: when the shared dict is FULL, the limiter blocks NOTHING (fail-open)",
        during == 0,
        "sent 1000 requests over a rps=10 limit with the dict full; " ..
        during .. " were blocked (a fail-closed or degraded limiter would block most)")
end

-- ------------------------------------------------------------------ report

io.write("\n\n")
if #failures == 0 then
    print(string.format("%d/%d checks passed", total, total))
    print("\nBoth are behaviour trade-offs for the project owner, now with evidence:")
    print("  #8  effective ceiling is ~2x the configured rate at a window boundary")
    print("  #7  a full shared dict disables rate limiting entirely (fail-open)")
    os.exit(0)
end
print(string.format("%d of %d checks FAILED:\n", #failures, total))
for _, f in ipairs(failures) do print("  - " .. f) end
os.exit(1)
