-- Deterministic tests for moswaf.ratelimit (findings #7 and #8).
--
-- ratelimit.check reads its clock from ngx.now() and its counters from the
-- lua_shared_dict ngx.shared.moswaf_cnt. Both are stubbed here so the two open
-- rate-limit findings can be shown exactly and repeatably, without booting the
-- stack or fighting sub-second HTTP timing:
--
--   #8  Sliding windows. A fixed bucket keyed on floor(now) reset on the wall-clock
--       second, so a burst either side of a boundary let ~2x the configured rps
--       through. Each window now carries the weighted tail of the previous bucket.
--
--   #7  A full shared dict no longer disables the limiter. cnt:incr returning nil
--       used to read as a count of zero, so the protection switched itself off under
--       exactly the load it exists to stop. It now reclaims once and, failing that,
--       reports DICT_FULL, which access.lua turns into a challenge.
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

function dict:get(key) return self.store[key] end
function dict:flush_expired(_n) return 0 end
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

-- ------------------------------------------------------------------ #8 sliding window

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

-- Straddle the boundary: rps requests land at t=5.90 and rps more at t=6.00. With
-- fixed buckets each side saw only rps and nothing was blocked, so 2x the rate got
-- through in 100ms. The sliding estimate still carries almost all of the first
-- burst at t=6.00 (10% into the new bucket), so the second one is blocked.
dict:reset()
do
    local rps, burst = 10, 1000       -- burst high enough not to interfere
    clock = 5.90
    local b1 = fire(rps, rps, burst)
    clock = 6.00
    local b2 = fire(rps, rps, burst)
    check("#8: a burst straddling the second boundary IS blocked now",
        b2 > 0,
        "expected the second half of the burst to be blocked, got " .. b2 ..
        " blocked (first half: " .. b1 .. ")")
    check("#8: the effective ceiling is no longer 2x the configured rps",
        (b1 + b2) >= rps - 1,
        "sent 2*rps across the boundary and only " .. (b1 + b2) .. " were blocked")
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
    clock = 10.05                      -- 10s bucket 1, only 0.5% in
    local c2 = fire(burst, rps + 1000, burst)
    check("#8: the 10s window no longer doubles at its own boundary",
        c2 > 0,
        "sent burst+burst straddling the 10s boundary, expected the second half to "
        .. "be blocked, got " .. c1 .. "+" .. c2)
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
    check("#7: a FULL shared dict no longer disables the limiter",
        during == 1000,
        "sent 1000 requests over a rps=10 limit with the dict full; only " ..
        during .. " were reported over the limit")

    -- What matters is *how* it degrades: the reason has to say the counters are
    -- unusable, so access.lua challenges instead of banning on a meaningless count.
    local _, reason = ratelimit.check("g", "198.51.100.9", rps, burst)
    check("#7: the degraded path reports DICT_FULL rather than a rate reason",
        reason == ratelimit.DICT_FULL,
        "got reason " .. tostring(reason))
end

-- ------------------------------------------------------------------ report

io.write("\n\n")
if #failures == 0 then
    print(string.format("%d/%d checks passed", total, total))
    print("\n  #8  sliding windows: a burst across a boundary no longer doubles the rate")
    print("  #7  a full shared dict degrades to a challenge instead of passing everything")
    os.exit(0)
end
print(string.format("%d of %d checks FAILED:\n", #failures, total))
for _, f in ipairs(failures) do print("  - " .. f) end
os.exit(1)
