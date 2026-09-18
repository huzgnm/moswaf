-- Deterministic tests for moswaf.flood - the distributed-flood defence.
--
-- The case this module exists for cannot be reproduced with a per-IP limiter, so
-- the first test builds it explicitly: ten thousand addresses asking twice a
-- second each. Every single address stays far below any per-IP threshold, and
-- together they deliver 20,000 requests a second to the origin. The per-IP
-- limiter is blind to it by construction; this module has to see it.
--
-- The clock and the shared dict are stubbed so the behaviour is exact and the
-- test finishes in milliseconds instead of waiting out real windows.
--
--   luajit dataplane/test/flood.lua

local ROOT = arg[0]:match("^(.*)/test/flood%.lua$") or "dataplane"
package.path = ROOT .. "/lua/?.lua;" .. ROOT .. "/lua/?/init.lua;" .. package.path

-- ------------------------------------------------------------------ stubs

local clock = 1000.0

local dict = { store = {} }

function dict:incr(key, value, init, _ttl)
    local v = (self.store[key] or init or 0) + value
    self.store[key] = v
    return v
end

function dict:get(key) return self.store[key] end
function dict:set(key, value, _ttl) self.store[key] = value; return true end
function dict:delete(key) self.store[key] = nil end
function dict:reset() self.store = {} end

_G.ngx = {
    time   = function() return math.floor(clock) end,
    now    = function() return clock end,
    shared = { moswaf_flood = dict },
    log    = function() end,
    WARN = 2, ERR = 3,
}

local flood = require "moswaf.flood"

-- ------------------------------------------------------------------ harness

local failures, total = {}, 0
local function check(name, ok, detail)
    total = total + 1
    if ok then io.write(".") else
        io.write("F")
        failures[#failures + 1] = name .. (detail and ("\n      " .. detail) or "")
    end
end

-- Let `seconds` pass, delivering `rps` requests in each of them.
local function traffic(site, seconds, rps)
    for _ = 1, seconds do
        for _ = 1, rps do flood.observe(site) end
        clock = clock + 1
    end
end

-- Let `seconds` pass with the origin answering; `fail_pct` of answers are 5xx.
local function answers(site, seconds, per_second, fail_pct)
    for _ = 1, seconds do
        for i = 1, per_second do
            flood.observe_status(site, (i <= per_second * fail_pct / 100) and 503 or 200)
        end
        clock = clock + 1
    end
end

-- flood.evaluate caches its answer for one second per worker. The helpers above
-- already move the clock by whole seconds between calls, so no nudge is needed
-- here - and nudging it would shift the measurement window and silently drop a
-- bucket, which is what the first version of this test did to itself.
local function evaluate(site, cfg)
    return flood.evaluate(site, cfg)
end

local CFG = { rps = 1000, error_rate = 50, hold = 120 }

-- ------------------------------------------------- the case it exists for

dict:reset()
do
    local site = "shop"

    -- 10,000 addresses at 2 r/s each. Written out as the total it produces,
    -- because that is the only thing any per-IP counter would ever see: 2.
    local BOTS, PER_BOT = 10000, 2
    traffic(site, flood.WINDOW, BOTS * PER_BOT)

    local engaged, reason, rps = evaluate(site, CFG)
    check("a distributed flood is detected even though no single IP is over the limit",
        engaged and reason == "site_rps",
        "20,000 r/s across 10,000 addresses, engaged=" .. tostring(engaged) ..
        " reason=" .. tostring(reason) .. " measured=" .. tostring(rps))

    check("the rate it reports is the site total, not a per-IP figure",
        rps and rps >= BOTS * PER_BOT * 0.9,
        "measured " .. tostring(rps) .. " r/s, expected about " .. (BOTS * PER_BOT))

    check("each attacker on its own is far under the per-IP limit",
        PER_BOT < 60,
        "a per-IP threshold of 60 r/s cannot see " .. PER_BOT .. " r/s")
end

-- ------------------------------------------------- ordinary traffic is left alone

dict:reset()
do
    local site = "shop"
    traffic(site, flood.WINDOW, 200)          -- a busy site, well under the threshold
    local engaged = evaluate(site, CFG)
    check("a busy site under the threshold is not challenged",
        not engaged,
        "200 r/s should not engage a 1000 r/s threshold")
end

-- A single noisy second must not engage it either: that is what the window is for.
dict:reset()
do
    local site = "shop"
    traffic(site, 1, 3000)                    -- one burst second
    traffic(site, flood.WINDOW - 1, 50)       -- then quiet
    local engaged, _, rps = evaluate(site, CFG)
    check("one noisy second does not engage the defence",
        not engaged,
        "one burst of 3000 in a " .. flood.WINDOW .. "s window averaged " .. tostring(rps))
end

-- ------------------------------------------------- the origin failing

dict:reset()
do
    local site = "slow"
    -- Well below the 1000 r/s volumetric threshold, but the origin is falling
    -- over: a slow endpoint can be taken down with a request rate no volumetric
    -- threshold would flag. 60 r/s clears the error signal's own floor.
    answers(site, flood.WINDOW, 60, 80)
    local engaged, reason = evaluate(site, CFG)
    check("the origin failing engages the defence well below the volumetric threshold",
        engaged and reason == "origin_errors",
        "60 r/s with 80% of answers failing against a 1000 r/s threshold, engaged=" ..
        tostring(engaged) .. " reason=" .. tostring(reason))
end

-- The error signal has to cost the attacker real traffic.
--
-- Twenty answers over a five second window is four requests a second. Anyone who
-- knows one URL on the site that returns 5xx - a broken endpoint, a route behind
-- a dead dependency - could otherwise hold every visitor in the challenge for
-- the price of four requests a second, indefinitely, by trickling just enough to
-- refresh the hold. The defence itself becomes the denial of service.
dict:reset()
do
    local site = "slow"
    answers(site, flood.WINDOW, 4, 100)      -- 4 r/s, every single answer a 5xx
    local engaged, reason = evaluate(site, CFG)
    check("a trickle of errors cannot hold the site in the challenge",
        not engaged,
        "4 r/s of pure 5xx engaged the defence (reason " .. tostring(reason) ..
        "); one broken URL would keep every visitor solving challenges for free")
end

-- The floor scales with the site: a small site configured with a low volumetric
-- threshold must not need the same absolute rate as a large one.
dict:reset()
do
    local site = "small"
    answers(site, flood.WINDOW, 25, 100)     -- 25 r/s, above the absolute floor of 20
    local engaged, reason = evaluate(site, { rps = 200, error_rate = 50, hold = 60 })
    check("a small site's error signal fires at its own scale",
        engaged and reason == "origin_errors",
        "25 r/s of 5xx on a site with a 200 r/s threshold, engaged=" .. tostring(engaged))
end

-- ...and on a large one the floor rises with it, so the same trickle is not enough.
dict:reset()
do
    local site = "large"
    answers(site, flood.WINDOW, 25, 100)
    local engaged = evaluate(site, { rps = 10000, error_rate = 50, hold = 60 })
    check("a large site's error signal needs a rate to match",
        not engaged,
        "25 r/s of 5xx engaged a site whose volumetric threshold is 10,000 r/s")
end

-- Two failures out of three is 66% and means nothing; the sample floor has to hold.
dict:reset()
do
    local site = "quiet"
    for i = 1, 3 do flood.observe_status(site, i <= 2 and 500 or 200) end
    clock = clock + 1
    local engaged = evaluate(site, CFG)
    check("a handful of errors on a quiet site does not engage it",
        not engaged,
        "3 answers, 2 of them 5xx, should be below the sample floor")
end

-- ------------------------------------------------- it turns itself off

dict:reset()
do
    local site = "shop"
    traffic(site, flood.WINDOW, 20000)
    local engaged = evaluate(site, { rps = 1000, error_rate = 50, hold = 30 })
    check("engaged while the flood runs", engaged, "should be engaged")

    -- The flag carries a TTL; the stub keeps values forever, so expiring it by
    -- hand is exactly what the TTL does in OpenResty.
    dict.store["on:" .. site] = nil

    traffic(site, flood.WINDOW, 30)           -- the flood has stopped
    local still = evaluate(site, { rps = 1000, error_rate = 50, hold = 30 })
    check("it releases by itself once the flood stops",
        not still,
        "still engaged after the traffic returned to 30 r/s")
end

-- ------------------------------------------------- switched off means off

dict:reset()
do
    local site = "shop"
    traffic(site, flood.WINDOW, 50000)
    local engaged = evaluate(site, { rps = 0, error_rate = 0, hold = 120 })
    check("thresholds of 0 switch the defence off entirely",
        not engaged,
        "50,000 r/s engaged the defence while it was configured off")
end

-- A flag left over from an earlier setting must not survive the feature being
-- turned off - otherwise a site stays in challenge mode with nothing to explain it.
dict:reset()
do
    local site = "shop"
    traffic(site, flood.WINDOW, 20000)
    evaluate(site, CFG)
    check("engaged before being switched off", flood.engaged(site), "setup failed")

    evaluate(site, { rps = 0, error_rate = 0, hold = 120 })
    check("switching it off clears a flag left over from before",
        not flood.engaged(site),
        "the site is still challenging every visitor with the feature off")
end

-- ------------------------------------------------- what the dashboard reads

dict:reset()
do
    local site = "shop"
    traffic(site, flood.WINDOW, 20000)
    evaluate(site, CFG)
    local st = flood.state(site)
    check("state() reports the engagement, the rate and the peak",
        st.engaged and st.reason == "site_rps" and st.rps >= 18000 and st.peak_rps >= 18000,
        string.format("engaged=%s reason=%s rps=%s peak=%s",
            tostring(st.engaged), tostring(st.reason), tostring(st.rps), tostring(st.peak_rps)))
end

-- ------------------------------------------------- one site does not report another
--
-- The measurement is cached for a second per worker. With a single shared slot
-- the decision stayed correct - it is read from the per-site flag - but the rate
-- and reason handed back belonged to whichever site was measured last, so a
-- quiet site could show a flooded site's numbers.
dict:reset()
do
    traffic("busy", flood.WINDOW, 20000)
    local engaged_busy, reason_busy, rps_busy = evaluate("busy", CFG)
    check("the flooded site reports its own flood", engaged_busy and rps_busy > 1000,
        "setup: engaged=" .. tostring(engaged_busy) .. " rps=" .. tostring(rps_busy))

    -- Immediately after, within the same second, ask about a site with no traffic.
    local engaged_quiet, reason_quiet, rps_quiet = evaluate("quiet", CFG)
    check("a quiet site is not reported as flooded",
        not engaged_quiet,
        "the quiet site came back engaged")
    check("a quiet site does not report the flooded site's rate",
        (rps_quiet or 0) == 0 and reason_quiet == nil,
        "quiet site reported rps=" .. tostring(rps_quiet) ..
        " reason=" .. tostring(reason_quiet) .. " - those belong to 'busy'")
end

-- ------------------------------------------------- resolving the thresholds
--
-- This is the check that was missing. The unit tests above hand evaluate() a cfg
-- table directly, so they never exercised how that table is built - and the way
-- it was built returned 0 for every site that had not set its own threshold,
-- because 0 is truthy in Lua. The defence was configured, switched on, and
-- silently never applied. A live flood found it; these keep it found.

do
    local st = { flood_rps = 1000, flood_error_rate = 50, flood_hold = 60 }

    local t = flood.threshold({ flood_rps = 0 }, st)
    check("a site with flood_rps 0 falls back to the global threshold",
        t.rps == 1000,
        "0 is truthy in Lua, so `tonumber(site.flood_rps) or global` yields 0 - got " .. t.rps)

    t = flood.threshold({}, st)
    check("a site with no flood_rps at all falls back to the global threshold",
        t.rps == 1000, "got " .. t.rps)

    t = flood.threshold({ flood_rps = 250 }, st)
    check("a site with its own threshold keeps it",
        t.rps == 250, "got " .. t.rps)

    t = flood.threshold({ flood_rps = 0 }, { flood_rps = 0, flood_error_rate = 0 })
    check("zero everywhere really means off",
        t.rps == 0 and t.error_rate == 0,
        "rps=" .. t.rps .. " error_rate=" .. t.error_rate)

    t = flood.threshold({}, { flood_rps = 1000 })
    check("a missing hold falls back to a sane one rather than 0",
        t.hold == 120,
        "hold 0 would drop the defence the instant the flood paused; got " .. t.hold)
end

-- And the whole path end to end, the way access.lua runs it: a default site, the
-- global setting, and a flood.
dict:reset()
do
    local site_cfg = { flood_rps = 0 }              -- exactly what a new site looks like
    local settings = { flood_rps = 1000, flood_error_rate = 50, flood_hold = 60 }
    traffic("shop", flood.WINDOW, 20000)
    local engaged = evaluate("shop", flood.threshold(site_cfg, settings))
    check("a default site is protected by the global threshold",
        engaged,
        "20,000 r/s against a global threshold of 1000 did not engage the defence")
end

-- ------------------------------------------------------------------ report

io.write("\n\n")
if #failures == 0 then
    print(string.format("%d/%d checks passed", total, total))
    print("\n  a distributed flood - 10,000 addresses at 2 r/s - is detected and challenged")
    print("  an origin that starts failing engages the defence on its own")
    print("  ordinary traffic, a single burst second, and a quiet site are left alone")
    print("  the defence releases itself once the flood stops")
    print("  a trickle of 5xx cannot hold the site in the challenge for free")
    os.exit(0)
end
print(string.format("%d of %d checks FAILED:\n", #failures, total))
for _, f in ipairs(failures) do print("  - " .. f) end
os.exit(1)
