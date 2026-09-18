-- Adversarial deterministic tests for moswaf.flood (site-wide L7 flood defence).
--
-- The live path is throttled by nginx's own limit_req (200 r/s per connection IP),
-- so a single machine cannot push 1000 r/s of genuinely distinct clients through it
-- to exercise the DEFAULT threshold. This harness stubs the shared dict and the
-- clock and drives flood.observe/observe_status/evaluate directly, so the default
-- 1000 r/s threshold, its boundary, the error-rate signal, the hold, and per-site
-- isolation are all checked exactly.
--
--   luajit dataplane/test/flood_attack.lua

local ROOT = arg[0]:match("^(.*)/test/flood_attack%.lua$") or "dataplane"
package.path = ROOT .. "/lua/?.lua;" .. ROOT .. "/lua/?/init.lua;" .. package.path

-- ------------------------------------------------------------------ shared dict mock
local dict = { store = {}, ttl = {}, full = false }
function dict:incr(key, v, init, ttlv)
    if self.full then return nil, "no memory" end
    local cur = self.store[key]
    if cur == nil then cur = init or 0 end
    cur = cur + v
    self.store[key] = cur
    if ttlv then self.ttl[key] = ttlv end
    return cur
end
function dict:get(key) return self.store[key] end
function dict:set(key, val, ttlv) self.store[key] = val; if ttlv then self.ttl[key] = ttlv end; return true end
function dict:delete(key) self.store[key] = nil; self.ttl[key] = nil end
function dict:reset() self.store = {}; self.ttl = {}; self.full = false end

local clock = 1000
_G.ngx = {
    shared = { moswaf_flood = dict },
    time = function() return math.floor(clock) end,
    now  = function() return clock end,
    log = function() end, WARN = 2, ERR = 1,
}

local flood = require "moswaf.flood"
local W = flood.WINDOW

-- Reset the per-worker eval throttle between cases by advancing the clock >1s and
-- forcing a fresh evaluate; the module caches last_eval internally.
local failures, total = {}, 0
local function check(name, ok, detail)
    total = total + 1
    if ok then io.write(".") else io.write("F"); failures[#failures+1] = name .. (detail and ("\n      "..detail) or "") end
end

-- Fill the WINDOW buckets that measure() will read at evaluation time `now`
-- (seconds now-1 .. now-W) with `perSec` requests each, so measure() sees `perSec`.
local function loadRequests(site, perSec, now)
    for back = 1, W do
        local sec = now - back
        dict.store["r:"..site..":"..sec] = perSec
        dict.ttl["r:"..site..":"..sec] = W + 5
    end
end

local function freshEval(site, cfg, now)
    clock = now   -- evaluate at exactly this second; cases are 1000s apart so the
                  -- module's 1s eval throttle never blocks a fresh evaluation
    return flood.evaluate(site, cfg)
end

local cfg = { rps = 1000, error_rate = 50, hold = 120 }

-- ---- default 1000 r/s threshold: boundary ----
dict:reset()
loadRequests("s1", 1000, 2000)
do
    local engaged, reason, rps = freshEval("s1", cfg, 2000)
    check("default 1000 r/s: exactly 1000 r/s engages", engaged == true and reason == "site_rps",
        "engaged="..tostring(engaged).." reason="..tostring(reason).." rps="..tostring(rps))
end

dict:reset()
loadRequests("s2", 999, 3000)
do
    local engaged = freshEval("s2", cfg, 3000)
    check("default 1000 r/s: 999 r/s does NOT engage", engaged == false,
        "engaged="..tostring(engaged))
end

dict:reset()
loadRequests("s3", 5000, 4000)   -- a real distributed flood, 5x over
do
    local engaged, reason = freshEval("s3", cfg, 4000)
    check("distributed flood 5000 r/s engages", engaged == true and reason == "site_rps")
end

-- ---- the error-rate signal, after the PR #20 griefing fix ----
--
-- The floor is now a *rate of origin answers*: max(20/s, threshold/20). The griefing
-- attack it closes: a trickle of 5xx (four requests a second against one broken URL)
-- used to hold every visitor in the challenge indefinitely. Now the origin also has
-- to be answering at a real rate before its error rate can engage the defence.

-- Griefing, now BLOCKED: 4 answers/s at 75% 5xx with a 1000 r/s threshold. The floor
-- is max(20, 1000/20) = 50 answers/s, so 4/s is far below it and must NOT engage.
dict:reset()
do
    local sec0 = 4999
    for back = 1, W do
        dict.store["e:s4:"..(sec0-back)] = 4       -- 4 answers/s (20 over the window)
        dict.store["e:s4:"..(sec0-back)..":5"] = 3 -- 75% of them 5xx
    end
    local engaged = freshEval("s4", { rps = 1000, error_rate = 50, hold = 120 }, sec0)
    check("error signal: a trickle of 5xx (4/s) no longer engages (griefing fix)",
        engaged == false, "engaged="..tostring(engaged))
end

-- A real error storm DOES engage: at the 1000 r/s threshold the floor is 50 answers/s;
-- 60 answers/s at 80% 5xx clears it.
dict:reset()
do
    local sec0 = 5999
    for back = 1, W do
        dict.store["e:s5:"..(sec0-back)] = 60       -- 60 answers/s (>= 50 floor)
        dict.store["e:s5:"..(sec0-back)..":5"] = 48 -- 80% 5xx
    end
    local engaged, reason = freshEval("s5", { rps = 1000, error_rate = 50, hold = 120 }, sec0)
    check("error signal: a real error storm (60 answers/s @80% 5xx) engages",
        engaged == true and reason == "origin_errors",
        "engaged="..tostring(engaged).." reason="..tostring(reason))
end

-- The floor scales with the threshold, but never below the absolute 20/s. On a small
-- site (threshold 200 -> floor max(20,10)=20/s), 20 answers/s at 60% 5xx engages.
dict:reset()
do
    local sec0 = 6999
    for back = 1, W do
        dict.store["e:s6:"..(sec0-back)] = 20       -- 20 answers/s = the absolute floor
        dict.store["e:s6:"..(sec0-back)..":5"] = 12 -- 60% 5xx
    end
    local engaged, reason = freshEval("s6", { rps = 200, error_rate = 50, hold = 120 }, sec0)
    check("error signal: absolute 20/s floor applies to a low-threshold site",
        engaged == true and reason == "origin_errors",
        "engaged="..tostring(engaged).." reason="..tostring(reason))
end

-- The floor is on ANSWERS, not requests: a site being flooded serves mostly
-- challenges (which never reach the origin), so requests >> answers. A high request
-- rate must NOT lower the answer floor. 4 answers/s of 5xx with a huge request rate
-- still must not engage the error signal (the volumetric signal is a separate path).
dict:reset()
do
    local sec0 = 7999
    for back = 1, W do
        dict.store["r:s7:"..(sec0-back)] = 100000    -- enormous request rate...
        dict.store["e:s7:"..(sec0-back)] = 4         -- ...but only 4 answers/s from origin
        dict.store["e:s7:"..(sec0-back)..":5"] = 4   -- 100% of those 5xx
    end
    -- rps here (100000) also trips the volumetric signal, so to isolate the error
    -- path, turn the volumetric threshold off and keep only the error threshold.
    local engaged = freshEval("s7", { rps = 0, error_rate = 50, hold = 120 }, sec0)
    check("error signal: a huge request rate does not lower the answer floor",
        engaged == false, "engaged="..tostring(engaged))
end

-- ---- per-site isolation: flooding site A must not engage site B ----
dict:reset()
loadRequests("A", 5000, 7000)
do
    freshEval("A", cfg, 7000)                 -- engage A
    local bEngaged = freshEval("B", cfg, 7000) -- B has no traffic
    check("cross-site: flooding A does not engage B", flood.engaged("A") == true and bEngaged == false and flood.engaged("B") == false,
        "A="..tostring(flood.engaged("A")).." B="..tostring(bEngaged))
end

-- ---- hold: the flag carries a TTL; refreshed only while over the line ----
dict:reset()
loadRequests("h1", 5000, 8000)
do
    freshEval("h1", cfg, 8000)
    check("hold: engaged flag is set with the hold TTL", dict.ttl["on:h1"] == 120,
        "ttl="..tostring(dict.ttl["on:h1"]))
end

-- ---- feature off: rps=0 and error_rate=0 clears the flag ----
dict:reset()
dict.store["on:off1"] = "site_rps"   -- stale flag from a previous setting
do
    local engaged = freshEval("off1", { rps = 0, error_rate = 0, hold = 120 }, 9000)
    check("feature off (rps=0,err=0) clears a stale flag", engaged == false and dict.store["on:off1"] == nil)
end

-- ---- threshold(): the Lua "0 is truthy" trap the peer fixed ----
do
    local t1 = flood.threshold({ flood_rps = 0 }, { flood_rps = 1000 })
    check("threshold: site 0 falls back to global (the 0-is-truthy trap)", t1.rps == 1000,
        "got rps="..tostring(t1.rps))
    local t2 = flood.threshold({}, {})
    check("threshold: nothing configured -> rps 0 (off)", t2.rps == 0)
    local t3 = flood.threshold({ flood_rps = 250 }, { flood_rps = 1000 })
    check("threshold: site override wins", t3.rps == 250)
end

-- ---- dict full: observe/measure degrade without crashing ----
dict:reset()
do
    dict.full = true
    local okObserve = pcall(flood.observe, "df1")
    dict.full = false
    check("dict full: observe does not crash", okObserve)
end

io.write("\n\n")
if #failures == 0 then
    print(string.format("%d/%d checks passed", total, total))
    print("\nWhat this pins:")
    print("  - the default 1000 r/s threshold engages exactly at the boundary (999 does not)")
    print("  - a distributed flood (5000 r/s across many clients) engages")
    print("  - flooding one site never engages another (per-site isolation)")
    print("  - the origin-error signal needs a real answer rate (max 20/s, threshold/20),")
    print("    which closes the trickle-of-5xx griefing path (PR #20), while a real error")
    print("    storm still engages; the floor is on answers, not requests")
    os.exit(0)
end
print(string.format("%d of %d checks FAILED:\n", #failures, total))
for _, f in ipairs(failures) do print("  - " .. f) end
os.exit(1)
