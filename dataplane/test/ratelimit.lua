-- Tests for moswaf.ratelimit - the per-address request budget.
--
-- The bug these exist for, stated plainly: opening one page is a burst. A page
-- with sixty assets is sixty requests inside one second, from one click, by one
-- person. The limiter that was here measured exactly that and called it a flood,
-- and an administrator opening their own dashboard went over the limit before
-- the page had finished drawing.
--
-- So the first test below is that one page load is allowed, and most of the rest
-- are about not fixing it by simply switching the protection off.
--
-- The clock and the shared dict are both stubbed, because the thing being tested
-- is arithmetic over time and real time would make it flaky rather than true.
--
--   luajit dataplane/test/ratelimit.lua      (or: make lua-test)

local ROOT = arg[0]:match("^(.*)/test/ratelimit%.lua$") or "dataplane"
package.path = ROOT .. "/lua/?.lua;" .. ROOT .. "/lua/?/init.lua;" .. package.path

local clock = 1000.0

-- ------------------------------------------------------------ shared dict mock
--
-- This one expires entries, and that is not a detail. GCRA represents "this
-- address has gone quiet" as "this address has no entry", so a mock that never
-- expired anything would let every test below pass for the wrong reason - it
-- would be testing an algorithm that cannot forget.

local dict = { store = {}, expires = {}, full = false }

local function alive(self, key)
    local e = self.expires[key]
    if e and clock >= e then
        self.store[key], self.expires[key] = nil, nil
        return false
    end
    return self.store[key] ~= nil
end

function dict:incr(key, value, init, init_ttl)
    if self.full then return nil, "no memory" end
    if not alive(self, key) then
        if init == nil then return nil, "not found" end
        self.store[key] = init + value
        self.expires[key] = init_ttl and (clock + init_ttl) or nil
        return self.store[key]
    end
    self.store[key] = self.store[key] + value
    return self.store[key]
end

function dict:expire(key, ttl)
    if not alive(self, key) then return nil, "not found" end
    self.expires[key] = clock + ttl
    return true
end

function dict:get(key) return alive(self, key) and self.store[key] or nil end
function dict:ttl(key)
    if not alive(self, key) then return nil end
    return self.expires[key] and (self.expires[key] - clock) or 0
end
function dict:flush_expired(_n) return 0 end
function dict:reset() self.store, self.expires, self.full = {}, {}, false end
function dict:free_space() return self.full and 0 or 1024 end
function dict:capacity() return 65536 end

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

local function reset(t)
    dict:reset()
    clock = t or 1000.0
end

-- The shipped defaults.
local RATE, BURST = 20, 300

-- Send n requests with no time passing between them; return how many were let
-- through and the reason the first refusal gave.
local function send(n, rate, burst, ip, scope)
    local passed, reason = 0, nil
    for _ = 1, n do
        local over, why = ratelimit.check(scope or "s", ip or "1.2.3.4",
                                          rate or RATE, burst or BURST)
        if over then reason = reason or why else passed = passed + 1 end
    end
    return passed, reason
end

-- ===================================================== THE ONE THAT MATTERS

do
    reset()
    -- One click. Sixty assets. Nothing waits for anything.
    local passed = send(60)
    check("opening one page is not a flood", passed == 60,
        "only " .. passed .. " of 60 got through. A page with sixty assets is " ..
        "sixty requests inside one second from one click by one person. This is " ..
        "the bug: the limiter measured the thing it should have been forgiving, " ..
        "and an administrator opening their own dashboard was refused before " ..
        "the page had finished drawing")

    -- Clicking quickly through a site, with no pause at all.
    reset()
    passed = send(300)
    check("five page loads back to back are allowed", passed == 300,
        "got " .. passed .. ". The burst has to exceed one page render by " ..
        "enough that somebody clicking quickly is not an attacker")
end

-- ===================================================== and still a limit

do
    reset()
    send(BURST)                     -- allowance spent exactly
    local over, why = ratelimit.check("s", "1.2.3.4", RATE, BURST)
    check("past the burst, the pace is enforced", over == true and why == ratelimit.OVER,
        "the burst is an allowance, not a suggestion. Without a floor under it " ..
        "this is not a rate limit, it is a rate limit that has been switched off")

    -- A real flood: keeps sending, never pauses.
    reset()
    local passed = send(5000)
    check("a sustained flood is cut down to the burst", passed == BURST,
        passed .. " of 5000 got through, expected " .. BURST)
end

-- ============================================= the debt drains with time

do
    reset()
    send(BURST)                     -- fully in debt
    check("fully in debt, the next request is refused",
        (ratelimit.check("s", "1.2.3.4", RATE, BURST)) == true)

    -- A human reads the page for five seconds. At twenty a second that is a
    -- hundred requests' worth of allowance back.
    clock = clock + 5
    local passed = send(100)
    check("five seconds of reading pays off five seconds of debt", passed == 100,
        "got " .. passed .. " of 100. The sustained rate is the rate the debt " ..
        "drains at; if it did not drain, one busy minute would lock somebody " ..
        "out for the rest of the day")

    -- Long enough away and the address is simply new again.
    reset()
    send(BURST)
    check("while in debt the address has an entry",
        dict:get("r:s:1.2.3.4") ~= nil)

    clock = clock + 60
    check("once the debt has drained, the entry is gone",
        dict:get("r:s:1.2.3.4") == nil,
        "GCRA represents 'this address went quiet' as 'this address has no " ..
        "entry'. An entry that outlived its debt would hand a returning visitor " ..
        "a clear-at time from the past; one that died early would hand a busy " ..
        "address a fresh burst. The lifetime IS the algorithm, not housekeeping")

    passed = send(BURST)
    check("and it gets its whole burst back", passed == BURST,
        "got " .. passed)
end

-- ========================= a busy address must not be handed a free refill
--
-- The entry is created with a lifetime, and if that lifetime were the only thing
-- keeping it alive an address that stayed busy would simply outlive its own
-- record: the entry vanishes, the next request finds nothing, and it starts
-- again with a whole fresh burst. A flood would get its full allowance back
-- every few seconds forever, which is not a rate limit at all.
--
-- What stops that is re-setting the lifetime to the debt on every allowed
-- request. So this test runs longer than the initial lifetime on purpose.

do
    reset()
    -- Sit exactly on the sustained rate for a minute: one request every 1/rate
    -- seconds, which is precisely affordable and should never build debt or
    -- earn a refill.
    local allowed = 0
    for _ = 1, RATE * 60 do
        clock = clock + (1 / RATE)
        if not (ratelimit.check("s", "1.2.3.4", RATE, BURST)) then
            allowed = allowed + 1
        end
    end
    check("a client sitting exactly on the rate is never refused", allowed == RATE * 60,
        "refused " .. (RATE * 60 - allowed) .. " of " .. (RATE * 60))

    -- Now the real question, and it has to be asked over a stretch LONGER than
    -- the entry's initial lifetime - which is where the bug would hide.
    --
    -- Fifty requests a second for thirty seconds: 1500 sent. What an address may
    -- honestly afford in that time is its burst plus what the rate pays out -
    -- 300 + 20x30 = 900. Anything much above that means it was handed a second
    -- burst it never earned.
    reset()
    local SECONDS, PACE = 30, 50
    local passed = 0
    for _ = 1, SECONDS * PACE do
        clock = clock + (1 / PACE)
        if not (ratelimit.check("s", "1.2.3.4", RATE, BURST)) then
            passed = passed + 1
        end
    end
    local affordable = BURST + RATE * SECONDS
    check("an address that never stops is never handed its burst back",
        passed <= affordable + 5,
        passed .. " of " .. (SECONDS * PACE) .. " got through; at most " ..
        affordable .. " were affordable. The entry is created with a lifetime, " ..
        "and if nothing re-set that lifetime a busy address would outlive its " ..
        "own record: the entry vanishes, the next request finds nothing, and it " ..
        "starts again with a whole fresh burst. A flood would get its full " ..
        "allowance back every few seconds, forever")
    check("and is still allowed everything it did earn", passed >= RATE * SECONDS,
        "only " .. passed .. " got through; the rate alone should pay for " ..
        (RATE * SECONDS))
end

-- ======================================== retrying must not dig the hole

do
    reset()
    send(BURST)

    -- A client that has been refused keeps trying, as clients do.
    for _ = 1, 500 do ratelimit.check("s", "1.2.3.4", RATE, BURST) end

    -- One second later they should be owed exactly one second of allowance,
    -- regardless of how many times they knocked while refused.
    clock = clock + 1
    local passed = send(RATE)
    check("a refused request does not deepen the debt", passed == RATE,
        "got " .. passed .. " of " .. RATE .. " after 500 refused retries. If " ..
        "a rejected request still charged the bucket, the punishment would grow " ..
        "with the retrying rather than with the sending - and every client " ..
        "retries. Somebody refused once would be locked out for minutes")
end

-- ====================================================== keeping things apart

do
    reset()
    send(BURST, nil, nil, "1.1.1.1")
    local passed = send(BURST, nil, nil, "2.2.2.2")
    check("one address spending its budget does not spend another's", passed == BURST,
        "got " .. passed .. ". Behind a carrier NAT this would be two hundred " ..
        "people sharing one verdict, but across different addresses it is just wrong")

    reset()
    send(BURST, nil, nil, "1.1.1.1", "siteA")
    passed = send(BURST, nil, nil, "1.1.1.1", "siteB")
    check("and flooding one site does not spend the budget on another", passed == BURST,
        "got " .. passed)
end

-- ================================================== refusing to lock people out

do
    reset()
    -- A huge burst over a tiny rate: 600 requests at 1/s is a ten-minute debt.
    send(600, 1, 600)
    local _, _, debt, allowance = ratelimit.check("s", "1.2.3.4", 1, 600)
    check("no configuration can put an address in debt for longer than the cap",
        allowance <= 60 and debt <= 61,
        "debt " .. string.format("%.1f", debt) .. "s, allowance " ..
        string.format("%.1f", allowance) .. "s. A misconfigured pair should not " ..
        "be able to refuse somebody for longer than a ban would")
end

-- ===================================================== switched off means off

do
    reset()
    local passed = send(10000, 0, 0)
    check("a rate of zero is off, not a limit of zero", passed == 10000,
        "got " .. passed .. ". 0 means 'no limit configured' everywhere else in " ..
        "the settings, and reading it as 'refuse everything' would take a site " ..
        "down the moment somebody cleared the field")
    check("and it does not even keep a counter", dict:get("r:s:1.2.3.4") == nil,
        "switched off has to mean the arithmetic never ran. A zero rate makes " ..
        "the emission interval infinite, and infinities compared against each " ..
        "other can land on 'allowed' by accident - which looks identical from " ..
        "outside and is not the same thing at all")

    -- A negative rate is a typo, not a policy.
    reset()
    passed = send(100, -5, 100)
    check("a negative rate is off too", passed == 100 and dict:get("r:s:1.2.3.4") == nil)

    -- A rate with no burst is still a rate: one request at a time, paced.
    reset()
    passed = send(10, RATE, 0)
    check("a burst of zero still paces rather than refusing everything", passed >= 1,
        "got " .. passed .. "; the first request must always be affordable")
end

-- ============================================ a full dict must not switch it off

do
    reset()
    dict.full = true
    local over, why = ratelimit.check("s", "1.2.3.4", RATE, BURST)
    check("a full shared dict reports itself", over == true and why == ratelimit.DICT_FULL,
        "returning 'allowed' here switches the protection off under exactly the " ..
        "load it exists to stop, because a flood from many addresses is what " ..
        "fills the dict in the first place")
    check("and is not reported as going over the limit", why ~= ratelimit.OVER,
        "access.lua challenges on this and must never ban on it: the number a " ..
        "ban would rest on does not exist right now")
    dict.full = false
end

-- ======================== the counters a ban actually rests on are untouched

do
    reset()
    for i = 1, ratelimit.ATTACK_BAN_AT do
        local n = ratelimit.mark_attack("1.2.3.4")
        if i == ratelimit.ATTACK_BAN_AT then
            check("attacks still count to the ban threshold", n == ratelimit.ATTACK_BAN_AT)
        end
    end
    reset()
    local n
    for _ = 1, 5 do n = ratelimit.mark_challenge("1.2.3.4") end
    check("unsolved challenges still count", n == 5)
    check("and the thresholds are unchanged by this rewrite",
        ratelimit.ATTACK_BAN_AT == 10 and ratelimit.CHALLENGE_BAN_AT == 600,
        "a ban rests on what somebody did, not on how much they sent. This file " ..
        "changing how much is measured must not quietly change what earns a ban")
end

-- ================================ the number the control plane also believes

do
    -- MAX_DEBT is duplicated in Go as store.MaxBurstSeconds, where it refuses a
    -- burst this engine would quietly cap. Nothing links the two, so each side
    -- pins the other by name: moving this one turns a Go test red, and moving
    -- that one turns this red.
    --
    -- Without this the guard only pointed one way. Lowering MAX_DEBT to 30 while
    -- Go kept 60 would leave every test green, and the control plane would go on
    -- accepting settings - and showing them back as in force - that this file
    -- had already thrown half of away.
    check("MAX_DEBT still matches store.MaxBurstSeconds in Go",
        ratelimit.MAX_DEBT == 60,
        "this is " .. tostring(ratelimit.MAX_DEBT) .. " and Go's " ..
        "MaxBurstSeconds is 60. Change both, or the control plane validates " ..
        "against a ceiling the engine does not have")
end

-- =================================================================== report

io.write("\n")
if #failures > 0 then
    io.write("\n", #failures, " of ", total, " checks failed:\n")
    for _, f in ipairs(failures) do io.write("  - ", f, "\n") end
    os.exit(1)
end
io.write(total, " checks passed\n")
