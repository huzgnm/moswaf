-- moswaf.ratelimit - per-address request budgets (layer 7 flood protection)
--
-- The budget is a GCRA - the generic cell rate algorithm, the same shape nginx's
-- limit_req and Redis's redis-cell use. Two numbers describe it and they mean
-- genuinely different things:
--
--   rate   how many requests a second this address may sustain forever
--   burst  how many it may fire back to back before that pace is enforced
--
-- That second number is the whole reason this file was rewritten. What was here
-- before was two hard ceilings - sixty in a second, a hundred and twenty in ten -
-- and no notion of a burst at all. But opening one page IS a burst: a page with
-- sixty assets is sixty requests inside one second, from one click, by one
-- person. The old shape could not tell that apart from an attack because it was
-- measuring the exact thing it should have been forgiving. An administrator
-- opening their own dashboard went over the limit before the page had finished
-- drawing.
--
-- A rate and a burst separate them cleanly, and without asking the client to
-- identify itself. A browser fires sixty requests and then stops while a human
-- reads; the debt drains during the reading. A flood fires sixty requests and
-- then sixty more, and the debt never drains.
--
-- HOW IT WORKS
--
-- One number is stored per address: the moment that address would be clear if it
-- kept to the sustained rate. Call it the clear-at time. Each request pushes it
-- forward by one emission interval (1/rate seconds). A request is allowed while
-- the clear-at time is no further ahead of now than the burst allowance - so an
-- address that has been quiet may fire a whole burst at once, and one that has
-- been busy is paced.
--
-- No counter to reset, no window boundary to game, no background process
-- dripping tokens back. The shared dict entry expires exactly when the debt
-- clears, so an address that goes quiet leaves nothing behind at all.
--
-- WHAT IT IS NOT FOR
--
-- This is not the defence against a distributed flood and must not be tuned as
-- if it were. Ten thousand addresses sending two requests a second each will
-- never trouble a per-address budget, and that is flood.lua's job - it watches
-- the site as a whole and challenges everybody. This file answers a narrower
-- question: is this ONE address asking for more than any one visitor could
-- plausibly need? Tightened past that it stops catching attackers and starts
-- catching customers, which is how it was wrong before.

local cnt = ngx.shared.moswaf_cnt
local _M  = {}

local floor = math.floor
local ceil  = math.ceil

-- Returned as the reason when the shared dict is exhausted and the budget can no
-- longer be trusted. access.lua treats it as a challenge and never escalates it
-- to a ban, because at that point the number means nothing.
_M.DICT_FULL = "dict_full"

_M.OVER = "rate"

-- bump increments a counter, or reports that the dict is exhausted.
--
-- Returning 0 on failure - the old behaviour - meant every count read as zero and
-- the limiter silently switched itself off under exactly the load it exists to
-- stop: a flood from many IPs is what fills the dict in the first place.
local function bump(key, ttl)
    local newval = cnt:incr(key, 1, 0, ttl)
    if newval then return newval end

    -- One reclaim attempt: expired entries are the usual reason it is full
    if cnt.flush_expired then cnt:flush_expired(200) end
    newval = cnt:incr(key, 1, 0, ttl)
    if newval then return newval end

    ngx.log(ngx.WARN, "moswaf: rate-limit shared dict is full, falling back to ",
            "a challenge for ", key, " - raise lua_shared_dict moswaf_cnt")
    return nil
end

-- The longest debt any address may carry, whatever it was configured with.
--
-- Without it a large burst over a small rate produces a clear-at time hours
-- ahead, and an address that fired one oversized page load would be paced for
-- the rest of the afternoon. Nothing here should be able to refuse somebody for
-- longer than a ban would.
local MAX_DEBT = 60

--- Ask whether this address may send one more request.
--
-- scope: "g" for global, or a site id, so one site's traffic cannot spend
--        another's budget.
-- rate:  sustained requests per second
-- burst: requests allowed back to back
--
-- Returns: over (boolean), reason (string|nil), debt in seconds, burst allowance
-- in seconds. The last two are for the log and the dashboard - "three seconds
-- into an allowance of fifteen" says something a raw count does not.
function _M.check(scope, ip, rate, burst)
    if not rate or rate <= 0 then return false, nil, 0, 0 end

    -- The smallest meaningful burst is one, and this is not rounding.
    --
    -- The allowance is how far ahead of now an address may already be spoken
    -- for, and sending a request always moves it one interval ahead. A burst of
    -- zero therefore refuses the very first request from an address that has
    -- been silent for a week - which is not "one request per second", it is
    -- zero per second wearing the wrong label. redis-cell says the same thing
    -- by reporting its capacity as max_burst + 1.
    if not burst or burst < 1 then burst = 1 end

    local now = ngx.now()
    local interval  = 1 / rate
    local allowance = burst * interval
    if allowance > MAX_DEBT then allowance = MAX_DEBT end

    local key = "r:" .. scope .. ":" .. ip

    -- incr with an init value is what makes this work without a lock.
    --
    -- When the key is absent the dict creates it at `now + interval` and returns
    -- that; when it is present the dict adds one interval to whatever is there.
    -- Those are exactly the two branches of the algorithm - a quiet address
    -- starting fresh, and a busy one accumulating - and the dict does the choice
    -- atomically, so two workers cannot both read the same clear-at time and both
    -- decide they may write it.
    --
    -- Absence is how "this address has gone quiet" is represented, which is why
    -- the entry's lifetime is the debt itself: see the expire() below.
    local clear_at = cnt:incr(key, interval, now, ceil(allowance) + 1)
    if not clear_at then
        if cnt.flush_expired then cnt:flush_expired(200) end
        clear_at = cnt:incr(key, interval, now, ceil(allowance) + 1)
    end
    if not clear_at then
        ngx.log(ngx.WARN, "moswaf: rate-limit shared dict is full - raise ",
                "lua_shared_dict moswaf_cnt")
        return true, _M.DICT_FULL, 0, allowance
    end

    local debt = clear_at - now

    if debt > allowance then
        -- Put back what this request took.
        --
        -- A refused request must not deepen the debt, or a client that keeps
        -- retrying pushes its own clear-at time further away with every attempt
        -- and is locked out for far longer than the allowance says - the
        -- punishment growing with the retrying rather than with the sending. The
        -- same reason nginx does not charge a rejected request either.
        cnt:incr(key, -interval)
        return true, _M.OVER, debt - interval, allowance
    end

    -- The entry lives exactly as long as the debt does.
    --
    -- This is not housekeeping, it is the other half of the algorithm: an entry
    -- that outlived its debt would make a returning visitor pick up an old
    -- clear-at time in the past, and one that died early would hand a busy
    -- address a fresh burst. Expiring on the debt means "quiet for long enough"
    -- and "has no entry" are the same statement.
    cnt:expire(key, ceil(debt) + 1)

    return false, nil, debt, allowance
end

-- There was a mark_violation() here, counting how often an address went over a
-- rate limit, and access.lua banned at three of them.
--
-- It is gone rather than tuned. The count was never the problem: going over a
-- limit is something every real visitor does - a page with forty assets, a crowd
-- behind one carrier address, somebody clicking quickly - so no threshold on it
-- separates an attacker from a customer. What separates them is being refused by
-- the signature engine, or being handed challenge after challenge and never
-- answering one. Both are counted above.

-- How many times the signature engine has refused this address recently, and the
-- point at which that stops being a mistake and starts being a campaign.
--
-- This is the signal a ban should rest on, and going over a rate limit is not.
-- Everybody goes over a rate limit eventually: a page with forty assets, a phone
-- on a carrier NAT shared with two hundred other people, somebody double-clicking.
-- Almost nobody trips a SQL injection rule ten times in a minute by accident.
--
-- Counting volume and calling it an attack is how an administrator opening their
-- own admin panel ended up banned for ten minutes with "flood" written in the log.
local ATTACK_BAN_AT     = 10
local ATTACK_BAN_WINDOW = 60

_M.ATTACK_BAN_AT = ATTACK_BAN_AT

-- Returns the count within the current window.
function _M.mark_attack(ip)
    local key = "at:" .. ip .. ":" .. floor(ngx.now() / ATTACK_BAN_WINDOW)
    return bump(key, ATTACK_BAN_WINDOW * 2) or 0
end

-- How many challenges an address has been handed without ever coming back with a
-- solved one.
--
-- A browser is challenged once. It solves the proof of work, gets a cookie, and
-- is not challenged again - so being challenged over and over means the thing
-- receiving them is not solving them, which no browser does.
--
-- This is what a volume flood earns instead of a ban-on-request-count: being
-- refused repeatedly is not evidence of anything, but being ASKED repeatedly and
-- never answering is. It cannot be produced by a page with too many assets, by a
-- crowd behind one carrier NAT, or by somebody clicking quickly - every one of
-- those solves the first challenge and stops being counted.
--
-- Six hundred in a minute - ten a second, sustained, never once answering.
--
-- The number is not chosen to catch every bot. It is chosen to answer one
-- question: is this address worth a rule in the kernel? A ban here is the only
-- door to that, and a kernel rule is worth placing on traffic that is genuinely
-- expensive and worth nothing on traffic that is merely rude.
--
-- Thirty was the first number here and it was wrong in a way worth writing down.
-- Half a request a second is something one idle scraper produces - and because
-- this counter is keyed on the address, one scraper sitting behind a carrier NAT
-- would drag the two hundred people sharing that address over the line with it.
-- The threshold has to sit above what a single misbehaving machine can reach on
-- its own, or it punishes its neighbours.
--
-- It does not remove that problem, it only moves it further away: a determined
-- client inside a shared address can still reach any per-address threshold by
-- going faster. Telling one machine from another behind the same address needs
-- something other than the address, and that is a different piece of work.
local CHALLENGE_BAN_AT     = 600
local CHALLENGE_BAN_WINDOW = 60

_M.CHALLENGE_BAN_AT = CHALLENGE_BAN_AT

function _M.mark_challenge(ip)
    local key = "ch:" .. ip .. ":" .. floor(ngx.now() / CHALLENGE_BAN_WINDOW)
    return bump(key, CHALLENGE_BAN_WINDOW * 2) or 0
end

-- Count consecutive 404s -> a sign of directory brute forcing or scanning
function _M.mark_notfound(ip)
    local key = "nf:" .. ip .. ":" .. floor(ngx.now() / 60)
    return bump(key, 120) or 0
end

function _M.stats()
    return cnt:free_space(), cnt:capacity()
end

return _M
