-- moswaf.ratelimit - per-IP request counters (layer 7 flood protection)
--
-- Two windows run side by side:
--   * 1 second : catches instant bursts (rps)
--   * 10 seconds: catches a slow, evenly paced flood that stays under the per-second
--                 threshold
--
-- Both are *sliding* windows. A fixed bucket keyed on floor(now) resets on the wall
-- clock, so sending the whole allowance just before the boundary and the whole
-- allowance again just after let twice the configured rate through unblocked - the
-- effective ceiling was 2x the number in the settings. Each window now carries the
-- tail of the previous bucket, weighted by how far into the current one we are:
--
--     estimate = current + previous * (1 - elapsed_fraction)
--
-- so the count decays smoothly instead of dropping to zero at a boundary.
--
-- The counters live in a lua_shared_dict, so every worker sees the same numbers.

local cnt = ngx.shared.moswaf_cnt
local _M  = {}

local floor = math.floor

-- Returned as the reason when the shared dict is exhausted and the counters can no
-- longer be trusted. access.lua treats it as a challenge and never escalates it to
-- a ban, because at that point the count means nothing.
_M.DICT_FULL = "dict_full"

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

-- Sliding estimate for one window width, plus the raw count in the current bucket.
local function window_count(scope, ip, width, now)
    local prefix = scope .. ":" .. width .. ":" .. ip .. ":"
    local idx    = floor(now / width)

    local current = bump(prefix .. idx, width * 2)
    if not current then return nil end

    local previous = cnt:get(prefix .. (idx - 1)) or 0
    local elapsed  = (now % width) / width

    return current + previous * (1 - elapsed)
end

-- scope: "g" for global, or a site id
-- Returns: over_threshold (boolean), reason (string|nil), 1s estimate, 10s estimate
function _M.check(scope, ip, rps, burst)
    local now = ngx.now()

    local c1 = window_count(scope, ip, 1, now)
    if not c1 then return true, _M.DICT_FULL, 0, 0 end

    local c10 = window_count(scope, ip, 10, now)
    if not c10 then return true, _M.DICT_FULL, c1, 0 end

    if rps and rps > 0 and c1 > rps then
        return true, "rate_rps", c1, c10
    end
    if burst and burst > 0 and c10 > burst then
        return true, "rate_burst", c1, c10
    end
    return false, nil, c1, c10
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
-- Thirty is deliberately far above what a browser can reach: it answers on the
-- first one.
local CHALLENGE_BAN_AT     = 30
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
