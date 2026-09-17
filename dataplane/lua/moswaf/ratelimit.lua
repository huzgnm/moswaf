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

-- Count how often an IP was blocked recently -> the basis for escalating to a ban
function _M.mark_violation(ip, window)
    window = window or 60
    local key = "v:" .. ip .. ":" .. floor(ngx.now() / window)
    return bump(key, window * 2) or 0
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
