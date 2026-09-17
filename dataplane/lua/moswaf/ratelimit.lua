-- moswaf.ratelimit - per-IP request counters (layer 7 flood protection)
--
-- Two windows run side by side:
--   * 1 second : catches instant bursts (rps)
--   * 10 seconds: catches a slow, evenly paced flood that stays under the per-second
--                 threshold
--
-- The counters live in a lua_shared_dict, so every worker sees the same numbers.

local cnt = ngx.shared.moswaf_cnt
local _M  = {}

local floor = math.floor

local function bump(key, ttl)
    local newval, err = cnt:incr(key, 1, 0, ttl)
    if not newval then
        -- shared dict is full -> log it rather than block the wrong people
        ngx.log(ngx.WARN, "moswaf: could not increment counter ", key, ": ", err)
        return 0
    end
    return newval
end

-- scope: "g" for global, or a site id
-- Returns: over_threshold (boolean), reason (string|nil), 1s count, 10s count
function _M.check(scope, ip, rps, burst)
    local now  = ngx.now()
    local sec  = floor(now)
    local win  = floor(now / 10)

    local ksec = scope .. ":s:" .. ip .. ":" .. sec
    local kwin = scope .. ":w:" .. ip .. ":" .. win

    local c1 = bump(ksec, 2)
    local c10 = bump(kwin, 20)

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
    return bump(key, window * 2)
end

-- Count consecutive 404s -> a sign of directory brute forcing or scanning
function _M.mark_notfound(ip)
    local key = "nf:" .. ip .. ":" .. floor(ngx.now() / 60)
    return bump(key, 120)
end

function _M.stats()
    return cnt:free_space(), cnt:capacity()
end

return _M
