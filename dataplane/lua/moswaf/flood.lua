-- moswaf.flood - defence against a distributed layer-7 flood
--
-- Every other limit in this engine counts per IP, and a distributed flood is
-- built precisely to stay under one. Ten thousand addresses asking twice a
-- second each is twenty thousand requests a second arriving at the origin, and
-- 2 r/s per address - a rate no per-IP threshold can object to, from addresses
-- no blocklist has ever seen. The origin falls over while the WAF reports that
-- nothing is wrong.
--
-- So this module counts what the site as a whole is receiving, and what the
-- origin is doing about it. When either crosses the line it turns the JS
-- challenge on for every visitor who has not already solved one, which is the
-- only cheap way to tell a browser from a botnet at that scale: the challenge is
-- served from memory here and never reaches the origin, and a solved cookie
-- lasts for the whole session.
--
-- It turns itself off again. The flag carries a TTL and is only refreshed while
-- the site is still over the line, so the site returns to normal on its own once
-- the flood stops - nobody has to be awake to switch it back.
--
--   observe(site)            count one request, called in the access phase
--   observe_status(site, s)  count the origin's answer, called in the log phase
--   evaluate(site, cfg)      decide; cheap to call on every request
--   state(site)              what the dashboard and the API report

local floods = ngx.shared.moswaf_flood

local _M = {}

-- Seconds of history the rate is measured over. Long enough that one noisy
-- second cannot engage the defence, short enough to react inside a few seconds.
local WINDOW = 5

-- A bucket has to outlive the window it is read in, with room for the clock.
local BUCKET_TTL = WINDOW + 5

-- Evaluating means reading WINDOW buckets. Doing that per request would add work
-- to exactly the moment the site is drowning, so each worker evaluates at most
-- once a second and every other request reads a single flag.
local last_eval, last_result = 0, nil

local function rkey(site, sec) return "r:" .. site .. ":" .. sec end
local function ekey(site, sec) return "e:" .. site .. ":" .. sec end
local function onkey(site)     return "on:" .. site end

-- Count one request. One dict operation, on purpose.
function _M.observe(site)
    if not floods then return end
    floods:incr(rkey(site, ngx.time()), 1, 0, BUCKET_TTL)
end

-- Count what the origin answered. Only server errors matter here: a flood that
-- gets past the request-rate threshold still shows up as the origin starting to
-- fail, and that is worth reacting to even when the request rate looks ordinary
-- - a slow endpoint can be taken down with far fewer requests than a fast one.
function _M.observe_status(site, status)
    if not floods or not status then return end
    local sec = ngx.time()
    floods:incr(ekey(site, sec), 1, 0, BUCKET_TTL)
    if status >= 500 then
        floods:incr(ekey(site, sec) .. ":5", 1, 0, BUCKET_TTL)
    end
end

-- Requests per second over the window, and the origin's error rate in percent.
--
-- The current second is skipped deliberately: it is still being filled, so
-- including it drags the average down and would make a flood look smaller than
-- it is at the exact moment the decision is being made.
local function measure(site)
    local now = ngx.time()
    local requests, answers, errors = 0, 0, 0

    for back = 1, WINDOW do
        local sec = now - back
        requests = requests + (floods:get(rkey(site, sec)) or 0)
        answers  = answers  + (floods:get(ekey(site, sec)) or 0)
        errors   = errors   + (floods:get(ekey(site, sec) .. ":5") or 0)
    end

    local rps = requests / WINDOW
    local error_rate = answers > 0 and (errors / answers) * 100 or 0
    return rps, error_rate, answers
end

-- Is the automatic defence currently on for this site?
function _M.engaged(site)
    if not floods then return false end
    return floods:get(onkey(site)) ~= nil
end

--- Decide whether the site is under a flood.
--
-- Returns: engaged (boolean), reason (string or nil), rps (number)
--
-- cfg carries the thresholds already resolved for this site:
--   rps        site-wide requests per second that engages the defence, 0 = off
--   error_rate origin 5xx percentage that engages it, 0 = off
--   hold       seconds to stay engaged after the last time it was over the line
function _M.evaluate(site, cfg)
    if not floods then return false end
    if (cfg.rps or 0) <= 0 and (cfg.error_rate or 0) <= 0 then
        -- Nothing configured. Clear any flag left over from a previous setting so
        -- turning the feature off actually turns it off.
        floods:delete(onkey(site))
        return false
    end

    local now = ngx.now()
    if now - last_eval < 1 and last_result ~= nil then
        -- Between evaluations, trust the shared flag rather than this worker's own
        -- last answer: another worker may have engaged the defence a moment ago.
        return _M.engaged(site), last_result.reason, last_result.rps
    end
    last_eval = now

    local rps, error_rate, answers = measure(site)
    local reason

    if (cfg.rps or 0) > 0 and rps >= cfg.rps then
        reason = "site_rps"
    elseif (cfg.error_rate or 0) > 0 and answers >= 20 and error_rate >= cfg.error_rate then
        -- The sample floor matters: three requests of which two failed is 66% and
        -- means nothing. Twenty answers in five seconds is a real signal.
        reason = "origin_errors"
    end

    last_result = { reason = reason, rps = rps }

    if reason then
        -- set() and not incr(): every refresh restarts the hold, so the defence
        -- stays on while the flood lasts and expires by itself afterwards.
        local hold = cfg.hold or 120
        floods:set(onkey(site), reason, hold)
        floods:set("peak:" .. site, math.max(rps, floods:get("peak:" .. site) or 0), 3600)
        return true, reason, rps
    end

    return _M.engaged(site), nil, rps
end

-- What the API reports, for the dashboard and for anyone debugging a live event.
function _M.state(site)
    if not floods then return { engaged = false } end
    local rps, error_rate = measure(site)
    return {
        engaged    = floods:get(onkey(site)) ~= nil,
        reason     = floods:get(onkey(site)),
        rps        = math.floor(rps * 10 + 0.5) / 10,
        error_rate = math.floor(error_rate * 10 + 0.5) / 10,
        peak_rps   = math.floor((floods:get("peak:" .. site) or 0) * 10 + 0.5) / 10,
    }
end

--- Work out which thresholds apply to a site.
--
-- The explicit `<= 0` checks are not decoration. In Lua the number 0 is truthy,
-- so `tonumber(site.flood_rps) or tonumber(st.flood_rps)` returns 0 for every
-- site that has not set its own value - which is all of them by default - and
-- the site-wide threshold silently never applies. This engine has been bitten by
-- exactly that once before, in the per-IP rate limiter, and it was caught here
-- again only because a live flood failed to engage the defence.
function _M.threshold(site, st)
    site, st = site or {}, st or {}

    local rps = tonumber(site.flood_rps) or 0
    if rps <= 0 then rps = tonumber(st.flood_rps) or 0 end

    local error_rate = tonumber(st.flood_error_rate) or 0
    local hold = tonumber(st.flood_hold) or 0
    if hold <= 0 then hold = 120 end

    return { rps = rps, error_rate = error_rate, hold = hold }
end

-- Used by the tests, and by a reset from the API.
function _M.clear(site)
    if not floods then return end
    floods:delete(onkey(site))
    floods:delete("peak:" .. site)
end

_M.WINDOW = WINDOW

return _M
