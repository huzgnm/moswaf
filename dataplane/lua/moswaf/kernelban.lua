-- moswaf.kernelban - asking the host to drop an address in the kernel
--
-- The last of three steps, and it is deliberately hard to reach.
--
--   1. a request breaks a rule       -> 403, and nothing else happens
--   2. it keeps breaking them        -> a temporary ban, still at this layer
--   3. it is banned AND STILL knocking, enough times -> this
--
-- Somebody who trips a limit and stops never gets here. Somebody who was banned
-- and went away never gets here. What gets here is traffic that has been told no,
-- knows it, and is still spending our CPU - which is the only traffic a kernel
-- rule is worth spending on.
--
-- Nothing in this file drops anything. It writes a request onto a queue; a host
-- agent reads the queue and programs nftables, and that agent is where the
-- never-drop list is enforced. Two processes, and the one that can lock somebody
-- out of their own machine is the one that also holds the list of who must never
-- be locked out.

local util  = require "moswaf.util"
local cjson = require "cjson.safe"

local _M = {}

-- The queue the host agent reads. Capped, because a queue nobody is reading is a
-- queue that grows: if the agent is stopped, this must cost a bounded amount of
-- memory rather than an unbounded one. Losing the oldest entries is safe - the
-- agent's periodic full resync repairs anything the queue dropped.
local FEED     = "moswaf:ban_events"
local FEED_MAX = 10000

-- How many requests an address sends AFTER being banned before it is worth a
-- kernel rule.
--
-- Not a tuning knob so much as a statement about intent: fifty requests after
-- being refused is not a misconfigured client retrying, it is something that has
-- been told no and is continuing. A smaller number would catch retry loops and
-- health checks; a much larger one would spend the CPU this exists to save.
local ESCALATE_AT = 50

_M.ESCALATE_AT = ESCALATE_AT

-- Addresses this layer refuses to escalate, whatever it is told.
--
-- The agent enforces its own list and that one is authoritative - it holds the
-- management address and it is the thing that can actually lock somebody out. So
-- why check here as well? Because these two are the only ones this side can know
-- about, they are cheap, and an address that never enters the queue cannot be
-- mishandled by a future version of something downstream. A private address in a
-- ban queue is a bug either way; it should not travel.
local function never_escalate(ip)
    return util.is_private_ip(ip)
end

--- Ask the host to drop this address until its ban expires.
--
-- Called once, at the moment the count crosses the threshold - not on every
-- request after it. The agent refreshes the kernel timeout on its own resync, so
-- repeating the request here would only add work to the path this is trying to
-- take work off.
function _M.request_drop(ip, ttl, reason)
    if type(ip) ~= "string" or ip == "" then return false end
    if ttl == nil or ttl <= 0 then return false end
    if never_escalate(ip) then
        ngx.log(ngx.WARN, "moswaf: refusing to escalate ", ip,
                " to the kernel - it is not a public address")
        return false
    end

    local payload = cjson.encode({
        op     = "drop",
        ip     = ip,
        -- The kernel entry expires at the same moment the ban does. One duration,
        -- one meaning: what the dashboard says about a ban is true of the kernel
        -- rule too, and neither outlives the other.
        ttl    = ttl,
        reason = reason or "auto",
        ts     = ngx.time(),
    })
    if not payload then return false end

    local red, err = util.redis()
    if not red then
        -- Nothing fails towards dropping packets. Without the queue the address
        -- stays banned at this layer, which is where it already was.
        ngx.log(ngx.WARN, "moswaf: could not queue a kernel drop for ", ip, ": ", err)
        return false
    end

    red:init_pipeline()
    red:rpush(FEED, payload)
    red:ltrim(FEED, -FEED_MAX, -1)
    local _, perr = red:commit_pipeline()
    util.redis_release(red)

    if perr then
        ngx.log(ngx.WARN, "moswaf: could not queue a kernel drop for ", ip, ": ", perr)
        return false
    end
    ngx.log(ngx.NOTICE, "moswaf: asked the kernel to drop ", ip, " for ", ttl, "s")
    return true
end

--- Ask the host to stop dropping an address.
--
-- Queued the same way, and the agent must treat it as cancelling a pending drop
-- as well as removing an applied one - otherwise a resync that ran between the
-- two would put back a rule for an address somebody has just released.
function _M.request_release(ip)
    if type(ip) ~= "string" or ip == "" then return false end

    local payload = cjson.encode({ op = "release", ip = ip, ts = ngx.time() })
    if not payload then return false end

    local red, err = util.redis()
    if not red then
        ngx.log(ngx.WARN, "moswaf: could not queue a kernel release for ", ip, ": ", err)
        return false
    end
    red:init_pipeline()
    red:rpush(FEED, payload)
    red:ltrim(FEED, -FEED_MAX, -1)
    local _, perr = red:commit_pipeline()
    util.redis_release(red)

    if perr then
        ngx.log(ngx.WARN, "moswaf: could not queue a kernel release for ", ip, ": ", perr)
        return false
    end
    return true
end

--- Count one request from an address that is already banned, and escalate at the
--- threshold.
--
-- Returns true when this call is the one that crossed it, so the caller can log
-- the moment rather than the fifty that led to it.
function _M.note_and_maybe_escalate(ipset, ip, ttl)
    local n = ipset.note_ban_hit(ip, ttl)
    if n ~= ESCALATE_AT then
        -- Only the crossing, never again. Equality rather than ">=" so the
        -- request is queued once: an address at three hundred hits would
        -- otherwise queue two hundred and fifty identical requests, which is
        -- work added to the path this exists to take work off.
        return false
    end
    return _M.request_drop(ip, ttl, "persistent")
end

return _M
