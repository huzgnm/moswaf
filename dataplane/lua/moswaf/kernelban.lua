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

-- Where the agent publishes what it has actually done, so the dashboard can tell
-- "asked for" apart from "in effect". Read here, written there; this side never
-- writes them.
local APPLIED = "moswaf:kernel_applied"
local REFUSED = "moswaf:kernel_refused"
local ORPHANS = "moswaf:kernel_orphans"
local HEALTH  = "moswaf:kernel_agent"

_M.APPLIED = APPLIED
_M.REFUSED = REFUSED
_M.ORPHANS = ORPHANS
_M.HEALTH  = HEALTH

-- The local note that an escalation was asked for.
--
-- Kept in shared memory rather than read back out of Redis because it answers a
-- question only this side can answer: the queue is write-only from here, and once
-- an event is pushed there is nothing in Redis that says it came from us until
-- the agent acts on it. Without this marker the gap between asking and the agent
-- applying is indistinguishable from never having asked - which is precisely the
-- window somebody looks at the dashboard during, wondering why nothing happened.
local cnt = ngx.shared.moswaf_cnt

local function pending_key(ip) return "kp:" .. ip end

--- When a kernel drop was queued for this address, or nil if none was.
function _M.pending_since(ip)
    return cnt:get(pending_key(ip))
end

local function mark_pending(ip, ttl)
    -- Expires with the ban. An address whose ban ran out has nothing pending,
    -- because there is nothing left to enforce.
    cnt:set(pending_key(ip), ngx.time(), ttl and ttl > 0 and ttl or 600)
end

local function clear_pending(ip)
    cnt:delete(pending_key(ip))
end

_M.clear_pending = clear_pending

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
    mark_pending(ip, ttl)
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
    -- Only after the queue write succeeded. Clearing the marker first would mean a
    -- failed release leaves an address the dashboard thinks nobody ever escalated,
    -- while the kernel goes on dropping it.
    clear_pending(ip)
    return true
end

--- Ask the host to stop dropping everything.
--
-- One event rather than one per address, because "unban all" during a flood may
-- be tens of thousands of addresses and the queue is capped at ten thousand -
-- sending them individually would silently drop the releases at the far end of
-- exactly the list somebody is trying to clear.
function _M.request_release_all()
    local payload = cjson.encode({ op = "release_all", ts = ngx.time() })
    if not payload then return false end

    local red, err = util.redis()
    if not red then
        ngx.log(ngx.WARN, "moswaf: could not queue a kernel release for all: ", err)
        return false
    end
    red:init_pipeline()
    red:rpush(FEED, payload)
    red:ltrim(FEED, -FEED_MAX, -1)
    local _, perr = red:commit_pipeline()
    util.redis_release(red)

    if perr then
        ngx.log(ngx.WARN, "moswaf: could not queue a kernel release for all: ", perr)
        return false
    end
    return true
end

--- What the agent has reported about itself and about individual addresses.
--
-- One round trip for the whole page: the caller passes the addresses it is about
-- to show and gets back only their state, rather than the entire applied set.
-- That matters during a flood, when the applied set is the largest it will ever
-- be and the dashboard is the thing being refreshed every few seconds.
--
-- Returns a table, never nil. `reachable` is the field that matters, and it is
-- kept separate from the contents on purpose.
--
-- An empty result has two completely different meanings: "there is no agent and
-- nothing is in the kernel", and "the queue is down, so I cannot tell you". Those
-- are identical in every other field - and a caller that treats them the same
-- concludes there is no kernel at exactly the moment it has lost the ability to
-- know, which is the moment that conclusion is most likely to be wrong and most
-- expensive to be wrong about.
-- Addresses asked about in one HMGET. Not a performance number: every field of a
-- pipelined command becomes a Lua vararg, and unpack() on a thousand-element list
-- is close enough to LuaJIT's stack limit that a later change to the page size
-- would turn a working dashboard into a runtime error. Chunking costs nothing -
-- the commands are pipelined either way, so it is still one round trip.
local HMGET_CHUNK = 128

function _M.kernel_state(ips)
    local out = { applied = {}, refused = {}, orphans = {}, health = nil,
                  reachable = false }

    local red = util.redis()
    if not red then return out end

    red:init_pipeline()
    red:hgetall(HEALTH)
    -- Capped: this is an error state, and a hundred examples of it says the same
    -- thing as ten thousand while costing the dashboard nothing to render.
    red:lrange(ORPHANS, 0, 99)

    -- Chunks are recorded as they are queued, so the replies can be matched back
    -- to the addresses that asked for them without counting anything twice.
    local chunks = {}
    for _, hash in ipairs({ APPLIED, REFUSED }) do
        for start = 1, #(ips or {}), HMGET_CHUNK do
            local group = {}
            for i = start, math.min(start + HMGET_CHUNK - 1, #ips) do
                group[#group + 1] = ips[i]
            end
            red:hmget(hash, unpack(group))
            chunks[#chunks + 1] = { hash = hash, ips = group }
        end
    end

    local res, perr = red:commit_pipeline()
    util.redis_release(red)
    if perr or type(res) ~= "table" then return out end
    out.reachable = true

    local health = res[1]
    if type(health) == "table" and #health >= 2 then
        local h = {}
        for i = 1, #health - 1, 2 do h[health[i]] = health[i + 1] end
        out.health = h
    end

    if type(res[2]) == "table" then
        for i = 1, #res[2] do
            if type(res[2][i]) == "string" then out.orphans[#out.orphans + 1] = res[2][i] end
        end
    end

    for c = 1, #chunks do
        local reply = res[2 + c]
        if type(reply) == "table" then
            local chunk = chunks[c]
            for i, ip in ipairs(chunk.ips) do
                local v = reply[i]
                if type(v) == "string" then
                    if chunk.hash == APPLIED then
                        out.applied[ip] = tonumber(v) or 0
                    else
                        out.refused[ip] = v
                    end
                end
            end
        end
    end
    return out
end

-- ---------------------------------------------------------- reporting

-- How long an escalation may sit unapplied before it is called stuck.
--
-- Two reconcile intervals, because one is the normal case: an event queued a
-- second after a reconcile started waits out the rest of that cycle and is picked
-- up by the next one. Calling that stuck would light a warning on every
-- escalation and teach whoever reads the dashboard to ignore it, which costs more
-- than the warning is worth.
local function stuck_after(health)
    local resync = tonumber(health and health.resync_every) or 60
    if resync < 15 then resync = 15 end
    return resync * 2
end

--- What is actually enforcing this ban, and whether that matches what was asked.
--
-- Four answers, and the distinction between the last three is the whole point of
-- reporting it at all:
--
--   lua            - the ban is refused in userspace and nothing more was asked
--   kernel_pending - a drop was asked for; the agent has not confirmed it yet
--   kernel         - the agent has the address in the kernel set
--   kernel_refused - the agent looked at it and said no, and said why
--
-- A dashboard that showed only "banned" would report the last three identically,
-- including the one where the machine's own administrator was spared a kernel
-- rule. Somebody debugging "why is this address still fast" needs to be able to
-- see which of the four it is.
--
-- `now` is a parameter so this can be tested without waiting.
function _M.enforcement(ip, state, now)
    now = now or ngx.time()
    state = state or {}

    local why = state.refused and state.refused[ip]
    if why then
        return { enforcement = "kernel_refused", refused_reason = why, stuck = false }
    end

    local since = state.applied and state.applied[ip]
    if since then
        return { enforcement = "kernel", enforcement_since = since, stuck = false }
    end

    local asked = _M.pending_since(ip)
    if asked then
        return {
            enforcement       = "kernel_pending",
            enforcement_since = asked,
            stuck             = (now - asked) > stuck_after(state.health),
        }
    end

    return { enforcement = "lua", stuck = false }
end

--- The agent's own state, in the shape the dashboard renders.
--
-- `stale` rather than a raw timestamp difference, because "is this thing alive"
-- is a question with one right answer and the dashboard should not be the place
-- it gets decided - two dashboards doing that arithmetic differently would
-- disagree about whether the machine is protected.
function _M.agent_status(state, now)
    local h = state and state.health
    if not h then
        -- Absent is not the same as broken. Most installations have no agent at
        -- all, and saying so plainly is better than reporting one that is down.
        return { present = false }
    end
    now = now or ngx.time()

    local applied = tonumber(h.applied)
    local out = {
        present      = true,
        seen_at      = h.seen_at,
        resync_every = tonumber(h.resync_every) or 60,
        -- -1 is the agent saying "I ran and could not read the ban list". Passed
        -- through as a null with a flag rather than as a number, so nobody
        -- renders "-1 addresses in the kernel".
        applied      = (applied and applied >= 0) and applied or nil,
        failing      = applied ~= nil and applied < 0,
    }

    -- The health key expires at four reconcile intervals, so its mere presence
    -- already means "seen recently". This is the finer-grained check: present but
    -- older than two intervals means it has missed a cycle.
    --
    -- The comparison is done against seen_unix, not against seen_at. The agent
    -- writes both: the timestamp for people to read and the integer for this.
    -- Parsing a date here to subtract it from a clock would put timezone handling
    -- in the path of deciding whether the machine is protected.
    local seen = tonumber(h.seen_unix)
    out.stale = (seen ~= nil) and ((now - seen) > stuck_after(h))
    return out
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
