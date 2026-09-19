-- moswaf.ipset - blocklist, allowlist and temporary bans
--
-- The static lists come from the control plane through the config.
-- Temporary bans are created by the engine itself when it detects a flood or a scan;
-- they live in a shared dict, so they expire on their own and need no database.

local config = require "moswaf.config"
local util   = require "moswaf.util"

local ban = ngx.shared.moswaf_ban

-- Counters for how often an already-banned address keeps knocking. Deliberately
-- in moswaf_cnt, where the other counters live, and NOT in moswaf_ban.
--
-- moswaf_ban holds exactly one shape of key, "b:<ip>", and two things depend on
-- that: /bans lists it with get_keys and filters, and banned_count counts every
-- key without filtering anything. Put a second kind of key in there and the ban
-- count silently doubles while the ban list starts truncating on counters rather
-- than on bans - and how much it truncates depends on hash order, so it would be
-- wrong differently each time.
local cnt = ngx.shared.moswaf_cnt

local _M  = {}

-- --------------------------------------------------------- static lists

function _M.is_whitelisted(ip)
    local conf = config.get()
    return (util.ip_in_list(ip, conf.whitelist))
end

function _M.is_blacklisted(ip)
    local conf = config.get()
    return (util.ip_in_list(ip, conf.blacklist))
end

-- --------------------------------------------------------- temporary bans

-- Ban an IP for `seconds`, with a reason recorded for the log
function _M.ban_ip(ip, seconds, reason)
    seconds = tonumber(seconds) or 600
    local ok, err = ban:set("b:" .. ip, reason or "auto", seconds)
    if not ok then
        ngx.log(ngx.WARN, "moswaf: could not ban ", ip, ": ", err)
        return false
    end
    -- A fresh ban starts the escalation count over. Somebody banned an hour ago,
    -- let go, and banned again is at the beginning again - not one knock away
    -- from the kernel because of what they did before lunch.
    cnt:delete("bh:" .. ip)
    ngx.log(ngx.NOTICE, "moswaf: banned ", ip, " for ", seconds, "s (", reason or "auto", ")")
    return true
end

-- How many requests an address has sent SINCE it was banned.
--
-- This is what separates somebody who tripped a limit and stopped from somebody
-- who is still hammering: the first costs nothing more, the second is the traffic
-- worth spending a kernel rule on. Only the second is escalated.
--
-- The counter expires with the ban, so an address that goes quiet leaves nothing
-- behind. Returns the new count.
function _M.note_ban_hit(ip, ttl)
    local key = "bh:" .. ip
    local n, err = cnt:incr(key, 1, 0, ttl and ttl > 0 and ttl or 600)
    if not n then
        -- The counter dict is full. Escalation simply does not happen, which
        -- leaves the address banned at the Lua layer - slower, but exactly what
        -- it was a moment ago. Nothing here may fail towards dropping packets.
        ngx.log(ngx.WARN, "moswaf: could not count a post-ban hit for ", ip, ": ",
                err or "unknown")
        return 0
    end
    return n
end

function _M.ban_hits(ip)
    return cnt:get("bh:" .. ip) or 0
end

-- Returns: banned, reason, seconds remaining
function _M.is_banned(ip)
    local reason, _, _ = ban:get("b:" .. ip)
    if not reason then return false end
    local ttl = ban:ttl("b:" .. ip) or 0
    return true, reason, ttl
end

function _M.unban(ip)
    ban:delete("b:" .. ip)
    cnt:delete("bh:" .. ip)
end

function _M.banned_count()
    -- get_keys is expensive; only used by the /metrics endpoint
    return #ban:get_keys(0)
end

-- Manual blocks added on the dashboard arrive through config.blacklist, so this only
-- sweeps the automatic bans that have expired
function _M.flush_expired()
    ban:flush_expired(1000)
end

return _M
