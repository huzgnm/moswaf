-- moswaf.ipset - blocklist, allowlist and temporary bans
--
-- The static lists come from the control plane through the config.
-- Temporary bans are created by the engine itself when it detects a flood or a scan;
-- they live in a shared dict, so they expire on their own and need no database.

local config = require "moswaf.config"
local util   = require "moswaf.util"

local ban = ngx.shared.moswaf_ban
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
    ngx.log(ngx.NOTICE, "moswaf: banned ", ip, " for ", seconds, "s (", reason or "auto", ")")
    return true
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
