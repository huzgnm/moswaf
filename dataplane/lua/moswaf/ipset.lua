-- moswaf.ipset - danh sach den/trang + ban tam thoi
--
-- Danh sach tinh (den/trang) den tu control plane qua config.
-- Ban tam thoi do chinh engine sinh ra khi phat hien flood/quet,
-- luu trong shared dict nen het han tu dong va khong can DB.

local config = require "moswaf.config"
local util   = require "moswaf.util"

local ban = ngx.shared.moswaf_ban
local _M  = {}

-- --------------------------------------------------------- danh sach tinh

function _M.is_whitelisted(ip)
    local conf = config.get()
    return (util.ip_in_list(ip, conf.whitelist))
end

function _M.is_blacklisted(ip)
    local conf = config.get()
    return (util.ip_in_list(ip, conf.blacklist))
end

-- --------------------------------------------------------- ban tam thoi

-- Ban IP trong `seconds` giay, kem ly do de ghi log
function _M.ban_ip(ip, seconds, reason)
    seconds = tonumber(seconds) or 600
    local ok, err = ban:set("b:" .. ip, reason or "auto", seconds)
    if not ok then
        ngx.log(ngx.WARN, "moswaf: khong ban duoc ", ip, ": ", err)
        return false
    end
    ngx.log(ngx.NOTICE, "moswaf: ban ", ip, " trong ", seconds, "s (", reason or "auto", ")")
    return true
end

-- Tra ve: dang_bi_ban, ly_do, so_giay_con_lai
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
    -- get_keys ton kem, chi dung cho endpoint /metrics
    return #ban:get_keys(0)
end

-- Dong bo danh sach ban do admin them tay tren dashboard
-- (control plane ghi vao config.blacklist nen ham nay chi don rac ban tu dong)
function _M.flush_expired()
    ban:flush_expired(1000)
end

return _M
