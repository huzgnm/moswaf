-- moswaf.ratelimit - dem tan suat request theo IP (chong flood L7)
--
-- Hai cua so chay song song:
--   * 1 giay : chan burst tuc thoi (rps)
--   * 10 giay: chan flood keo dai deu tay ma rps tung giay van duoi nguong
--
-- Dem nam trong lua_shared_dict nen moi worker deu thay chung so lieu.

local cnt = ngx.shared.moswaf_cnt
local _M  = {}

local floor = math.floor

local function bump(key, ttl)
    local newval, err = cnt:incr(key, 1, 0, ttl)
    if not newval then
        -- shared dict day -> khong chan nham, chi ghi log
        ngx.log(ngx.WARN, "moswaf: khong tang duoc bo dem ", key, ": ", err)
        return 0
    end
    return newval
end

-- scope: "g" (toan cuc) hoac id cua site
-- Tra ve: vuot_nguong(boolean), ly_do(string|nil), so_dem_giay, so_dem_10giay
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

-- Dem so lan mot IP bi chan gan day -> co so de leo thang sang ban
function _M.mark_violation(ip, window)
    window = window or 60
    local key = "v:" .. ip .. ":" .. floor(ngx.now() / window)
    return bump(key, window * 2)
end

-- Dem so request 404 lien tiep -> dau hieu do thu muc/quet
function _M.mark_notfound(ip)
    local key = "nf:" .. ip .. ":" .. floor(ngx.now() / 60)
    return bump(key, 120)
end

function _M.stats()
    return cnt:free_space(), cnt:capacity()
end

return _M
