-- moswaf.config - dong bo cau hinh tu control plane qua Redis
--
-- Control plane ghi JSON vao key "moswaf:config" moi khi admin luu thay doi.
-- Worker 0 keo ve va cat vao shared dict; cac worker con lai doc tu shared dict
-- roi cache ban da giai ma theo so version -> khong decode JSON moi request.

local cjson = require "cjson.safe"
local util  = require "moswaf.util"

local shm    = ngx.shared.moswaf_conf
local _M     = {}

local CONFIG_KEY  = "moswaf:config"
local SYNC_PERIOD = 3          -- giay

-- cache cap worker
local cached      = nil
local cached_ver  = -1

_M.defaults = {
    version  = 0,
    settings = {
        under_attack         = false,   -- bat: ep JS challenge voi moi khach la
        default_mode         = "protect",
        real_ip_header       = "",
        trusted_proxies      = {},
        global_rate_rps      = 60,      -- request/giay/IP tren toan he thong
        global_rate_burst    = 120,     -- nguong 10s
        ban_seconds          = 600,
        challenge_difficulty = 16,      -- so bit 0 dau cua SHA-256 (PoW)
        challenge_ttl        = 1800,
        block_status         = 403,
        max_body_scan        = 65536,   -- chi quet <= 64KB body
        scan_body            = true,
    },
    sites     = {},
    rules     = {},
    blacklist = {},
    whitelist = {},
}

-- Trang challenge nap 1 lan luc init
_M.challenge_html = nil
_M.block_html     = nil

local function read_file(path)
    local f = io.open(path, "r")
    if not f then return nil end
    local c = f:read("*a")
    f:close()
    return c
end

function _M.bootstrap()
    _M.challenge_html = read_file("/usr/local/moswaf/conf/challenge.html") or "<html><body>Checking...</body></html>"
    _M.block_html     = read_file("/usr/local/moswaf/conf/blocked.html")   or "<html><body>Blocked by MosWAF</body></html>"

    if not shm:get("data") then
        shm:set("data", cjson.encode(_M.defaults))
        shm:set("version", 0)
    end
end

-- Keo cau hinh moi nhat tu Redis vao shared dict. Chi worker 0 goi.
function _M.sync()
    local red, err = util.redis()
    if not red then
        ngx.log(ngx.WARN, "moswaf: khong ket noi duoc redis de dong bo config: ", err)
        return false
    end

    local raw, rerr = red:get(CONFIG_KEY)
    util.redis_release(red)

    if not raw or raw == ngx.null then
        if rerr then ngx.log(ngx.WARN, "moswaf: doc config loi: ", rerr) end
        return false
    end

    local conf = cjson.decode(raw)
    if not conf or type(conf) ~= "table" then
        ngx.log(ngx.ERR, "moswaf: config trong Redis khong phai JSON hop le")
        return false
    end

    local cur = shm:get("version") or -1
    local new = tonumber(conf.version) or 0
    if new == cur then return true end

    shm:set("data", raw)
    shm:set("version", new)
    ngx.log(ngx.NOTICE, "moswaf: da nap cau hinh version ", new)
    return true
end

-- Cau hinh da giai ma (co cache theo version)
function _M.get()
    local ver = shm:get("version") or 0
    if cached and cached_ver == ver then return cached end

    local raw = shm:get("data")
    local conf = raw and cjson.decode(raw) or nil
    if type(conf) ~= "table" then conf = _M.defaults end

    -- bu cac truong thieu bang gia tri mac dinh
    conf.settings = conf.settings or {}
    for k, v in pairs(_M.defaults.settings) do
        if conf.settings[k] == nil then conf.settings[k] = v end
    end
    conf.sites     = conf.sites     or {}
    conf.rules     = conf.rules     or {}
    conf.blacklist = conf.blacklist or {}
    conf.whitelist = conf.whitelist or {}

    cached, cached_ver = conf, ver
    return conf
end

function _M.site(id)
    if not id or id == "" then return nil end
    return _M.get().sites[id]
end

function _M.version()
    return shm:get("version") or 0
end

function _M.start_sync()
    if ngx.worker.id() ~= 0 then return end     -- mot worker dong bo la du
    _M.sync()
    local function tick(premature)
        if premature then return end
        local ok, err = pcall(_M.sync)
        if not ok then ngx.log(ngx.ERR, "moswaf: loi dong bo config: ", err) end
        local ok2, err2 = ngx.timer.at(SYNC_PERIOD, tick)
        if not ok2 then ngx.log(ngx.ERR, "moswaf: khong dat duoc timer config: ", err2) end
    end
    local ok, err = ngx.timer.at(SYNC_PERIOD, tick)
    if not ok then ngx.log(ngx.ERR, "moswaf: khong dat duoc timer config: ", err) end
end

return _M
