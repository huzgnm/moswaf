-- moswaf.config - configuration sync from the control plane through Redis
--
-- The control plane writes JSON into the key "moswaf:config" whenever an admin saves.
-- Worker 0 pulls it and stores it in a shared dict; the other workers read from that
-- dict and cache the decoded table by version, so no JSON is decoded per request.

local cjson = require "cjson.safe"
local util  = require "moswaf.util"

local shm    = ngx.shared.moswaf_conf
local _M     = {}

local CONFIG_KEY  = "moswaf:config"
local SYNC_PERIOD = 3          -- seconds

-- per-worker cache
local cached      = nil
local cached_ver  = -1

_M.defaults = {
    version  = 0,
    internal_token = "",
    settings = {
        under_attack         = false,   -- bat: ep JS challenge voi moi khach la
        default_mode         = "protect",
        real_ip_header       = "",
        trusted_proxies      = {},
        global_rate_rps      = 60,      -- requests per second per IP, system wide
        global_rate_burst    = 120,     -- threshold over 10 seconds
        ban_seconds          = 600,
        challenge_difficulty = 16,      -- leading zero bits required from SHA-256
        challenge_ttl        = 1800,
        block_status         = 403,
        max_body_scan        = 65536,   -- only scan bodies up to 64KB
        scan_body            = true,
    },
    sites     = {},
    rules     = {},
    blacklist = {},
    whitelist = {},
}

-- The challenge page is loaded once at init
_M.challenge_html = nil
_M.block_html     = nil

local function read_file(path)
    local f = io.open(path, "r")
    if not f then return nil end
    local c = f:read("*a")
    f:close()
    return c
end

-- Directory holding the challenge and block pages. Fixed inside the container, but a
-- native install (scripts/dev-local.sh) keeps them somewhere else.
local CONF_DIR = os.getenv("MOSWAF_CONF_DIR") or "/usr/local/moswaf/conf"

function _M.bootstrap()
    _M.challenge_html = read_file(CONF_DIR .. "/challenge.html")
    _M.block_html     = read_file(CONF_DIR .. "/blocked.html")

    -- Missing the challenge page is severe: the fallback carries no JavaScript, so a
    -- visitor can never solve it and turning on under-attack mode locks everyone out.
    -- Say so loudly instead of quietly carrying on.
    if not _M.challenge_html then
        ngx.log(ngx.ERR, "moswaf: CANNOT read ", CONF_DIR, "/challenge.html - ",
                "the JS challenge will not work. Set MOSWAF_CONF_DIR correctly.")
        _M.challenge_html = "<html><body>Checking...</body></html>"
    end
    if not _M.block_html then
        ngx.log(ngx.ERR, "moswaf: cannot read ", CONF_DIR, "/blocked.html")
        _M.block_html = "<html><body>Blocked by MosWAF</body></html>"
    end

    if not shm:get("data") then
        shm:set("data", cjson.encode(_M.defaults))
        shm:set("version", 0)
    end
end

-- Pull the latest configuration from Redis into the shared dict. Worker 0 only.
function _M.sync()
    local red, err = util.redis()
    if not red then
        ngx.log(ngx.WARN, "moswaf: cannot reach redis to sync the config: ", err)
        return false
    end

    local raw, rerr = red:get(CONFIG_KEY)
    util.redis_release(red)

    if not raw or raw == ngx.null then
        if rerr then ngx.log(ngx.WARN, "moswaf: failed to read the config: ", rerr) end
        return false
    end

    local conf = cjson.decode(raw)
    if not conf or type(conf) ~= "table" then
        ngx.log(ngx.ERR, "moswaf: the config in Redis is not valid JSON")
        return false
    end

    local cur = shm:get("version") or -1
    local new = tonumber(conf.version) or 0
    if new == cur then return true end

    shm:set("data", raw)
    shm:set("version", new)
    ngx.log(ngx.NOTICE, "moswaf: loaded configuration version ", new)
    return true
end

-- The decoded configuration, cached by version
function _M.get()
    local ver = shm:get("version") or 0
    if cached and cached_ver == ver then return cached end

    local raw = shm:get("data")
    local conf = raw and cjson.decode(raw) or nil
    if type(conf) ~= "table" then conf = _M.defaults end

    -- fill any missing fields from the defaults
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
    if ngx.worker.id() ~= 0 then return end     -- one worker syncing is enough

    local function tick(premature)
        if premature then return end
        local ok, err = pcall(_M.sync)
        if not ok then ngx.log(ngx.ERR, "moswaf: config sync error: ", err) end
        local ok2, err2 = ngx.timer.at(SYNC_PERIOD, tick)
        if not ok2 then ngx.log(ngx.ERR, "moswaf: could not schedule the config timer: ", err2) end
    end

    -- Never call _M.sync() directly here: this runs in the init_worker phase, and that
    -- phase cannot use cosockets (ngx.socket.tcp). A direct call throws, which aborts
    -- the rest of worker startup so the sync timer is never scheduled - leaving the
    -- engine running forever on its defaults. A 0 second timer still syncs immediately.
    local ok, err = ngx.timer.at(0, tick)
    if not ok then ngx.log(ngx.ERR, "moswaf: could not schedule the config timer: ", err) end
end

return _M
