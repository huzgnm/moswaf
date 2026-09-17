-- moswaf.init - load the engine when nginx starts
local _M = {}

function _M.init()
    -- preload the modules so every worker shares the same bytecode
    local config = require "moswaf.config"
    require "moswaf.util"
    require "moswaf.rules"
    require "moswaf.ipset"
    require "moswaf.ratelimit"
    require "moswaf.challenge"
    require "moswaf.log"
    require "moswaf.access"

    config.bootstrap()
    ngx.log(ngx.NOTICE, "moswaf: engine loaded")
end

function _M.init_worker()
    local config = require "moswaf.config"
    local log    = require "moswaf.log"
    local ipset  = require "moswaf.ipset"

    math.randomseed(ngx.now() * 1000 + ngx.worker.pid())

    -- Wrap each part in its own pcall: if one fails the rest still runs, instead of
    -- aborting the whole worker startup as it did before.
    local ok, err = pcall(config.start_sync)   -- pull configuration from the control plane
    if not ok then ngx.log(ngx.ERR, "moswaf: could not start the config sync: ", err) end

    ok, err = pcall(log.start_flush)           -- ship events and statistics
    if not ok then ngx.log(ngx.ERR, "moswaf: could not start the log shipper: ", err) end

    -- sweep expired bans (one worker is enough)
    if ngx.worker.id() == 0 then
        local function tick(premature)
            if premature then return end
            pcall(ipset.flush_expired)
            ngx.timer.at(60, tick)
        end
        ngx.timer.at(60, tick)
    end
end

return _M
