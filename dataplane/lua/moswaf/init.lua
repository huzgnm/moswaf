-- moswaf.init - nap engine luc nginx khoi dong
local _M = {}

function _M.init()
    -- nap san cac module de moi worker dung chung bytecode
    local config = require "moswaf.config"
    require "moswaf.util"
    require "moswaf.rules"
    require "moswaf.ipset"
    require "moswaf.ratelimit"
    require "moswaf.challenge"
    require "moswaf.log"
    require "moswaf.access"

    config.bootstrap()
    ngx.log(ngx.NOTICE, "moswaf: engine da nap")
end

function _M.init_worker()
    local config = require "moswaf.config"
    local log    = require "moswaf.log"
    local ipset  = require "moswaf.ipset"

    math.randomseed(ngx.now() * 1000 + ngx.worker.pid())

    config.start_sync()     -- keo cau hinh tu control plane
    log.start_flush()       -- day su kien + thong ke

    -- don ban het han (mot worker la du)
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
