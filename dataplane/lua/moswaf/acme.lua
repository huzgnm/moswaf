-- moswaf.acme - serve the ACME HTTP-01 challenge
--
-- The certificate authority fetches
--     http://<domain>/.well-known/acme-challenge/<token>
-- while validating a domain. The control plane is the side talking to the CA, so it
-- puts the expected response in Redis under moswaf:acme:<token> with a short TTL and
-- this handler reads it back out.
--
-- Going through Redis rather than a directory shared by both containers keeps the
-- planes decoupled: they already share Redis for the configuration, and the answer
-- is short-lived by nature.
--
-- The path is deliberately reachable before every other check in access.lua. It has
-- to be: a site whose certificate expired still needs to renew, and a visitor-facing
-- block would stop the CA from ever reaching the token.

local util = require "moswaf.util"

local _M = {}

local PREFIX = "moswaf:acme:"

function _M.serve()
    local token = ngx.var.uri:match("/%.well%-known/acme%-challenge/([%w%-_]+)$")
    if not token then
        return ngx.exit(404)
    end

    local red, err = util.redis()
    if not red then
        ngx.log(ngx.ERR, "moswaf: cannot reach redis to answer an acme challenge: ", err)
        return ngx.exit(500)
    end

    local response, rerr = red:get(PREFIX .. token)
    util.redis_release(red)

    if not response or response == ngx.null then
        if rerr then
            ngx.log(ngx.ERR, "moswaf: reading the acme token failed: ", rerr)
        end
        ngx.log(ngx.WARN, "moswaf: no acme challenge is pending for token ", token)
        return ngx.exit(404)
    end

    ngx.header["Content-Type"] = "text/plain"
    ngx.header["Cache-Control"] = "no-store"
    ngx.print(response)
    return ngx.exit(200)
end

return _M
