-- moswaf.challenge - a proof-of-work JS challenge
--
-- The idea: before letting a visitor in, make the browser find a nonce such that
-- sha256(salt .. nonce) starts with N zero bits. A real browser solves it in about
-- 0.1-0.3s, a plain curl or python bot fails outright, and a botnet that wants to
-- keep flooding pays thousands of times more CPU than the server does.
--
-- Flow:
--   1. No valid cookie      -> serve the challenge page (status 503, never cached)
--   2. The page solves it   -> GET /__moswaf/verify?s=&g=&n=&r=
--   3. Verification passes  -> issue an HMAC-signed cookie, 302 back to the URL

local sha256 = require "resty.sha256"
local config = require "moswaf.config"
local util   = require "moswaf.util"

local _M = {}

local COOKIE     = "__moswaf"
local VERIFY_URI = "/__moswaf/verify"
local SALT_TTL   = 120        -- a salt is valid for 2 minutes

local SECRET = os.getenv("MOSWAF_CHALLENGE_SECRET") or "moswaf-insecure-default"

_M.verify_uri = VERIFY_URI

-- ------------------------------------------------------------- cookie

local function cookie_value(ip, ua, ttl)
    local exp = ngx.time() + ttl
    return exp .. "." .. util.hmac(SECRET, ip .. "|" .. (ua or "") .. "|" .. exp)
end

function _M.has_valid_cookie(ip, ua)
    local c = ngx.var["cookie_" .. COOKIE]
    if not c or c == "" then return false end

    local exp, sig = c:match("^(%d+)%.([%w%-_]+)$")
    if not exp then return false end

    exp = tonumber(exp)
    if not exp or exp < ngx.time() then return false end

    local want = util.hmac(SECRET, ip .. "|" .. (ua or "") .. "|" .. exp)
    return util.const_eq(sig, want)
end

local function set_cookie(ip, ua, ttl)
    local v = cookie_value(ip, ua, ttl)
    local parts = { COOKIE, "=", v, "; Path=/; Max-Age=", ttl, "; HttpOnly; SameSite=Lax" }
    if ngx.var.scheme == "https" then parts[#parts + 1] = "; Secure" end
    ngx.header["Set-Cookie"] = table.concat(parts)
end

-- ------------------------------------------------------------- proof of work

local function leading_zero_bits(digest)
    local n = 0
    for i = 1, #digest do
        local b = string.byte(digest, i)
        if b == 0 then
            n = n + 8
        else
            local v, c = b, 0
            while v < 128 do v = v * 2; c = c + 1 end
            return n + c
        end
    end
    return n
end

local function pow_ok(salt, nonce, bits)
    local s = sha256:new()
    s:update(salt .. nonce)
    return leading_zero_bits(s:final()) >= bits
end

-- the salt carries its issue time so it expires on its own
local function new_salt()
    return util.hex(ngx.md5_bin(ngx.var.request_id or tostring(math.random()))):sub(1, 16)
        .. "-" .. ngx.time()
end

local function salt_fresh(salt)
    local ts = salt:match("%-(%d+)$")
    ts = tonumber(ts)
    if not ts then return false end
    local age = ngx.time() - ts
    return age >= 0 and age <= SALT_TTL
end

-- ------------------------------------------------------------- handlers

-- Serve the challenge page. The request ends here.
function _M.serve(ip, ua, reason)
    local st   = config.get().settings
    local bits = tonumber(st.challenge_difficulty) or 16
    local salt = new_salt()
    local sig  = util.hmac(SECRET, salt)
    local ret  = util.b64url(ngx.var.request_uri or "/")

    local html = config.challenge_html
        :gsub("{{SALT}}", salt)
        :gsub("{{SIG}}", sig)
        :gsub("{{BITS}}", tostring(bits))
        :gsub("{{RET}}", ret)
        :gsub("{{VERIFY}}", VERIFY_URI)
        :gsub("{{REASON}}", reason or "")

    ngx.status = 503
    ngx.header["Content-Type"]  = "text/html; charset=utf-8"
    ngx.header["Cache-Control"] = "no-store, no-cache, must-revalidate"
    ngx.header["Retry-After"]   = "5"
    ngx.print(html)
    return ngx.exit(503)
end

-- Handle /__moswaf/verify. The request ends here.
function _M.handle_verify(ip, ua)
    local args = ngx.req.get_uri_args(10)
    local salt, sig, nonce, ret = args.s, args.g, args.n, args.r
    local st   = config.get().settings
    local bits = tonumber(st.challenge_difficulty) or 16
    local ttl  = tonumber(st.challenge_ttl) or 1800

    local function fail(msg)
        ngx.status = 403
        ngx.header["Content-Type"] = "text/plain; charset=utf-8"
        ngx.print("MosWAF: challenge failed (" .. msg .. ")")
        return ngx.exit(403)
    end

    if type(salt) ~= "string" or type(sig) ~= "string" or type(nonce) ~= "string" then
        return fail("missing parameters")
    end
    if not salt_fresh(salt) then return fail("salt expired") end
    if not util.const_eq(sig, util.hmac(SECRET, salt)) then return fail("bad signature") end
    if #nonce > 32 then return fail("nonce too long") end
    if not pow_ok(salt, nonce, bits) then return fail("invalid proof of work") end

    set_cookie(ip, ua, ttl)

    local target = "/"
    if type(ret) == "string" and ret ~= "" then
        local decoded = ngx.decode_base64((ret:gsub("-", "+"):gsub("_", "/")) .. "==")
        -- only allow internal paths, to prevent an open redirect
        if decoded and decoded:sub(1, 1) == "/" and decoded:sub(2, 2) ~= "/" then
            target = decoded
        end
    end

    ngx.header["Cache-Control"] = "no-store"
    return ngx.redirect(target, 302)
end

return _M
