-- moswaf.challenge - a proof-of-work JS challenge
--
-- The idea: before letting a visitor in, make the browser find a nonce such that
-- sha256(salt .. nonce) starts with N zero bits. A real browser solves it in about
-- 0.1-0.3s, a plain curl or python bot fails outright, and a botnet that wants to
-- keep flooding pays thousands of times more CPU than the server does.
--
-- That last sentence is only true if a solution cannot be shared, and the first
-- version of this got it wrong. The salt was bound to nobody and the signature
-- covered the salt alone, with no record of a salt having been spent - so one
-- machine could solve once and hand (salt, signature, nonce) to the whole
-- botnet, each member replaying it for its own cookie without doing any work.
-- The defence collapsed to one solve every two minutes for an entire botnet,
-- precisely when it matters: under attack, where it is the thing holding the
-- line. Two changes close it, and both are here because either alone leaves a
-- case open:
--
--   the signature binds the salt to the address it was issued to, so a solution
--   is worthless anywhere else;
--
--   and a salt is spent when it is redeemed, so it cannot be replayed even from
--   the address that earned it - which is what a farm behind one NAT would do.
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

-- Salts already redeemed. Keyed by salt, expiring with it, so the table holds at
-- most two minutes of traffic.
local spent = ngx.shared.moswaf_chal

-- No fallback value here on purpose: a default published in this repository would
-- let anyone forge the __moswaf cookie and walk past the challenge. If the variable
-- is missing the engine says so and refuses to issue challenges it cannot verify.
local SECRET = os.getenv("MOSWAF_CHALLENGE_SECRET")
if not SECRET or SECRET == "" then
    ngx.log(ngx.ERR, "moswaf: MOSWAF_CHALLENGE_SECRET is not set - the JS challenge ",
            "is disabled because its cookie could be forged by anyone")
end

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

-- The signature over a salt, bound to the address it was issued to.
--
-- Binding is what stops a solved challenge being passed around: the verifier
-- recomputes this with the address of whoever is presenting it, so a solution
-- earned at one address does not verify at another. A visitor whose address
-- changes between the page and the solve is challenged again, which is rare and
-- costs one puzzle.
local function salt_sig(salt, ip)
    return util.hmac(SECRET, salt .. "|" .. (ip or ""))
end

-- Redeem a salt, once.
--
-- add() is the atomic half: it fails when the key is already there, so two
-- requests racing with the same salt cannot both win. Only "exists" is a
-- refusal - if the dictionary is full or missing, the salt is allowed through
-- and the address binding above still stands. Refusing on a full dictionary
-- would turn a memory problem into every visitor being unable to pass the
-- challenge at all, which is the failure this defence exists to prevent.
local function spend_salt(salt)
    if not spent then return true end
    local ok, err = spent:add("s:" .. salt, 1, SALT_TTL)
    if ok then return true end
    if err == "exists" then return false end
    ngx.log(ngx.WARN, "moswaf: cannot record a spent challenge salt (", tostring(err),
            "); replay is still blocked by the address binding")
    return true
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
    if not SECRET or SECRET == "" then
        -- Better to let the request through than to hand out a cookie anyone can mint
        ngx.log(ngx.ERR, "moswaf: cannot issue a challenge without MOSWAF_CHALLENGE_SECRET")
        return
    end
    local st   = config.get().settings
    local bits = tonumber(st.challenge_difficulty) or 16
    local salt = new_salt()
    local sig  = salt_sig(salt, ip)
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
    -- Recomputed with the address presenting it, not the one it was issued to:
    -- that is the check that makes a shared solution useless.
    if not util.const_eq(sig, salt_sig(salt, ip)) then return fail("bad signature") end
    if #nonce > 32 then return fail("nonce too long") end
    if not pow_ok(salt, nonce, bits) then return fail("invalid proof of work") end
    -- Last, and only once the work has been checked: spending a salt on a request
    -- that was going to fail anyway would let anyone burn a visitor's challenge
    -- by replaying its salt with a wrong nonce.
    if not spend_salt(salt) then return fail("challenge already used") end

    set_cookie(ip, ua, ttl)

    local target = "/"
    if type(ret) == "string" and ret ~= "" then
        local decoded = ngx.decode_base64((ret:gsub("-", "+"):gsub("_", "/")) .. "==")
        if decoded and util.is_local_path(decoded) then
            target = decoded
        end
    end

    ngx.header["Cache-Control"] = "no-store"
    return ngx.redirect(target, 302)
end

return _M
