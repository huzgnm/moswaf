-- moswaf.auth - a login gate in front of a site
--
-- Nobody reaches the upstream without a session. Used to put a password in front
-- of an admin panel, a staging site, or anything that was written without one.
--
-- The session is a signed cookie and nothing else: verifying it reads memory and
-- makes no call to anything, because it happens on every request. Signing in is
-- the expensive half and happens once per session, so that is handled by the
-- control plane, which is also the only side that ever sees a password.

local util = require "moswaf.util"

local _M = {}

-- These three have to be the same strings the generated nginx config routes on -
-- see loginPath / logoutPath in control/internal/engine/nginxconf.go. A login page
-- nginx sends somewhere other than where the gate exempts is a gate with a hole in
-- it, so there is a test that compares the two.
local COOKIE     = "__moswaf_auth"
local LOGIN_URI  = "/__moswaf/login"
local LOGOUT_URI = "/__moswaf/logout"

-- The same key the JavaScript challenge signs with, and that is a decision rather
-- than an oversight. A second secret would be a second thing to generate at
-- install, carry through an upgrade, and fail to rotate, for no separation:
-- anything able to read one can read the other, since they live in the same file
-- on the same host for the same two processes. What keeps the two uses from being
-- confused is the signed string - a challenge token and a session token have
-- different shapes and neither parses as the other.
--
-- No default. A key written into this repository would let anybody mint a session
-- for any protected site, so with nothing configured the gate refuses every
-- request rather than pretending to check them.
local SECRET = os.getenv("MOSWAF_CHALLENGE_SECRET")

_M.login_uri  = LOGIN_URI
_M.logout_uri = LOGOUT_URI

-- ------------------------------------------------------------- inbound headers
--
-- Everything MosWAF tells the upstream about a request travels in an X-MosWAF-*
-- header, and every one of those means "the WAF established this". A request
-- arriving with one is a request trying to establish it for itself: send
-- X-MosWAF-User: admin and an upstream that trusts the gateway has been handed
-- an administrator. Send X-MosWAF-Token and the control plane's internal
-- endpoints think the data plane is calling.
--
-- So the whole namespace is cleared, unconditionally, on every request to every
-- site - including sites with no gate. A site without the gate has no business
-- receiving a forged identity either, and "we only clear it where we use it" is
-- the rule that leaves a hole the next time someone adds a header.
--
-- Clearing by prefix rather than by a list of names is deliberate for the same
-- reason: a new header is covered the day it is invented, not the day somebody
-- remembers to add it here.
local TRUSTED_PREFIX = "x-moswaf-"

function _M.strip_trusted_headers()
    local h = ngx.req.get_headers(0, true)
    for name in pairs(h) do
        -- nginx gives header names lowercased with dashes; a client may send
        -- underscores, which some servers fold to dashes downstream, so both
        -- spellings are removed.
        local lower = name:lower()
        if lower:sub(1, #TRUSTED_PREFIX) == TRUSTED_PREFIX
           or lower:sub(1, #TRUSTED_PREFIX):gsub("_", "-") == TRUSTED_PREFIX then
            ngx.req.clear_header(name)
        end
    end
end

-- ------------------------------------------------------------- session cookie

-- What gets signed. Every field is part of the signature, so none of them can be
-- edited on the way back.
local function payload(site_id, user_id, generation, exp)
    return table.concat({ site_id, user_id, generation, exp }, "|")
end

function _M.sign(site_id, user_id, generation, exp)
    return table.concat({ user_id, generation, exp,
        util.hmac(SECRET, payload(site_id, user_id, generation, exp)) }, ".")
end

--- Verify a session cookie against the site now being served.
--
-- Two checks, and the second is not implied by the first.
--
-- The signature proves the token was issued by us. It does not prove it was
-- issued for HERE: one secret signs every site, so a cookie minted for site A
-- carries a perfectly valid signature when presented at site B. Comparing the
-- site id the token names against the site actually being served is what makes a
-- session belong to one site, and it has to take that id from the configuration,
-- never from the token - a value the token supplies cannot be used to check the
-- token.
--
-- Returns: user id, or nil and a short reason.
function _M.verify(site_id, cookie, generations, now)
    if not SECRET or SECRET == "" then return nil, "no_secret" end
    if not cookie or cookie == "" then return nil, "no_cookie" end

    local user_id, generation, exp, sig =
        cookie:match("^(%d+)%.(%d+)%.(%d+)%.([%w%-_]+)$")
    if not user_id then return nil, "malformed" end

    if tonumber(exp) <= now then return nil, "expired" end

    -- site_id comes from the site being served, not from the cookie.
    local want = util.hmac(SECRET, payload(site_id, user_id, generation, exp))
    if not util.const_eq(sig, want) then return nil, "bad_signature" end

    -- The account still has to exist, and the session still has to be current.
    -- An account that was deleted is absent from this map, which refuses its
    -- sessions without anything having to be counted or cleaned up.
    --
    -- Checked as a table rather than for nil: a site with no accounts is published
    -- as JSON null, and cjson decodes null to a userdata that is perfectly truthy
    -- and throws when indexed. "and generations[...]" alone would turn the empty
    -- case into a 500 on every request.
    if type(generations) ~= "table" then return nil, "no_such_user" end
    local current = generations[user_id]
    if current == nil then return nil, "no_such_user" end
    if tostring(current) ~= generation then return nil, "revoked" end

    return user_id
end

function _M.cookie_value()
    local c = ngx.var["cookie_" .. COOKIE]
    if c == "" then return nil end
    return c
end

function _M.set_cookie(value, ttl)
    local parts = { COOKIE, "=", value, "; Path=/; Max-Age=", ttl,
                    "; HttpOnly; SameSite=Lax" }
    if ngx.var.scheme == "https" then parts[#parts + 1] = "; Secure" end
    ngx.header["Set-Cookie"] = table.concat(parts)
end

-- ------------------------------------------------------------- path matching

local ACME_PREFIX = "/.well-known/acme-challenge/"

--- Is this request behind the gate?
--
-- Called with ngx.var.uri, which nginx has already percent-decoded and collapsed,
-- so "/adm%69n" and "/admin/./" are both "/admin" by the time they arrive here.
-- Matching on the raw request line instead would let either of those spellings
-- walk past a gate configured for "/admin".
--
-- Two exemptions, and both are compared exactly rather than by prefix, because an
-- exemption that matches more than it names is a way past the gate:
-- "/__moswaf/login" as a prefix would also exempt "/__moswaf/loginbypass".
function _M.gated(uri, site)
    if uri == LOGIN_URI or uri == LOGOUT_URI then return false end
    -- The certificate authority has to reach this whatever else is configured, or
    -- the site loses the ability to renew and quietly expires behind a login page
    -- nobody thought was in the way.
    if uri:sub(1, #ACME_PREFIX) == ACME_PREFIX then return false end

    local paths = site.auth_paths
    if not paths or #paths == 0 then return true end   -- no list means the whole site

    -- Compared without case. A gate configured for "/admin" that let "/ADMIN"
    -- through would be no gate at all in front of the several upstreams that treat
    -- paths case-insensitively - IIS, and anything on a Mac volume. Ignoring case
    -- can only ever protect more than was asked for, never less, so it is the side
    -- to be wrong on.
    local lower = uri:lower()

    for i = 1, #paths do
        local p = paths[i]
        if p and p ~= "" then
            p = p:lower()
            -- "/x" covers "/x" and everything under "/x/", and stops there. A plain
            -- prefix test would put "/administrator" behind a gate the operator
            -- asked for on "/admin" - fail-closed, but not what they wrote.
            if p == "/" or lower == p or lower:sub(1, #p + 1) == p .. "/" then
                return true
            end
        end
    end
    return false
end

-- What the upstream is told about who this is. Set only after a session has been
-- verified, and only ever after the inbound namespace has been cleared.
function _M.announce(user_id)
    if user_id and user_id ~= "" then
        ngx.req.set_header("X-MosWAF-User", user_id)
    end
end

-- ------------------------------------------------------------- enforcement

-- Where to send the visitor back to after signing in.
--
-- Rebuilt from $uri and $args rather than taken from $request_uri, because $uri
-- has already been decoded and normalised: that is the form the gate compared
-- against, so it is the form that will be compared against again on the way back.
local function return_to()
    local uri = ngx.var.uri or "/"
    local args = ngx.var.args
    if args and args ~= "" then uri = uri .. "?" .. args end
    if not util.is_local_path(uri) then return "/" end
    return uri
end

--- Refuse a request that has no session, in whichever way suits the caller.
--
-- A browser being navigated wants the login page. Anything else - a fetch(), an
-- API client, an image - wants a status code: answering those with a redirect to
-- an HTML page produces a 200 full of markup where JSON was expected, which is a
-- harder failure to read than the 401 that was true all along.
function _M.refuse(reason)
    local accept = ngx.var.http_accept or ""
    local method = ngx.var.request_method
    local navigation = (method == "GET" or method == "HEAD")
        and accept:find("text/html", 1, true) ~= nil

    if navigation then
        ngx.header["Cache-Control"] = "no-store"
        return ngx.redirect(LOGIN_URI .. "?next=" .. ngx.escape_uri(return_to()), 302)
    end

    ngx.status = ngx.HTTP_UNAUTHORIZED
    ngx.header["Content-Type"]  = "application/json"
    ngx.header["Cache-Control"] = "no-store"
    -- No detail. "no such user" and "wrong generation" are answers to questions
    -- the person asking has not earned, and the difference between them tells an
    -- attacker which account ids exist.
    ngx.print('{"error":"authentication required"}')
    return ngx.exit(ngx.HTTP_UNAUTHORIZED)
end

return _M
