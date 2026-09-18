-- moswaf.login - the sign-in page for a site behind the gate
--
-- Served from here rather than from the control plane so that the page itself
-- stays up when the control plane does not. Only the one request that carries a
-- password goes across, because only the control plane has the hashes and only it
-- should be running bcrypt.

local config = require "moswaf.config"
local util   = require "moswaf.util"
local auth   = require "moswaf.auth"
local cjson  = require "cjson.safe"

local _M = {}

-- The internal location that proxies to the control plane. Marked `internal` in
-- the generated nginx config, so it can be reached from here and from nowhere
-- outside.
local BACKEND = "/__moswaf_auth_backend"

local MAX_FIELD = 256   -- a username or password longer than this is not one

-- -------------------------------------------------------------------- page

local ESCAPES = { ["&"] = "&amp;", ["<"] = "&lt;", [">"] = "&gt;",
                  ['"'] = "&quot;", ["'"] = "&#39;" }

local function esc(s)
    return (tostring(s or ""):gsub("[&<>\"']", ESCAPES))
end

local PAGE = [[<!doctype html>
<html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow">
<title>Sign in</title>
<style>
  :root { color-scheme: dark }
  * { box-sizing: border-box }
  body { margin:0; min-height:100vh; display:flex; align-items:center;
         justify-content:center; background:#0b0e14; color:#c9d1d9;
         font:15px/1.5 system-ui,-apple-system,Segoe UI,Roboto,sans-serif }
  form { width:100%; max-width:340px; padding:32px 28px;
         background:#11151d; border:1px solid #1f2630; border-radius:12px }
  h1 { margin:0 0 4px; font-size:17px; font-weight:600 }
  p.sub { margin:0 0 22px; font-size:13px; color:#7d8794 }
  label { display:block; margin:0 0 6px; font-size:13px; color:#9aa4b1 }
  input { width:100%; padding:9px 11px; margin:0 0 16px; font-size:14px;
          color:#e6edf3; background:#0b0e14; border:1px solid #242c38;
          border-radius:7px; outline:none }
  input:focus { border-color:#3b82f6 }
  button { width:100%; padding:10px; font-size:14px; font-weight:600;
           color:#fff; background:#2563eb; border:0; border-radius:7px;
           cursor:pointer }
  button:hover { background:#1d4ed8 }
  .err { margin:0 0 16px; padding:9px 11px; font-size:13px; color:#fca5a5;
         background:#2a1215; border:1px solid #5b1f24; border-radius:7px }
  .foot { margin:18px 0 0; font-size:11px; color:#4c5563; text-align:center }
</style>
</head><body>
<form method="post" autocomplete="on">
  <h1>Sign in</h1>
  <p class="sub">{{SITE}}</p>
  {{ERROR}}
  <input type="hidden" name="next" value="{{NEXT}}">
  <label for="u">Username</label>
  <input id="u" name="username" autocomplete="username" autofocus required maxlength="64">
  <label for="p">Password</label>
  <input id="p" name="password" type="password" autocomplete="current-password" required maxlength="256">
  <button type="submit">Sign in</button>
  <p class="foot">Protected by MosWAF</p>
</form>
</body></html>]]

local function render(status, site_name, next_path, err)
    -- Each replacement is a function, not a string. gsub reads "%1" and friends in
    -- a replacement string as capture references, so a value containing a percent
    -- sign - which any percent-encoded path does - would either be mangled or
    -- raise "invalid capture index" and turn the login page into a 500. A function
    -- returns its value verbatim.
    local html = PAGE
        :gsub("{{SITE}}",  function() return esc(site_name) end)
        :gsub("{{NEXT}}",  function() return esc(next_path) end)
        :gsub("{{ERROR}}", function()
            if not err then return "" end
            return '<p class="err">' .. esc(err) .. "</p>"
        end)

    ngx.status = status
    ngx.header["Content-Type"]  = "text/html; charset=utf-8"
    -- A page that reflects a failed attempt and sets a session must never be
    -- stored by a shared cache between here and the visitor.
    ngx.header["Cache-Control"] = "no-store, private"
    ngx.header["X-Robots-Tag"]  = "noindex, nofollow"
    ngx.print(html)
    -- ngx.exit(ngx.HTTP_OK) in the content phase means "this handler is finished",
    -- and the status already set above is the one sent. Passing the real status
    -- here instead would discard what was just printed and substitute nginx's own
    -- error page.
    return ngx.exit(ngx.HTTP_OK)
end

-- ------------------------------------------------------------------- input

local function form_field(args, name)
    local v = args[name]
    -- A repeated field arrives as a table. Refuse rather than pick one: which one
    -- nginx would hand over is not the same question as which one the visitor
    -- meant, and "username=admin&username=x" is a way to ask two things at once.
    if type(v) ~= "string" then return nil end
    if #v > MAX_FIELD then return nil end
    return v
end

-- Where the form was submitted from.
--
-- A login form is the one place where a cross-site POST has a use: it signs the
-- visitor into an account the attacker controls, so that what they do afterwards
-- is recorded against it, and it is the first step of several phishing patterns.
-- There is no session yet, so there is nowhere to keep a token; the origin of the
-- request is what is available, and a browser will not let a page lie about it.
--
-- A request with neither header is allowed through. Some privacy tools strip both,
-- and refusing those visitors would be refusing people who are doing nothing
-- wrong, to prevent something an attacker cannot arrange from a browser anyway -
-- the attack needs the victim's browser to send the request, and that browser
-- sends the header.
local function same_origin()
    local origin = ngx.var.http_origin
    local host   = ngx.var.http_host or ngx.var.host or ""
    if origin and origin ~= "" then
        -- Compared against the Host the request was addressed to, not against the
        -- configured domains: a site may answer on several names and each of them
        -- is its own origin.
        local want = ngx.var.scheme .. "://" .. host
        return origin == want
    end
    local referer = ngx.var.http_referer
    if referer and referer ~= "" then
        local prefix = ngx.var.scheme .. "://" .. host
        return referer == prefix or referer:sub(1, #prefix + 1) == prefix .. "/"
    end
    return true
end

-- ----------------------------------------------------------------- handler

function _M.serve()
    local conf    = config.get()
    local site_id = ngx.var.moswaf_site or ""
    local site    = conf.sites[site_id] or {}
    local name    = site.name or ngx.var.http_host or "This site"

    -- The gate being off makes this page meaningless, and leaving it reachable
    -- would let anyone enumerate which sites have it switched on.
    if not site.auth_enabled then
        return ngx.exit(ngx.HTTP_NOT_FOUND)
    end

    local args = ngx.req.get_uri_args(20)
    local next_path = args.next
    if type(next_path) ~= "string" or not util.is_local_path(next_path) then
        next_path = "/"
    end

    if ngx.var.request_method ~= "POST" then
        -- Already signed in: no reason to show the form again.
        local ok = auth.verify(site_id, auth.cookie_value(), site.auth_users, ngx.time())
        if ok then
            return ngx.redirect(next_path, 302)
        end
        return render(ngx.HTTP_OK, name, next_path, nil)
    end

    if not same_origin() then
        return render(ngx.HTTP_FORBIDDEN, name, next_path,
            "That request did not come from this site. Please try again from the sign-in page.")
    end

    ngx.req.read_body()
    local post = ngx.req.get_post_args(20)
    if not post then
        return render(ngx.HTTP_BAD_REQUEST, name, next_path, "Could not read that form.")
    end

    -- The form's own next wins over the query string: it is the one that survived
    -- the round trip through the page the visitor was actually looking at.
    local posted_next = post.next
    if type(posted_next) == "string" and util.is_local_path(posted_next) then
        next_path = posted_next
    end

    local username = form_field(post, "username")
    local password = form_field(post, "password")
    if not username or not password or username == "" or password == "" then
        return render(ngx.HTTP_BAD_REQUEST, name, next_path,
            "Please fill in both fields.")
    end

    local body = cjson.encode({
        username = username,
        password = password,
        next     = next_path,
    })
    if not body then
        return render(ngx.HTTP_BAD_REQUEST, name, next_path, "Could not read that form.")
    end

    -- The site and the client address are passed as headers the control plane
    -- trusts, because they come from here and not from the form. Letting the body
    -- name the site would let somebody with an account on their own site ask for a
    -- session on somebody else's.
    local res = ngx.location.capture(BACKEND, {
        method = ngx.HTTP_POST,
        body   = body,
        vars   = {
            moswaf_auth_site  = site_id,
            moswaf_auth_ip    = util.client_ip(conf.settings) or "",
            moswaf_auth_token = conf.internal_token or "",
        },
    })

    if not res then
        return render(ngx.HTTP_SERVICE_UNAVAILABLE, name, next_path,
            "Sign-in is temporarily unavailable. Please try again shortly.")
    end

    if res.status == 200 then
        local decoded = cjson.decode(res.body or "")
        if type(decoded) ~= "table" or type(decoded.token) ~= "string" then
            return render(ngx.HTTP_SERVICE_UNAVAILABLE, name, next_path,
                "Sign-in is temporarily unavailable. Please try again shortly.")
        end
        auth.set_cookie(decoded.token, tonumber(decoded.max_age) or 3600)
        -- 303 so that the browser follows with GET. A 302 after a POST is allowed
        -- to be repeated as a POST, which would put the password back on the wire
        -- against a page that is not expecting one.
        return ngx.redirect(next_path, 303)
    end

    if res.status == 429 then
        return render(429, name, next_path,
            "Too many attempts. Please wait a few minutes and try again.")
    end
    if res.status == 401 then
        -- Deliberately one message for a wrong name and a wrong password.
        return render(ngx.HTTP_UNAUTHORIZED, name, next_path,
            "Wrong username or password.")
    end
    return render(ngx.HTTP_SERVICE_UNAVAILABLE, name, next_path,
        "Sign-in is temporarily unavailable. Please try again shortly.")
end

-- ------------------------------------------------------------------ logout
--
-- Clears the cookie here and sends the visitor to the login page. It does not end
-- the session everywhere - that is a generation bump, which only the control plane
-- can write - so a cookie already copied off the machine stays valid until it
-- expires. The dashboard's "sign out everywhere" is the button that closes that,
-- and the difference is stated there rather than left to be discovered.
function _M.logout()
    auth.set_cookie("", 0)
    ngx.header["Cache-Control"] = "no-store"
    return ngx.redirect(auth.login_uri, 303)
end

return _M
