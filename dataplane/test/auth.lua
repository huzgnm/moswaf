-- Tests for moswaf.auth - the login gate in front of a site.
--
-- Written as the attacks, because the design has three places where a plausible
-- implementation is wrong in a way that looks right:
--
--   1. One secret signs every site. A cookie minted for site A therefore carries a
--      perfectly valid signature at site B, and checking the signature alone -
--      which is what "verify the token" normally means - is a cross-site session
--      forgery with no forgery in it. The site has to be compared separately, and
--      against the site being served, never against what the cookie says.
--
--   2. Sessions are revoked by a number in the published configuration, not by
--      deleting a row anywhere. If an account missing from that map were treated
--      as "nothing to check", deleting a user would leave their cookie working.
--
--   3. X-MosWAF-User is an identity the upstream is asked to trust. If it is only
--      stripped on gated sites, or only after the early returns, a request can
--      supply its own.
--
--   luajit dataplane/test/auth.lua

local ROOT = arg[0]:match("^(.*)/test/auth%.lua$") or "dataplane"
package.path = ROOT .. "/lua/?.lua;" .. ROOT .. "/lua/?/init.lua;" .. package.path

package.loaded["resty.redis"] = {}

-- ------------------------------------------------------------------ stubs

local cleared = {}
local inbound = {}

_G.ngx = {
    time = function() return 1700000000 end,
    var  = { scheme = "https" },
    req  = {
        get_headers  = function() return inbound end,
        clear_header = function(n) cleared[#cleared + 1] = n end,
        set_header   = function(n, v) inbound[n] = v end,
    },
    header = {},
    log = function() end, ERR = 1, WARN = 2,

    -- Stands in for the real HMAC. What these tests check is WHAT is signed - is
    -- the site part of the message? - not the strength of the primitive, which
    -- OpenResty supplies in production. It only has to be deterministic and to
    -- change when any part of the message changes.
    hmac_sha1 = function(secret, msg)
        local h = 5381
        for i = 1, #secret do h = (h * 33 + string.byte(secret, i)) % 2147483648 end
        for i = 1, #msg do h = (h * 33 + string.byte(msg, i)) % 2147483648 end
        return string.format("%010d", h)
    end,
    encode_base64 = function(s) return s end,
}

os.getenv = function(k)             -- luacheck: ignore
    if k == "MOSWAF_CHALLENGE_SECRET" then return "test-secret-for-the-gate" end
    return nil
end

local auth = require "moswaf.auth"

-- ---------------------------------------------------------------- harness

local failures, total = {}, 0
local function check(name, ok, detail)
    total = total + 1
    if ok then io.write(".") else
        io.write("F")
        failures[#failures + 1] = name .. (detail and ("\n      " .. detail) or "")
    end
end

local NOW = 1700000000
local LATER = NOW + 3600

-- Two sites and two accounts, as the data plane sees them after a publish.
local SITE_A = "sa1b2c3d4e"
local SITE_B = "sf5g6h7i8j"
local USERS_A = { ["7"] = 3, ["9"] = 1 }
local USERS_B = { ["7"] = 3 }   -- deliberately the same id and generation

-- =================================================================== signing

check("a session this gate issued is accepted",
    auth.verify(SITE_A, auth.sign(SITE_A, "7", "3", LATER), USERS_A, NOW) == "7")

-- 1. The attack the whole second check exists for.
--
-- Sign a session on a site you control - a staging box, a site you were given an
-- account on - and present the cookie at a site you were not. One secret signs
-- both, so the signature is genuine. Only comparing the site makes it fail, and
-- only if that comparison uses the site being served rather than the one named in
-- the token.
do
    local stolen = auth.sign(SITE_B, "7", "3", LATER)
    local user, why = auth.verify(SITE_A, stolen, USERS_A, NOW)
    check("a session signed for another site is refused", user == nil,
        "a cookie minted at " .. SITE_B .. " was accepted at " .. SITE_A ..
        "; one secret signs every site, so its signature was always going to " ..
        "verify - the site itself has to be compared (got " .. tostring(why) .. ")")
end

-- And the account being present on both sites with the same generation must not
-- rescue it: the two sites are separate whatever their tables happen to contain.
do
    local stolen = auth.sign(SITE_B, "7", "3", LATER)
    check("and not even when the same id exists on both sites",
        auth.verify(SITE_A, stolen, USERS_B, NOW) == nil)
end

-- =============================================================== tampering

do
    local token = auth.sign(SITE_A, "7", "3", LATER)
    local user, gen, exp, sig = token:match("^(%d+)%.(%d+)%.(%d+)%.(.+)$")

    check("a different account id with the same signature is refused",
        auth.verify(SITE_A, "9." .. gen .. "." .. exp .. "." .. sig, USERS_A, NOW) == nil,
        "the user id is inside the signed message, so editing it must break the " ..
        "signature; if it does not, any session is every session")

    check("a later expiry with the same signature is refused",
        auth.verify(SITE_A, user .. "." .. gen .. "." .. (LATER + 86400) .. "." .. sig,
                    USERS_A, NOW) == nil,
        "the expiry is signed; an editable one is a session that never ends")

    check("a rewritten generation is refused",
        auth.verify(SITE_A, user .. ".1." .. exp .. "." .. sig, USERS_A, NOW) == nil,
        "the generation is what revokes a session; if it can be rewritten, " ..
        "revoking does nothing")

    check("an invented signature is refused",
        auth.verify(SITE_A, user .. "." .. gen .. "." .. exp .. ".0000000000",
                    USERS_A, NOW) == nil)
end

-- ================================================================== expiry

do
    local expired = auth.sign(SITE_A, "7", "3", NOW - 1)
    local _, why = auth.verify(SITE_A, expired, USERS_A, NOW)
    check("an expired session is refused", why == "expired", tostring(why))

    -- Exactly at the boundary. "<=" rather than "<" so that a session cannot be
    -- valid during the second it expires.
    local edge = auth.sign(SITE_A, "7", "3", NOW)
    check("a session expiring this very second is refused",
        auth.verify(SITE_A, edge, USERS_A, NOW) == nil)
end

-- ============================================================== revocation

do
    -- 2. The password was changed, which bumped the generation. Every cookie
    -- issued before it has to stop working, or changing a password because it
    -- might be known is a gesture.
    local old = auth.sign(SITE_A, "7", "2", LATER)
    local _, why = auth.verify(SITE_A, old, USERS_A, NOW)
    check("a session from before the generation was bumped is refused",
        why == "revoked", tostring(why))

    -- The account was deleted, so it is simply absent from the published map.
    -- Absent must mean refused, not "nothing to compare against".
    local ghost = auth.sign(SITE_A, "42", "1", LATER)
    local _, why2 = auth.verify(SITE_A, ghost, USERS_A, NOW)
    check("a session belonging to a deleted account is refused",
        why2 == "no_such_user",
        "the account is gone from the published map; if a missing entry is read " ..
        "as 'nothing to check', deleting a user leaves their cookie working " ..
        "until it expires (got " .. tostring(why2) .. ")")
end

-- A site with no accounts at all is published as JSON null, which cjson decodes
-- to a userdata - truthy, and it throws when indexed. `generations and
-- generations[id]` would turn that into a 500 on every request to the site.
do
    local token = auth.sign(SITE_A, "7", "3", LATER)
    for _, empty in ipairs({ "nil", "userdata" }) do
        local value = empty == "nil" and nil or newproxy and newproxy() or {}
        local ok, res = pcall(auth.verify, SITE_A, token, value, NOW)
        check("an empty account table is refused rather than raising (" .. empty .. ")",
            ok and res == nil, ok and "returned " .. tostring(res) or tostring(res))
    end
end

-- ================================================================ nonsense

for _, bad in ipairs({
    "", ".", "7.3", "7.3.1700003600", "x.3.1700003600.0000000000",
    "7.3.1700003600.", "7.3.1700003600.sig with spaces",
    "../../etc/passwd", string.rep("7", 5000),
}) do
    local ok, res = pcall(auth.verify, SITE_A, bad, USERS_A, NOW)
    check("a malformed cookie is refused without raising: " .. bad:sub(1, 24),
        ok and res == nil, ok and "returned " .. tostring(res) or tostring(res))
end

check("no cookie at all is refused", auth.verify(SITE_A, nil, USERS_A, NOW) == nil)

-- ============================================================ path matching

local site = { auth_paths = { "/admin", "/billing/reports" } }

check("the listed path is behind the gate", auth.gated("/admin", site))
check("and everything under it",            auth.gated("/admin/users/new", site))
check("and its own trailing slash",         auth.gated("/admin/", site))

-- The bug a plain prefix test produces. Fail-closed, but not what the operator
-- wrote, and a login prompt on an unrelated page is a support ticket.
check("a path that merely starts with the same letters is not",
    not auth.gated("/administrator-guide", site),
    "\"/admin\" as a bare prefix also catches \"/administrator-guide\"")

check("an unrelated path is not gated", not auth.gated("/", site))
check("a deeper listed path works too",  auth.gated("/billing/reports/q3", site))
check("its parent is not gated",         not auth.gated("/billing", site))

-- A gate on "/admin" that lets "/ADMIN" through is no gate at all in front of the
-- several upstreams that treat paths without case - IIS, anything on a Mac
-- volume. Ignoring case can only ever protect more than was asked for.
check("case is ignored", auth.gated("/ADMIN/Users", site))

-- An empty list means the whole site: a gate switched on with nothing listed must
-- protect everything rather than nothing.
check("no list means the whole site", auth.gated("/anything", { auth_paths = {} }))
check("and so does a missing one",    auth.gated("/anything", {}))
check("\"/\" means the whole site",   auth.gated("/anything", { auth_paths = { "/" } }))

-- The two exemptions. Compared exactly, because an exemption that matches more
-- than it names is a way past the gate.
check("the login page is not gated",  not auth.gated(auth.login_uri, { auth_paths = {} }))
check("the logout page is not gated", not auth.gated(auth.logout_uri, { auth_paths = {} }))
check("a path that only begins like the login page IS gated",
    auth.gated(auth.login_uri .. "bypass", { auth_paths = {} }),
    "\"" .. auth.login_uri .. "\" exempted as a prefix would exempt " ..
    "\"" .. auth.login_uri .. "bypass\" too, and the login endpoint is the one " ..
    "place on a gated site that answers without a session")

-- The certificate authority has to get through whatever else is configured, or a
-- site quietly stops being able to renew behind a login page nobody thought was
-- in the way.
check("the ACME path is not gated",
    not auth.gated("/.well-known/acme-challenge/tok3n", { auth_paths = {} }))
check("but a lookalike is",
    auth.gated("/.well-known/acme-challenge-x/tok3n", { auth_paths = {} }))

-- ========================================================= inbound headers

-- 3. X-MosWAF-User is an identity the upstream is asked to trust; X-MosWAF-Token
-- is the control plane's internal credential. A request arriving with either is a
-- request establishing it for itself.
do
    cleared = {}
    inbound = {
        ["x-moswaf-user"]  = "admin",
        ["X-MosWAF-Token"] = "guessed",
        ["x-moswaf-ray"]   = "spoofed",
        ["x_moswaf_site"]  = "other",
        ["user-agent"]     = "TestUA/1",
        ["cookie"]         = "a=b",
    }
    auth.strip_trusted_headers()

    local removed = {}
    for _, n in ipairs(cleared) do removed[n:lower():gsub("_", "-")] = true end

    check("a forged identity header is removed", removed["x-moswaf-user"],
        "an upstream that trusts the gateway was just handed an administrator")
    check("a forged internal token is removed", removed["x-moswaf-token"],
        "the control plane's internal endpoints would believe the caller is the " ..
        "data plane")
    check("the whole namespace goes, not a list of known names",
        removed["x-moswaf-ray"] and removed["x-moswaf-site"],
        "clearing by name leaves every header invented after this line was written")
    check("headers outside the namespace are left alone",
        not removed["user-agent"] and not removed["cookie"])
end

-- =================================================================== report

io.write("\n")
if #failures > 0 then
    io.write("\n", #failures, " of ", total, " checks failed:\n")
    for _, f in ipairs(failures) do io.write("  - ", f, "\n") end
    os.exit(1)
end
io.write(total, " checks passed\n")
