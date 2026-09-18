-- Tests for the ban listing endpoint.
--
-- One number in it used to be a lie: total was the length of the list returned,
-- so once there were more bans than fit in a page the list was short AND the
-- count agreed with the short list. An operator had no way to know they were
-- looking at part of it.
--
--   luajit dataplane/test/bans.lua

local ROOT = arg[0]:match("^(.*)/test/bans%.lua$") or "dataplane"
package.path = ROOT .. "/lua/?.lua;" .. ROOT .. "/lua/?/init.lua;" .. package.path

package.loaded["resty.redis"] = {}

local store = {}
local dict = {}
function dict:get(k) return store[k] end
function dict:ttl(k) return store[k] and 600 or nil end
function dict:set(k, v) store[k] = v; return true end
function dict:get_keys(n)
    local out = {}
    for k in pairs(store) do
        out[#out + 1] = k
        if n and n > 0 and #out >= n then break end
    end
    return out
end

_G.ngx = {
    shared = { moswaf_ban = dict, moswaf_conf = dict, moswaf_cnt = dict,
               moswaf_stats = dict, moswaf_flood = dict, moswaf_chal = dict,
               moswaf_locks = dict },
    req = { get_headers = function() return { ["X-MosWAF-Token"] = "t" } end,
            get_uri_args = function() return {} end, read_body = function() end,
            get_body_data = function() return nil end },
    var = {}, header = {},
    say = function() end, print = function() end,
    exit = function() end, log = function() end,
    time = function() return 1700000000 end, now = function() return 1700000000 end,
    ERR = 1, WARN = 2, NOTICE = 3, HTTP_OK = 200,
    encode_base64 = function(s) return s end, hmac_sha1 = function(_, m) return m end,
    status = 200,
    -- rules.lua compiles its signatures against ngx.re at load time; nothing here
    -- runs them, so a stand-in is enough to get the module loaded.
    re = { find = function() return nil end, match = function() return nil end },
    worker = { id = function() return 0 end, count = function() return 1 end },
    timer = { at = function() return true end },
    localtime = function() return "2026-09-19 00:00:00" end,
    unescape_uri = function(s) return s end,
}
os.getenv = function(k)  -- luacheck: ignore
    if k == "MOSWAF_INTERNAL_TOKEN" then return "t" end
    return nil
end

-- cjson is an OpenResty module and is not there under plain luajit. The endpoint
-- only needs it to serialise, and what these tests check is the numbers it puts
-- in - so encode keeps the table instead of turning it into text.
local encoded
package.loaded["cjson.safe"] = {
    encode = function(t) encoded = t; return "{}" end,
    decode = function() return nil end,
}

local api = require "moswaf.api"

local failures, total = {}, 0
local function check(name, ok, detail)
    total = total + 1
    if ok then io.write(".") else
        io.write("F")
        failures[#failures + 1] = name .. (detail and ("\n      " .. detail) or "")
    end
end

local function list(n)
    store = {}
    for i = 1, n do dict:set("b:10.0." .. math.floor(i / 256) .. "." .. (i % 256), "auto") end
    encoded = nil
    api.bans()
    return encoded or {}
end

-- Under the page size everything is known, so the count is exact.
do
    local r = list(5)
    check("a short list returns every ban", #r.items == 5)
    check("and reports the real total",     r.total == 5)
    check("and does not claim truncation",  r.truncated == false)
end

-- Over it, the list is cut - and has to say so.
do
    local r = list(1500)
    check("a long list is cut to the page size", #r.items == 1000,
        "returned " .. #r.items)
    check("and says it was cut", r.truncated == true,
        "the list is short and nothing in the answer admits it; an operator " ..
        "reading it has no way to know they are seeing part of the bans")
    check("and does not report a total it cannot know", r.total == nil,
        "total = " .. tostring(r.total) .. ". Reporting the length of the cut " ..
        "list as the total is the bug this test exists for: it does not merely " ..
        "omit information, it states a wrong number that reads as the answer")
    check("shown says how many came back", r.shown == 1000)
end

-- Exactly a page is not truncated, and the boundary is the easy place to be off
-- by one in the direction that lies.
do
    local r = list(1000)
    check("exactly one page is not reported as cut", r.truncated == false)
    check("and its total is exact", r.total == 1000)
end

io.write("\n")
if #failures > 0 then
    io.write("\n", #failures, " of ", total, " checks failed:\n")
    for _, f in ipairs(failures) do io.write("  - ", f, "\n") end
    os.exit(1)
end
io.write(total, " checks passed\n")
