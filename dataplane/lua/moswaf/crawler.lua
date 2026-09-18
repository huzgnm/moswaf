-- moswaf.crawler - recognise a search engine by where it came from
--
-- A User-Agent is a string anyone can type. "Googlebot/2.1" costs an attacker
-- nothing, and treating it as identification is how a WAF ends up with a hole
-- shaped exactly like its most trusted visitor.
--
-- The operators publish the addresses their crawlers use, so the question has a
-- real answer: the claim in the header has to agree with the address the request
-- arrived from. The control plane fetches, validates and publishes those ranges;
-- this only matches against them, which means no DNS in the request path, no
-- per-address cache to poison, and no network call an attacker can provoke.
--
-- What recognition grants is deliberately small: exemption from the JS
-- challenge, because a crawler cannot run JavaScript and challenging one is the
-- same as blocking it. Rules, rate limits and the flood defence all still apply.
-- So the prize for defeating this is "not challenged", never "through the WAF".

local config = require "moswaf.config"
local util   = require "moswaf.util"

local _M = {}

-- The index is rebuilt when the configuration version changes, not per request.
--
-- Matching an address against six hundred ranges one at a time is work an
-- attacker can ask for: set the User-Agent to Googlebot and every request pays
-- for the whole list. Bucketed by the first octet, a lookup touches the handful
-- of ranges that could possibly match.
local index, index_version = nil, nil

local function build_index(crawlers)
    local idx = { v4 = {}, v6 = {}, ua = {} }

    for name, entry in pairs(crawlers or {}) do
        idx.ua[name] = (entry.ua or name):lower()

        for _, cidr in ipairs(entry.prefixes or {}) do
            local addr = cidr:match("^([^/]+)")
            if addr and addr:find(".", 1, true) and not addr:find(":", 1, true) then
                local first = tonumber(addr:match("^(%d+)%."))
                if first then
                    idx.v4[first] = idx.v4[first] or {}
                    local b = idx.v4[first]
                    b[#b + 1] = { cidr = cidr, name = name }
                end
            elseif addr then
                -- IPv6 ranges are far fewer, and their first group is a poor
                -- discriminator, so they share one list.
                idx.v6[#idx.v6 + 1] = { cidr = cidr, name = name }
            end
        end
    end
    return idx
end

local function current_index()
    local conf = config.get()
    local version = config.version()
    if index and index_version == version then return index end
    index = build_index(conf.crawlers)
    index_version = version
    return index
end

--- Which crawler does this request belong to, if any?
--
-- Returns: name of the verified crawler, or nil, plus a second value that is
-- true when the User-Agent claimed a crawler the address does not back up.
--
-- Both halves matter. The first decides whether to exempt; the second is a fake
-- worth recording, because a request claiming to be Googlebot from an address
-- Google does not own is not a mistake anyone makes by accident.
function _M.verify(ip, ua)
    if not ip or ip == "" then return nil, false end

    local idx = current_index()
    if not next(idx.ua) then return nil, false end

    -- The claim first: a substring search over one short string, and it decides
    -- whether any address matching happens at all.
    --
    -- Every match is collected, not the first one. The needles overlap - a
    -- Googlebot User-Agent contains "googlebot" and also "google", which belongs
    -- to a different list with different ranges - and pairs() has no order, so
    -- taking the first match meant a real Googlebot was checked against the
    -- special-crawlers ranges roughly half the time and failed to verify. It
    -- looked like a spoof. Whichever list actually contains the address is the
    -- one that answers.
    local lowered = (ua or ""):lower()
    local claimed = {}
    for name, needle in pairs(idx.ua) do
        if lowered:find(needle, 1, true) then
            claimed[name] = true
        end
    end
    if not next(claimed) then return nil, false end

    -- ip has already been through util.normalize_ip, so an IPv4 client that
    -- arrived written as ::ffff:1.2.3.4 is a dotted address here and matches the
    -- IPv4 ranges. Without that folding a mapped crawler would fail to verify.
    local first = tonumber(ip:match("^(%d+)%."))
    local bucket = first and idx.v4[first] or idx.v6

    for i = 1, #bucket do
        if claimed[bucket[i].name] and util.ip_in_list(ip, { bucket[i].cidr }) then
            return bucket[i].name, false
        end
    end

    -- Claimed, but the address does not belong to them.
    return nil, true
end

-- Exposed for the tests and for anyone debugging a list that looks wrong.
function _M.stats()
    local idx = current_index()
    local v4 = 0
    for _, bucket in pairs(idx.v4) do v4 = v4 + #bucket end
    local names = {}
    for name in pairs(idx.ua) do names[#names + 1] = name end
    table.sort(names)
    return { ipv4_ranges = v4, ipv6_ranges = #idx.v6, crawlers = names }
end

return _M
