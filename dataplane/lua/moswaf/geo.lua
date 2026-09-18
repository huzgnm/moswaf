-- moswaf.geo - deciding whether an address is in a listed set of countries
--
-- The country dataset itself never comes here. It is seven hundred thousand
-- ranges and it lives in the control plane, which uses it to label the attack log.
-- What arrives instead is one merged, sorted list of address ranges per rule,
-- covering only the countries somebody is actually deciding on - a rule blocking
-- two countries ships those two, which for a typical rule is a percent or two of
-- the dataset.
--
-- The country codes are not here either. A rule asks "is this address in the
-- listed set?", which is one bit, so the answer is a membership test over a merged
-- list rather than a lookup that returns a name.

local util = require "moswaf.util"

local _M = {}

local format = string.format

-- ------------------------------------------------------------------- IPv4

-- The ranges arrive interleaved - lo, hi, lo, hi - so the search steps in pairs.
--
-- Binary search over a sorted, merged, non-overlapping list: about seventeen
-- comparisons for the largest rule anyone would write, which is why this can sit
-- on a path that every request takes.
local function in_v4(list, n)
    local lo, hi = 1, #list / 2
    while lo <= hi do
        local mid = math.floor((lo + hi) / 2)
        local i = mid * 2 - 1
        if n < list[i] then
            hi = mid - 1
        elseif n > list[i + 1] then
            lo = mid + 1
        else
            return true
        end
    end
    return false
end

-- ------------------------------------------------------------------- IPv6

-- An address as thirty-two lowercase hex characters.
--
-- Fixed-width big-endian hex compares lexicographically in exactly numeric order,
-- so the ranges can be searched with Lua's own string comparison. The alternative
-- is 128-bit arithmetic in a language whose numbers stop being exact at 53 bits -
-- which is the mistake that makes two different hosts look like the same one.
local function v6_hex(ip)
    local g = util.ipv6_groups(ip)
    if not g or #g ~= 8 then return nil end
    return format("%04x%04x%04x%04x%04x%04x%04x%04x",
        g[1], g[2], g[3], g[4], g[5], g[6], g[7], g[8])
end

local function in_v6(list, hexip)
    local lo, hi = 1, #list / 2
    while lo <= hi do
        local mid = math.floor((lo + hi) / 2)
        local i = mid * 2 - 1
        if hexip < list[i] then
            hi = mid - 1
        elseif hexip > list[i + 1] then
            lo = mid + 1
        else
            return true
        end
    end
    return false
end

-- ------------------------------------------------------------------ lookup

--- Is this address inside the published set?
--
-- Returns nil - not false - when the question cannot be answered: no set, an
-- address that will not parse, an empty table. The caller must tell the two apart,
-- because under an allow rule "not in the set" means refuse, and answering that
-- for an address nobody could place would refuse visitors over a parsing failure.
function _M.contains(set, ip)
    if type(set) ~= "table" or type(ip) ~= "string" or ip == "" then return nil end

    -- An IPv4 address written as IPv6 is an IPv4 address, and the IPv4 table is the
    -- one that holds it. Without this fold, the same visitor is placed in a country
    -- over a v4 socket and nowhere at all over a dual-stack one - which under an
    -- allow rule is the difference between being let in and being refused.
    ip = util.unmap_ipv4(ip) or ip

    local n = util.ipv4_to_int(ip)
    if n then
        local list = set.v4
        if type(list) ~= "table" or #list == 0 then return nil end
        return in_v4(list, n)
    end

    local hexip = v6_hex(ip)
    if not hexip then return nil end
    local list = set.v6
    -- A rule can legitimately hold IPv4 ranges and no IPv6 ones, because some
    -- countries have no IPv6 allocation in the dataset. That is an unanswerable
    -- question for an IPv6 visitor, not a "no".
    if type(list) ~= "table" or #list == 0 then return nil end
    return in_v6(list, hexip)
end

--- The verdict for one request: true to refuse it.
--
-- mode is "block" (refuse the listed countries) or "allow" (refuse everything
-- else). Anything else means there is no rule.
--
-- An address that cannot be placed is let through under both modes, and that is
-- the whole of the difference between this being a firewall feature and an outage.
-- Under "block" it is obvious. Under "allow" it is the one that matters: the
-- dataset does not cover every address on the internet, so refusing everything it
-- has no entry for would turn an allow rule into a slow, invisible ban on a
-- fraction of ordinary visitors - the kind of fault that is reported as "the site
-- works for me".
function _M.refuses(mode, set, ip)
    if mode ~= "block" and mode ~= "allow" then return false end

    local inside = _M.contains(set, ip)
    if inside == nil then return false end

    if mode == "block" then return inside end
    return not inside
end

return _M
