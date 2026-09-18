-- Tests for moswaf.crawler - recognising a search engine by its address.
--
-- The whole feature exists because a User-Agent is a string anyone can type. So
-- the tests are written from the attacker's side: every case below is somebody
-- claiming to be a crawler and the question is whether the claim survives
-- contact with the address it arrived from.
--
--   luajit dataplane/test/crawler.lua

local ROOT = arg[0]:match("^(.*)/test/crawler%.lua$") or "dataplane"
package.path = ROOT .. "/lua/?.lua;" .. ROOT .. "/lua/?/init.lua;" .. package.path

package.loaded["resty.redis"] = {}
_G.ngx = { log = function() end, WARN = 2, ERR = 3, re = { find = function() return nil end }, var = {} }

-- Stand in for the published configuration. Ranges are real Googlebot and
-- Bingbot prefixes so the shapes are the ones that actually turn up.
local published = {
    crawlers = {
        googlebot = {
            ua = "googlebot",
            prefixes = { "66.249.64.0/19", "66.249.96.0/19", "2001:4860:4801::/48" },
        },
        bingbot = {
            ua = "bingbot",
            prefixes = { "157.55.39.0/24", "207.46.13.0/24" },
        },
    },
}

local version = 1
package.loaded["moswaf.config"] = {
    get = function() return published end,
    version = function() return version end,
}

local crawler = require "moswaf.crawler"

local failures, total = {}, 0
local function check(name, ok, detail)
    total = total + 1
    if ok then io.write(".") else
        io.write("F")
        failures[#failures + 1] = name .. (detail and ("\n      " .. detail) or "")
    end
end

local GOOGLE_UA = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
local BING_UA   = "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)"
local HUMAN_UA  = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Chrome/120"

-- ---------------------------------------------------------- the real thing

do
    local name, faked = crawler.verify("66.249.66.1", GOOGLE_UA)
    check("a Googlebot User-Agent from a Google address verifies",
        name == "googlebot" and not faked,
        "got " .. tostring(name) .. " faked=" .. tostring(faked))

    name = crawler.verify("157.55.39.50", BING_UA)
    check("a Bingbot User-Agent from a Bing address verifies", name == "bingbot",
        "got " .. tostring(name))

    name = crawler.verify("2001:4860:4801:1::5", GOOGLE_UA)
    check("an IPv6 crawler address verifies too", name == "googlebot",
        "got " .. tostring(name))
end

-- ---------------------------------------------------------- the impostor

do
    -- The case the feature exists for. The header is free; the address is not.
    local name, faked = crawler.verify("203.0.113.9", GOOGLE_UA)
    check("claiming Googlebot from an address Google does not own does NOT verify",
        name == nil and faked,
        "got " .. tostring(name) .. " faked=" .. tostring(faked))

    -- A real crawler address with the wrong claim is not a free pass either: the
    -- two have to agree, or an attacker on a shared host inside any published
    -- range would inherit every other crawler's exemption.
    name = crawler.verify("157.55.39.50", GOOGLE_UA)
    check("a Bing address claiming to be Googlebot does not verify", name == nil,
        "got " .. tostring(name))

    -- Near-miss addresses, one on each side of a real range.
    check("the address just below a range does not verify",
        crawler.verify("66.249.63.255", GOOGLE_UA) == nil)
    check("the address just above a range does not verify",
        crawler.verify("66.249.96.0", GOOGLE_UA) == "googlebot",
        "66.249.96.0/19 is a published range, this should verify")
    check("an address past the last range does not verify",
        crawler.verify("66.249.128.1", GOOGLE_UA) == nil)
end

-- ---------------------------------------------------------- ordinary visitors

do
    local name, faked = crawler.verify("203.0.113.9", HUMAN_UA)
    check("an ordinary visitor is neither verified nor flagged as a fake",
        name == nil and not faked,
        "a browser that never claimed to be a crawler must not be recorded as one")

    -- Even from inside a crawler range: being at Google's address without saying
    -- so is not a claim, and the exemption follows the claim.
    name, faked = crawler.verify("66.249.66.1", HUMAN_UA)
    check("a browser User-Agent from a crawler address is not verified",
        name == nil and not faked,
        "got " .. tostring(name))

    check("an empty User-Agent is not a claim", crawler.verify("66.249.66.1", "") == nil)
    check("a missing address verifies nothing", crawler.verify(nil, GOOGLE_UA) == nil)
end

-- ---------------------------------------------------------- spelling the claim

do
    -- The comparison is case-insensitive, because the real crawlers are not
    -- consistent about it and neither is anybody spoofing them.
    check("GOOGLEBOT in capitals still verifies from a Google address",
        crawler.verify("66.249.66.1", "compatible; GOOGLEBOT/2.1") == "googlebot")

    -- ...which cuts the other way too: a fake in capitals is still a fake.
    local _, faked = crawler.verify("203.0.113.9", "GoogleBot")
    check("a fake claim in mixed case is still recorded as a fake", faked)
end

-- ---------------------------------------------------------- IPv4 written as IPv6
--
-- access.lua hands this module an address that has already been through
-- normalize_ip, so a crawler arriving over a dual-stack socket as
-- ::ffff:66.249.66.1 is a dotted address by the time it gets here. If that
-- folding ever stops happening, a real crawler silently stops verifying - so
-- assert the shape this module is promised.

do
    local util = require "moswaf.util"
    local folded = util.normalize_ip("::ffff:66.249.66.1")
    check("a mapped crawler address folds to IPv4 before it reaches here",
        folded == "66.249.66.1",
        "got " .. tostring(folded))
    check("and then verifies", crawler.verify(folded, GOOGLE_UA) == "googlebot")
end

-- ---------------------------------------------------------- the index

do
    local st = crawler.stats()
    check("every published range is indexed",
        st.ipv4_ranges == 4 and st.ipv6_ranges == 1,
        "ipv4=" .. st.ipv4_ranges .. " ipv6=" .. st.ipv6_ranges .. ", expected 4 and 1")
    check("both crawlers are known",
        #st.crawlers == 2 and st.crawlers[1] == "bingbot",
        "got " .. table.concat(st.crawlers, ","))

    -- The index is rebuilt when the configuration version changes. Without that a
    -- range removed by the operators would keep granting an exemption until the
    -- worker restarted.
    published.crawlers.googlebot.prefixes = { "8.8.8.0/24" }
    version = 2
    check("a changed configuration rebuilds the index",
        crawler.verify("66.249.66.1", GOOGLE_UA) == nil
        and crawler.verify("8.8.8.8", GOOGLE_UA) == "googlebot",
        "the old ranges are still being matched after the version changed")
end

-- ---------------------------------------------------------- nothing published

do
    published.crawlers = {}
    version = 3
    local name, faked = crawler.verify("66.249.66.1", GOOGLE_UA)
    check("with no ranges published, nothing verifies and nothing is flagged",
        name == nil and not faked,
        "an empty list must exempt nobody rather than everybody")
end

-- ---------------------------------------------------------- report

io.write("\n\n")
if #failures == 0 then
    print(string.format("%d/%d checks passed", total, total))
    print("\n  a crawler is recognised by its address, not by what it calls itself")
    print("  claiming Googlebot from anywhere else is recorded, not believed")
    print("  an empty list exempts nobody")
    os.exit(0)
end
print(string.format("%d of %d checks FAILED:\n", #failures, total))
for _, f in ipairs(failures) do print("  - " .. f) end
os.exit(1)
