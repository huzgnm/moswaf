-- moswaf.rules - engine chu ky (signature) cho tang ung dung
--
-- Rule: { id, name, category, target, pattern, action, severity, enabled }
--   target : uri | args | body | ua | header | cookie | any
--   action : deny | challenge | ban | log
--
-- Neu control plane da day rule xuong (conf.rules) thi dung bo do,
-- neu chua thi chay bo mac dinh ben duoi de he thong van co bao ve ngay tu dau.

local config = require "moswaf.config"

local re_find = ngx.re.find
local concat  = table.concat
local _M      = {}

-- ------------------------------------------------------------ bo rule goc
-- Nhung rule nay duoc control plane seed vao DB lan dau chay,
-- admin co the tat/sua tren dashboard.
_M.builtin = {
    { id = "sqli-union",   name = "SQLi - UNION SELECT",      category = "sqli",     target = "any",
      pattern = [[(?i)union[\s/*()]+(all[\s/*()]+)?select]],                       action = "deny", severity = "high" },
    { id = "sqli-common",  name = "SQLi - common syntax",  category = "sqli",     target = "any",
      pattern = [[(?i)(\bselect\b[\s\S]{1,60}\bfrom\b|\binsert\b\s+into\b|\bdrop\b\s+table\b|\bupdate\b[\s\S]{1,40}\bset\b[\s\S]{1,40}=)]],
      action = "deny", severity = "high" },
    { id = "sqli-blind",   name = "SQLi - blind / time based", category = "sqli",    target = "any",
      pattern = [[(?i)(sleep\s*\(\s*\d|benchmark\s*\(|pg_sleep\s*\(|waitfor\s+delay|\bor\b\s+\d+\s*=\s*\d+|'\s*or\s*'1'\s*=\s*'1)]],
      action = "deny", severity = "high" },
    { id = "sqli-meta",    name = "SQLi - metadata probing",        category = "sqli",    target = "any",
      pattern = [[(?i)(information_schema|load_file\s*\(|into\s+(out|dump)file|@@version|version\s*\(\s*\))]],
      action = "deny", severity = "high" },

    { id = "xss-tag",      name = "XSS - dangerous tags",       category = "xss",     target = "any",
      pattern = [[(?i)<\s*(script|iframe|object|embed|svg\b[^>]*onload)]],           action = "deny", severity = "high" },
    { id = "xss-event",    name = "XSS - event handler / js:", category = "xss",     target = "any",
      pattern = [[(?i)(javascript\s*:|on(error|load|click|mouseover|focus)\s*=|document\.cookie|eval\s*\(|atob\s*\()]],
      action = "deny", severity = "medium" },

    { id = "lfi-traversal", name = "Path traversal",           category = "lfi",     target = "any",
      pattern = [[(?i)(\.\./|\.\.\\|%2e%2e[/%5c]|\.\.%2f)]],                        action = "deny", severity = "high" },
    { id = "lfi-file",      name = "System file access",        category = "lfi",     target = "any",
      pattern = [[(?i)(/etc/(passwd|shadow|hosts)|/proc/self/(environ|cmdline)|boot\.ini|win\.ini)]],
      action = "deny", severity = "high" },
    { id = "lfi-wrapper",   name = "PHP wrapper",              category = "lfi",     target = "any",
      pattern = [[(?i)(php://(input|filter|memory)|data://text|expect://|zip://)]],  action = "deny", severity = "high" },

    { id = "rce-shell",    name = "RCE - shell command injection",     category = "rce",     target = "any",
      pattern = [[(?i)([;|&`]\s*(cat|ls|id|pwd|whoami|uname|wget|curl|nc|ncat|bash|sh|python|perl)\b|\$\([^)]{1,40}\))]],
      action = "deny", severity = "critical" },
    { id = "rce-php",      name = "RCE - dangerous PHP functions",   category = "rce",     target = "any",
      pattern = [[(?i)\b(system|exec|passthru|shell_exec|popen|proc_open|assert|base64_decode)\s*\(]],
      action = "deny", severity = "critical" },

    { id = "path-secret",  name = "Secret file probing",            category = "recon",   target = "uri",
      pattern = [[(?i)/(\.env|\.git/|\.svn/|\.ssh/|\.aws/|wp-config\.php(\.bak)?|config\.php\.(bak|old|save)|\.DS_Store|docker-compose\.ya?ml|backup\.(sql|zip|tar\.gz))]],
      action = "deny", severity = "medium" },
    { id = "path-admin",   name = "Admin panel probing",        category = "recon",   target = "uri",
      pattern = [[(?i)/(phpmyadmin|pma|adminer\.php|phpinfo\.php)]],
      action = "log",  severity = "low" },

    { id = "ua-scanner",   name = "Vulnerability scanner",      category = "bot",     target = "ua",
      pattern = [[(?i)(sqlmap|nikto|nmap|masscan|zgrab|acunetix|nessus|openvas|dirbuster|gobuster|feroxbuster|wpscan|joomscan|hydra|havij|netsparker|arachni|w3af|xsstrike)]],
      action = "deny", severity = "high" },
    { id = "ua-empty",     name = "Missing User-Agent",          category = "bot",     target = "ua",
      pattern = [[^$]],                                                             action = "challenge", severity = "low" },
    { id = "ua-lib",       name = "Automated HTTP client",       category = "bot",     target = "ua",
      pattern = [[(?i)^(python-requests|python-urllib|go-http-client|java/|okhttp|libwww-perl|axios/|scrapy|node-fetch)]],
      action = "log", severity = "low" },

    { id = "hdr-inject",   name = "Header injection / CRLF",        category = "proto",   target = "any",
      pattern = [[(?i)(%0d%0a|\r\n)(set-cookie|location|content-length)\s*:]],       action = "deny", severity = "medium" },
    { id = "ssrf-meta",    name = "SSRF - cloud metadata",     category = "ssrf",    target = "any",
      pattern = [[(?i)(169\.254\.169\.254|metadata\.google\.internal|100\.100\.100\.200)]],
      action = "deny", severity = "high" },
}

-- ------------------------------------------------------------ cache rule

local cache_ver, cache_list = -1, nil

local function active_rules()
    local ver = config.version()
    if cache_list and cache_ver == ver then return cache_list end

    local conf = config.get()
    local src  = (#conf.rules > 0) and conf.rules or _M.builtin

    local list = {}
    for i = 1, #src do
        local r = src[i]
        if r.enabled ~= false and r.pattern and r.pattern ~= "" then
            list[#list + 1] = r
        end
    end

    cache_list, cache_ver = list, ver
    return list
end

-- ------------------------------------------------------------ quet

-- Gom noi dung can quet theo tung target, tao lazily de do ton CPU
local function subject_for(target, ctx)
    if target == "uri" then
        return ctx.uri
    elseif target == "args" then
        return ctx.args or ""
    elseif target == "ua" then
        return ctx.ua or ""
    elseif target == "body" then
        return ctx.body or ""
    elseif target == "cookie" then
        return ctx.cookie or ""
    elseif target == "header" then
        if not ctx._hdr then
            local parts = {}
            for k, v in pairs(ctx.headers or {}) do
                if type(v) == "table" then v = concat(v, ",") end
                parts[#parts + 1] = k .. ": " .. tostring(v)
            end
            ctx._hdr = concat(parts, "\n")
        end
        return ctx._hdr
    else -- any
        if not ctx._any then
            ctx._any = concat({ ctx.uri or "", ctx.args or "", ctx.body or "",
                                ctx.cookie or "", ctx.referer or "" }, "\n")
        end
        return ctx._any
    end
end

-- Tra ve rule dau tien khop, hoac nil
function _M.scan(ctx, site)
    local rules = active_rules()
    local off   = site and site.rules_off or nil

    for i = 1, #rules do
        local r = rules[i]
        local skip = false
        if off then
            for j = 1, #off do
                if off[j] == r.id then skip = true break end
            end
        end
        if not skip then
            local subject = subject_for(r.target or "any", ctx)
            if subject then
                local from = re_find(subject, r.pattern, "joi")
                if from then return r end
            end
        end
    end
    return nil
end

function _M.count()
    return #active_rules()
end

return _M
