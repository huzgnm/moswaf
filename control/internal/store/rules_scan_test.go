package store

import (
	"regexp"
	"sort"
	"strings"
	"testing"
)

// This file reproduces, in Go, the exact rule-evaluation behaviour of the data
// plane, so that WAF bypasses can be found without booting the whole stack.
//
// Two pieces of production code are mirrored here:
//
//   - Store.ListRules  -> ORDER BY <blocking actions first>, builtin DESC, category, id.
//     Publisher.Publish appends the rules to the Redis config in that same order,
//     and rules.lua walks that slice front to back, so this ordering *is* the
//     evaluation order of the engine.
//   - rules.lua:_M.scan -> a blocking match wins immediately; a `log` match is
//     remembered and the scan continues, so a logging rule can never shadow a
//     blocking one.
//
// The builtin patterns are all RE2-compatible (ValidateRule already compiles them
// with regexp.Compile), so Go's regexp engine reaches the same verdict as PCRE for
// the inputs used below.

// request is the part of an HTTP request the signature engine can see.
type request struct {
	uri     string
	args    string
	body    string
	cookie  string
	referer string
	ua      string
	headers map[string]string
}

// percentDecode is ngx.unescape_uri: decode %XX, leave anything malformed alone.
func percentDecode(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '%' && i+2 < len(s) {
			hi, ok1 := unhex(s[i+1])
			lo, ok2 := unhex(s[i+2])
			if ok1 && ok2 {
				b.WriteByte(hi<<4 | lo)
				i += 2
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

func unhex(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}

// expand mirrors access.lua:expand - the original plus up to two decoded layers,
// concatenated, so a rule matches whichever encoding layer the payload sits in.
func expand(s string) string {
	if s == "" {
		return ""
	}
	out, prev := s, s
	for i := 0; i < 2; i++ {
		decoded := percentDecode(prev)
		if decoded == prev {
			break
		}
		out = out + "\n" + decoded
		prev = decoded
	}
	return out
}

// subjectFor mirrors dataplane/lua/moswaf/rules.lua:subject_for, applying the same
// normalisation access.lua applies before handing the values to the engine.
//
// Target "any" covers the User-Agent and the request headers as well: leaving them
// out turned every header into an unscanned channel.
func (r request) subjectFor(target string) string {
	switch target {
	case "uri":
		return expand(r.uri)
	case "args":
		return expand(r.args)
	case "body":
		return expand(r.body)
	case "cookie":
		return expand(r.cookie)
	case "ua":
		return r.ua // access.lua passes the User-Agent through unchanged
	case "header":
		return r.headerBlob()
	default: // "any"
		return strings.Join([]string{
			expand(r.uri), expand(r.args), expand(r.body),
			expand(r.cookie), expand(r.referer),
			r.ua, r.headerBlob(),
		}, "\n")
	}
}

func (r request) headerBlob() string {
	parts := make([]string, 0, len(r.headers))
	for k, v := range r.headers {
		parts = append(parts, k+": "+v)
	}
	sort.Strings(parts)
	return strings.Join(parts, "\n")
}

// actionRank mirrors the CASE expression in ListRules' ORDER BY.
func actionRank(action string) int {
	switch action {
	case "deny":
		return 0
	case "ban":
		return 1
	case "challenge":
		return 2
	default: // log
		return 3
	}
}

// evaluationOrder mirrors ListRules' ORDER BY for the builtin set.
func evaluationOrder() []Rule {
	out := append([]Rule(nil), BuiltinRules...)
	sort.SliceStable(out, func(i, j int) bool {
		if ri, rj := actionRank(out[i].Action), actionRank(out[j].Action); ri != rj {
			return ri < rj
		}
		if out[i].Category != out[j].Category {
			return out[i].Category < out[j].Category
		}
		return out[i].ID < out[j].ID
	})
	return out
}

// scan mirrors rules.lua:_M.scan - a blocking rule decides the request as soon as
// it matches, while a `log` match is only remembered so the scan can carry on.
func scan(rules []Rule, r request) *Rule {
	var logged *Rule
	for i := range rules {
		re, err := regexp.Compile(rules[i].Pattern)
		if err != nil {
			continue
		}
		if !re.MatchString(r.subjectFor(rules[i].Target)) {
			continue
		}
		if rules[i].Action == "log" {
			if logged == nil {
				logged = &rules[i]
			}
			continue
		}
		return &rules[i]
	}
	return logged
}

// blocks reports whether access.lua would actually stop the request.
// "log" lets the request through to the upstream; only "deny", "ban" and
// "challenge" stop it.
func blocks(r *Rule) bool {
	return r != nil && (r.Action == "deny" || r.Action == "ban" || r.Action == "challenge")
}

func TestBuiltinRulesBlockObviousAttacks(t *testing.T) {
	rules := evaluationOrder()

	cases := []struct {
		name string
		req  request
	}{
		{"SQLi UNION SELECT in the query string", request{
			uri: "/products", args: "id=1%20UNION%20ALL%20SELECT%20password%20FROM%20users", ua: "Mozilla/5.0",
		}},
		{"path traversal", request{
			uri: "/download?f=../../../../etc/passwd", ua: "Mozilla/5.0",
		}},
		{"RCE via shell metacharacter", request{
			uri: "/ping", args: "host=127.0.0.1;cat /etc/passwd", ua: "Mozilla/5.0",
		}},
		{"XSS script tag", request{
			uri: "/search", args: "q=<script>alert(1)</script>", ua: "Mozilla/5.0",
		}},
		{"scanner user agent", request{
			uri: "/", ua: "sqlmap/1.7.2#stable",
		}},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if m := scan(rules, c.req); !blocks(m) {
				t.Fatalf("the request was let through; matched rule = %v", m)
			}
		})
	}
}

// TestLoggingRuleDoesNotShadowBlockingRule is the sharpest bypass found so far.
//
// Rules are evaluated in (category, id) order and the first match wins. Category
// "bot" sorts before "lfi", "rce", "sqli" and "xss", and inside "bot" the ids sort
// as ua-empty, ua-lib, ua-scanner. "ua-lib" carries action "log", which access.lua
// treats as *allow and record*.
//
// The result: announcing one of the HTTP client libraries in the User-Agent makes
// ua-lib match first, the scan loop returns, and every SQLi / XSS / RCE / LFI rule
// is skipped. One header disables the whole signature engine.
//
//	curl -A 'python-requests/2.31.0' 'https://site/?id=1 UNION SELECT ...'
func TestLoggingRuleDoesNotShadowBlockingRule(t *testing.T) {
	rules := evaluationOrder()

	shadowingUAs := []string{
		"python-requests/2.31.0",
		"Go-http-client/1.1",
		"okhttp/4.12.0",
		"axios/1.6.0",
		"node-fetch/3.3.2",
		"Scrapy/2.11",
		"Java/1.8.0_381",
	}

	for _, ua := range shadowingUAs {
		t.Run(ua, func(t *testing.T) {
			req := request{
				uri:  "/products",
				args: "id=1 UNION ALL SELECT password FROM users",
				ua:   ua,
			}
			m := scan(rules, req)
			if !blocks(m) {
				t.Fatalf("SQLi let through: User-Agent %q matched %q (action %q) first, "+
					"so the sqli-* rules were never evaluated", ua, m.ID, m.Action)
			}
		})
	}
}

// Same shadowing problem inside category "recon": path-admin (action "log") sorts
// before path-secret (action "deny"), so a URI that contains both is allowed.
func TestReconLoggingRuleDoesNotShadowSecretFileRule(t *testing.T) {
	rules := evaluationOrder()

	req := request{uri: "/pma/.env", ua: "Mozilla/5.0"}
	m := scan(rules, req)
	if !blocks(m) {
		t.Fatalf("secret file probe let through: %q matched %q (action %q) first",
			req.uri, m.ID, m.Action)
	}
}

// No builtin rule targets "header", and target "any" deliberately excludes the
// headers, so an attack delivered in a header is invisible to the engine even
// though access.lua goes to the trouble of collecting ngx.req.get_headers(64).
func TestAttackInHeaderIsDetected(t *testing.T) {
	rules := evaluationOrder()

	req := request{
		uri: "/", ua: "Mozilla/5.0",
		headers: map[string]string{
			"X-Api-Version": "1 UNION ALL SELECT password FROM users",
		},
	}
	if m := scan(rules, req); !blocks(m) {
		t.Fatalf("SQLi in a request header was not detected; matched rule = %v", m)
	}
}

// The User-Agent is only ever matched by the three "ua" rules, so a payload placed
// there escapes the sqli/xss/rce rules entirely.
func TestAttackInUserAgentIsDetected(t *testing.T) {
	rules := evaluationOrder()

	req := request{uri: "/", ua: "1' UNION ALL SELECT password FROM users -- "}
	if m := scan(rules, req); !blocks(m) {
		t.Fatalf("SQLi in the User-Agent was not detected; matched rule = %v", m)
	}
}
