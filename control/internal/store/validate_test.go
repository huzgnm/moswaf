package store

import (
	"strings"
	"testing"
)

func validSite() *Site {
	return &Site{
		ID: "acme", Name: "Acme", Domains: []string{"acme.test"},
		UpstreamScheme: "http", UpstreamHost: "10.0.0.5", UpstreamPort: 8080,
		Mode: "protect", Challenge: "auto", Enabled: true,
	}
}

// Site.Name is the one field ValidateSite does not check at all - it is trimmed,
// required to be non-empty, and nothing else. engine.renderSite then writes it
// verbatim into a *comment line* of the generated nginx config:
//
//	w("# MosWAF - %s (%s)", s.Name, s.ID)
//
// A newline ends that comment, and because Name also permits `;`, `{` and `}`,
// everything after the newline is parsed as nginx configuration. The file is
// included from inside http{} and the workers run as root
// (dataplane/conf/nginx.conf:7), so the injected directives run with full
// privilege in the proxy container - up to content_by_lua_block, i.e. code
// execution.
//
// Domains and UpstreamHost are NOT injectable: ValidateSite rejects `;`, `{`, `}`
// and spaces there, so a directive cannot be terminated. See
// TestValidateSiteRejectsNewlinesThatBreakTheConfig for what they can still do.
func TestValidateSiteNameCannotInjectNginxDirectives(t *testing.T) {
	payloads := []string{
		"acme\n}\nserver { listen 8888; location / { root /; } }\n#",
		"acme\r\n    return 200 'pwned';\r\n#",
	}

	for _, p := range payloads {
		s := validSite()
		s.Name = p
		if err := ValidateSite(s); err == nil {
			t.Errorf("Name %q was accepted: arbitrary nginx directives can be injected "+
				"into the generated site config", p)
		}
	}
}

// Even where injection is impossible, a newline still lands in the generated file
// and produces a directive nginx cannot parse. The proxy then fails to reload, so
// every later configuration change silently stops being applied.
func TestValidateSiteRejectsNewlinesThatBreakTheConfig(t *testing.T) {
	cases := []struct {
		field  string
		mutate func(*Site)
	}{
		{"Domains", func(s *Site) { s.Domains = []string{"acme.test\nreturn"} }},
		{"UpstreamHost", func(s *Site) { s.UpstreamHost = "10.0.0.5\nreturn" }},
	}

	for _, c := range cases {
		t.Run(c.field, func(t *testing.T) {
			s := validSite()
			c.mutate(s)
			if err := ValidateSite(s); err == nil {
				t.Fatalf("%s accepted a newline: the rendered nginx config will not parse "+
					"and the data plane will stop reloading", c.field)
			}
		})
	}
}

func TestValidateSiteAcceptsOrdinaryInput(t *testing.T) {
	s := &Site{
		ID: "acme", Name: "Acme Corp (prod)", Domains: []string{"Acme.test", " www.acme.test "},
		UpstreamScheme: "http", UpstreamHost: "10.0.0.5", UpstreamPort: 8080,
		Mode: "protect", Challenge: "auto", Enabled: true,
	}
	if err := ValidateSite(s); err != nil {
		t.Fatalf("a valid site was rejected: %v", err)
	}
	if s.Domains[0] != "acme.test" || s.Domains[1] != "www.acme.test" {
		t.Fatalf("domains were not normalised: %q", s.Domains)
	}
}

// Setting a real-IP header without naming the proxies that are allowed to send it
// makes util.client_ip (dataplane/lua/moswaf/util.lua:99) trust that header from
// *anyone*: the guard is `if trusted and #trusted > 0 and not in_list(...)`, so an
// empty trusted list skips the check entirely.
//
// Every IP-keyed control then becomes attacker-controlled - temporary bans, the
// blocklist and the rate-limit counters are all keyed on the spoofed value, and a
// fresh `X-Forwarded-For` per request means a fresh counter per request.
func TestValidateSettingsRequiresTrustedProxiesWithRealIPHeader(t *testing.T) {
	st := DefaultSettings()
	st.RealIPHeader = "X-Forwarded-For"
	st.TrustedProxies = []string{}

	if err := ValidateSettings(&st); err == nil {
		t.Fatal("a real-IP header was accepted with an empty trusted-proxy list: " +
			"any client can now spoof its own IP and evade bans and rate limits")
	}
}

func TestValidateSettingsAcceptsRealIPHeaderWithTrustedProxies(t *testing.T) {
	st := DefaultSettings()
	st.RealIPHeader = "X-Forwarded-For"
	st.TrustedProxies = []string{"10.0.0.0/8"}

	if err := ValidateSettings(&st); err != nil {
		t.Fatalf("a correctly configured real-IP header was rejected: %v", err)
	}
}

// ValidateRule compiles the pattern with Go's regexp (RE2) but the data plane runs
// it with PCRE through ngx.re.find. The two engines disagree in both directions:
//
//   - RE2 rejects lookarounds and backreferences, so ordinary WAF patterns that
//     PCRE handles fine cannot be saved at all.
//   - RE2 has no catastrophic backtracking, so it happily accepts a pattern that
//     will stall PCRE. nginx.conf sets no lua_regex_match_limit, and rules.lua
//     discards the error return of ngx.re.find, so a pattern PCRE rejects silently
//     never matches while the dashboard still shows the rule as active.
func TestValidateRuleAcceptsPCRELookahead(t *testing.T) {
	r := Rule{
		ID: "custom-1", Name: "lookahead", Category: "custom", Target: "any",
		Pattern: `(?i)(?=.*union)(?=.*select)`, Action: "deny", Severity: "high",
	}
	if err := ValidateRule(&r); err != nil {
		t.Fatalf("a valid PCRE pattern was rejected because it was validated with RE2: %v", err)
	}
}

func TestValidateRuleRejectsCatastrophicBacktracking(t *testing.T) {
	r := Rule{
		ID: "custom-2", Name: "redos", Category: "custom", Target: "any",
		Pattern: `^(a+)+$`, Action: "deny", Severity: "high",
	}
	if err := ValidateRule(&r); err == nil {
		t.Fatal("a catastrophically backtracking pattern was accepted; PCRE in the " +
			"data plane will run it on every request with no match limit set")
	}
}

func TestValidateRuleRejectsGarbage(t *testing.T) {
	r := Rule{
		ID: "custom-3", Name: "broken", Category: "custom", Target: "any",
		Pattern: `(unclosed`, Action: "deny", Severity: "high",
	}
	if err := ValidateRule(&r); err == nil {
		t.Fatal("an unparseable pattern was accepted")
	} else if !strings.Contains(err.Error(), "invalid pattern") {
		t.Fatalf("unexpected error: %v", err)
	}
}
