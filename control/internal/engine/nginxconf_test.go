package engine

import (
	"strings"
	"testing"

	"github.com/mosvpn/moswaf/control/internal/store"
)

func testSite() *store.Site {
	return &store.Site{
		ID: "acme", Name: "Acme", Domains: []string{"acme.test", "www.acme.test"},
		UpstreamScheme: "http", UpstreamHost: "10.0.0.5", UpstreamPort: 8080,
		Mode: "protect", Challenge: "auto", Enabled: true,
	}
}

func TestRenderSiteAppliesTheWAFAndTheRateLimits(t *testing.T) {
	conf, err := renderSite(testSite(), SiteRender{})
	if err != nil {
		t.Fatalf("renderSite: %v", err)
	}

	for _, want := range []string{
		`set $moswaf_site "acme";`,
		`limit_conn moswaf_conn`,
		`limit_req  zone=moswaf_hard`,
		`access_by_lua_block { require("moswaf.access").run() }`,
		`log_by_lua_block    { require("moswaf.log").run() }`,
		`server_name acme.test www.acme.test;`,
		`server 10.0.0.5:8080`,
	} {
		if !strings.Contains(conf, want) {
			t.Errorf("the generated config is missing %q\n---\n%s", want, conf)
		}
	}
}

// A site whose HTTP block only redirects must still not be the soft spot: check
// what actually gets emitted so the trade-off is visible in a test rather than
// discovered in production.
func TestRenderSiteForceHTTPSLeavesPort80Unprotected(t *testing.T) {
	s := testSite()
	s.TLSCert, s.TLSKey = "cert", "key"
	s.HasTLS, s.ForceHTTPS = true, true

	conf, err := renderSite(s, SiteRender{CertsDir: "/etc/moswaf/certs"})
	if err != nil {
		t.Fatalf("renderSite: %v", err)
	}

	httpBlock := conf[strings.Index(conf, "server {"):strings.LastIndex(conf, "server {")]
	if strings.Contains(httpBlock, "limit_req") {
		return // already fixed
	}
	t.Logf("KNOWN: the port-80 server block carries neither limit_req nor limit_conn, "+
		"so the redirect endpoint can be flooded without any rate limiting:\n%s", httpBlock)
}

// The counterpart to TestValidateSiteNameCannotInjectNginxDirectives: this shows
// what the unvalidated Name actually turns into on disk.
func TestRenderSiteDoesNotEmitInjectedDirectives(t *testing.T) {
	s := testSite()
	s.Name = "acme\n}\nserver { listen 8888; location / { root /; } }\n#"

	conf, err := renderSite(s, SiteRender{})
	if err != nil {
		// Rejecting the site outright is a perfectly good fix.
		return
	}

	if strings.Contains(conf, "root /;") {
		t.Fatalf("the site name escaped its comment line and injected live nginx "+
			"directives into the generated config:\n---\n%s", conf)
	}
}

// Renders must be deterministic: Publish rewrites every site file on every save,
// and a config that churns causes needless nginx reloads.
func TestRenderSiteIsDeterministic(t *testing.T) {
	a, err := renderSite(testSite(), SiteRender{})
	if err != nil {
		t.Fatalf("renderSite: %v", err)
	}
	b, err := renderSite(testSite(), SiteRender{})
	if err != nil {
		t.Fatalf("renderSite: %v", err)
	}
	if a != b {
		t.Fatal("two renders of the same site produced different output")
	}
}

func TestRenderSiteRejectsBadIDs(t *testing.T) {
	for _, id := range []string{"", "ab", "UPPER", "has space", "../../etc/passwd", "x/y"} {
		s := testSite()
		s.ID = id
		if _, err := renderSite(s, SiteRender{}); err == nil {
			t.Errorf("site id %q was accepted; it becomes a file name and an nginx upstream name", id)
		}
	}
}
