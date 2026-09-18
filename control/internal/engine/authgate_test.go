package engine

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mosvpn/moswaf/control/internal/store"
)

// A site with the gate switched on. It carries a certificate because the gate
// refuses to be enabled without one - see the last test in this file - so a
// gate-bearing site that renders at all is a site with TLS.
func gatedSite() *store.Site {
	s := &store.Site{
		ID: "s0123456789", Name: "Example", Domains: []string{"example.com"},
		UpstreamScheme: "http", UpstreamHost: "app", UpstreamPort: 8080,
		Mode: "protect", Challenge: "auto", Enabled: true,
		AuthEnabled: true, AuthPaths: []string{"/admin"},
		TLSCert: "cert", TLSKey: "key",
	}
	s.HasTLS = true
	return s
}

func render(t *testing.T, s *store.Site) string {
	t.Helper()
	out, err := renderSite(s, SiteRender{CertsDir: "/certs"})
	if err != nil {
		t.Fatalf("rendering the site: %v", err)
	}
	return out
}

// The login endpoint is the one place on a gated site that answers without a
// session, so nginx has to route it by exact match. As a prefix location it would
// also catch "/__moswaf/loginbypass", and the gate would have a door in it that
// the Lua exemption test could never see - the request would never reach the gate
// at all.
func TestTheLoginEndpointIsAnExactLocation(t *testing.T) {
	conf := render(t, gatedSite())

	for _, want := range []string{
		"location = " + loginPath + " {",
		"location = " + logoutPath + " {",
		"location = " + authBackendPath + " {",
	} {
		if !strings.Contains(conf, want) {
			t.Errorf("the generated config has no %q", want)
		}
	}

	// A prefix location for any of the three would be the bug.
	for _, wrong := range []string{
		"location " + loginPath + " {",
		"location " + logoutPath + " {",
		"location " + authBackendPath + " {",
	} {
		if strings.Contains(conf, wrong) {
			t.Errorf("%q is a prefix location; it matches every path that merely "+
				"begins with it", wrong)
		}
	}
}

// The path the password travels on must be unreachable from outside. Without
// `internal`, it is a public endpoint that forwards an arbitrary body to the
// control plane with the internal token attached - which is a way to ask for a
// session on any site, from the internet.
func TestTheAuthBackendIsInternalOnly(t *testing.T) {
	conf := render(t, gatedSite())

	i := strings.Index(conf, "location = "+authBackendPath+" {")
	if i < 0 {
		t.Fatal("the backend location is missing entirely")
	}
	block := conf[i:]
	if j := strings.Index(block, "\n    }"); j > 0 {
		block = block[:j]
	}
	if !strings.Contains(block, "internal;") {
		t.Error("the backend location is not marked `internal`, so it can be " +
			"reached from the internet; it forwards whatever body it is given to " +
			"the control plane with the internal token attached")
	}
}

// Every value handed to the control plane as proof of who we are has to come from
// this server's own configuration. Taking any of them from a request header would
// be handing a client-supplied value back as our own credential.
func TestTheTrustedHeadersAreNeverTakenFromTheRequest(t *testing.T) {
	conf := render(t, gatedSite())

	for _, want := range []string{
		"proxy_set_header X-MosWAF-Site  $moswaf_auth_site;",
		"proxy_set_header X-MosWAF-Token $moswaf_auth_token;",
	} {
		if !strings.Contains(conf, want) {
			t.Errorf("missing %q", want)
		}
	}
	if strings.Contains(conf, "$http_x_moswaf") {
		t.Error("a trusted header is being set from $http_x_moswaf_*, which is " +
			"whatever the client sent: anyone could name their own site or supply " +
			"their own internal token")
	}

	// Declared in the location that makes the subrequest, not in the one that
	// receives it. Declared in the target, the `set` directive runs in that
	// subrequest's rewrite phase and resets the values to empty AFTER
	// ngx.location.capture passed them - the control plane would be asked to sign a
	// session for no site, with no token.
	i := strings.Index(conf, "location = "+loginPath+" {")
	if i < 0 {
		t.Fatal("the login location is missing")
	}
	block := conf[i:]
	if j := strings.Index(block, "\n    }"); j > 0 {
		block = block[:j]
	}
	for _, v := range []string{"$moswaf_auth_site", "$moswaf_auth_ip", "$moswaf_auth_token"} {
		if !strings.Contains(block, "set "+v) {
			t.Errorf("%s is not declared in the login location. Declared in the "+
				"backend location instead, nginx resets it to empty in that "+
				"subrequest's rewrite phase, after the value was passed to it", v)
		}
	}
}

// Named directly, nginx resolves an upstream host once at startup and refuses to
// start when it cannot - which is every boot where the control plane is not up
// yet, and it would take the whole data plane down with it.
func TestTheControlPlaneIsAddressedThroughAVariable(t *testing.T) {
	conf := render(t, gatedSite())
	if !strings.Contains(conf, "proxy_pass http://$moswaf_mgmt/internal/site-login;") {
		t.Error("the control plane is not addressed through a variable; nginx would " +
			"refuse to start whenever it is not already running")
	}
}

// It comes from an environment variable rather than from a request, but a
// generated config file that can be extended by setting one is still worth a line
// to prevent - the proxy's master process runs as root.
func TestAnAbsurdControlAddressFallsBackToTheDefault(t *testing.T) {
	for _, bad := range []string{
		"mgmt:9444\";\n    content_by_lua_block { os.execute(\"sh\") }\n    #",
		"mgmt 9444",
		"mgmt:notaport",
		"$evil:9444",
		"",
	} {
		out, err := renderSite(gatedSite(), SiteRender{
			CertsDir: "/certs", ControlInternal: bad,
		})
		if err != nil {
			t.Fatalf("rendering with %q: %v", bad, err)
		}
		if !strings.Contains(out, `set $moswaf_mgmt "mgmt:9444";`) {
			t.Errorf("%q was written into the config instead of being refused", bad)
		}
	}
}

// The gate's paths exist twice: as Go constants that generate the nginx locations,
// and as Lua constants that decide which requests are exempt from it. If they
// drift, nginx routes the login page somewhere the gate still protects - a login
// page nobody can reach - or the gate exempts a path nginx sends straight to the
// upstream, which is a hole.
func TestTheGatePathsMatchTheDataPlane(t *testing.T) {
	src, err := os.ReadFile(filepath.Join("..", "..", "..",
		"dataplane", "lua", "moswaf", "auth.lua"))
	if err != nil {
		t.Skipf("cannot read the data plane source: %v", err)
	}
	lua := string(src)

	for name, want := range map[string]string{
		"LOGIN_URI":  loginPath,
		"LOGOUT_URI": logoutPath,
	} {
		if !strings.Contains(lua, fmt.Sprintf("%q", want)) {
			t.Errorf("auth.lua does not mention %q for %s; nginx routes it and the "+
				"gate exempts whatever auth.lua says", want, name)
		}
	}

	login, err := os.ReadFile(filepath.Join("..", "..", "..",
		"dataplane", "lua", "moswaf", "login.lua"))
	if err != nil {
		t.Skipf("cannot read the data plane source: %v", err)
	}
	if !strings.Contains(string(login), fmt.Sprintf("%q", authBackendPath)) {
		t.Errorf("login.lua does not capture %q; the subrequest would 404 and "+
			"nobody could sign in", authBackendPath)
	}
}

// A login gate over plain HTTP hands over the password and then the session cookie
// to everybody on the path. It would appear to work, which is the worst version of
// not working: the operator puts their admin panel behind it believing it is now
// private.
func TestTheGateRefusesToBeEnabledWithoutHTTPS(t *testing.T) {
	s := gatedSite()
	s.TLSCert, s.TLSKey, s.HasTLS = "", "", false
	if err := store.ValidateSite(s); err == nil {
		t.Error("the gate was accepted on a site with no certificate and no " +
			"automatic certificates; the password would cross the network in clear")
	}

	// A certificate already installed is fine.
	if err := store.ValidateSite(gatedSite()); err != nil {
		t.Errorf("the gate was refused on a site that has a certificate: %v", err)
	}

	// And so is ACME, because the certificate arrives on its own within the minute
	// and the alternative is telling somebody to set the gate up twice.
	s = gatedSite()
	s.TLSCert, s.TLSKey, s.HasTLS = "", "", false
	s.AcmeEnabled, s.AcmeEmail = true, "ops@example.com"
	if err := store.ValidateSite(s); err != nil {
		t.Errorf("the gate was refused on a site with automatic certificates: %v", err)
	}
}
