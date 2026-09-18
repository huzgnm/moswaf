// Package engine connects the control plane to the data plane: it renders the nginx
// config for each site, publishes policy through Redis, and drains the event queue
// from OpenResty back into Postgres.
package engine

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/mosvpn/moswaf/control/internal/store"
)

var idRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{3,31}$`)

// sanitizeComment keeps a value on the single comment line it was written into.
var commentBreakers = strings.NewReplacer("\n", " ", "\r", " ", "\x00", "")

func sanitizeComment(v string) string { return commentBreakers.Replace(v) }

// The gate's endpoints. Under a reserved prefix so that they cannot collide with
// a path the site itself serves, and written once here so the Lua side and the
// generated config cannot drift apart - a login page nginx routes to a different
// place than the gate exempts is a gate with a hole in it.
const (
	loginPath       = "/__moswaf/login"
	logoutPath      = "/__moswaf/logout"
	authBackendPath = "/__moswaf_auth_backend"
)

// SiteRender carries what is needed to render a site config file.
// Always 80/443 in the container; the ports are configurable for local development.
type SiteRender struct {
	CertsDir  string
	HTTPPort  int
	HTTPSPort int

	// host:port of the control plane's internal listener, which the login form
	// posts to. Never reachable from outside the container network.
	ControlInternal string
}

func (o SiteRender) normalized() SiteRender {
	if o.HTTPPort == 0 {
		o.HTTPPort = 80
	}
	if o.HTTPSPort == 0 {
		o.HTTPSPort = 443
	}
	// Written straight into a generated nginx directive, so anything that could end
	// that directive early is refused and the default used instead. It comes from
	// an environment variable rather than from a request, but a config file that
	// can be extended by setting one is worth a line to prevent.
	if o.ControlInternal == "" || !controlInternalRe.MatchString(o.ControlInternal) {
		o.ControlInternal = "mgmt:9444"
	}
	return o
}

var controlInternalRe = regexp.MustCompile(`^[A-Za-z0-9._-]+:[0-9]{1,5}$`)

// renderSite produces the .conf contents for one site.
//
// Two shapes:
//   - with a certificate: one server block on the HTTP port (redirect or serve)
//     and one on the HTTPS port
//   - without a certificate: only the HTTP server block
func renderSite(s *store.Site, opt SiteRender) (string, error) {
	opt = opt.normalized()
	certsDir := opt.CertsDir
	if !idRe.MatchString(s.ID) {
		return "", fmt.Errorf("invalid site id: %q", s.ID)
	}
	if err := store.ValidateSite(s); err != nil {
		return "", err
	}

	names := strings.Join(s.Domains, " ")
	upstream := fmt.Sprintf("moswaf_up_%s", strings.ReplaceAll(s.ID, "-", "_"))
	proxyTarget := fmt.Sprintf("%s://%s", s.UpstreamScheme, upstream)

	var b strings.Builder
	w := func(format string, args ...any) { fmt.Fprintf(&b, format+"\n", args...) }

	w("# ====================================================================")
	// ValidateSite already rejects control characters, but this file is included
	// straight into http{} so the comment line is sanitised here as well.
	w("# MosWAF - %s (%s)", sanitizeComment(s.Name), s.ID)
	w("# Generated automatically by the control plane. Do not edit by hand.")
	w("# ====================================================================")
	w("")
	w("upstream %s {", upstream)
	w("    server %s:%d max_fails=3 fail_timeout=10s;", s.UpstreamHost, s.UpstreamPort)
	w("    keepalive 32;")
	w("}")
	w("")

	// Shared body: WAF plus proxying
	body := func(indent string) {
		w("%sset $moswaf_site \"%s\";", indent, s.ID)
		w("%slimit_conn moswaf_conn 200;", indent)
		w("%slimit_req  zone=moswaf_hard burst=200 nodelay;", indent)
		w("")
		w("%saccess_by_lua_block { require(\"moswaf.access\").run() }", indent)
		w("%slog_by_lua_block    { require(\"moswaf.log\").run() }", indent)
		w("")
		// The login gate's own endpoints.
		//
		// Exact-match locations ("location = /path"), not prefixes. A prefix would
		// make "/__moswaf/loginbypass" reach the login handler too, and the handler
		// is the one place on a gated site that answers without a session.
		//
		// The engine still runs here - the headers are still stripped, the address is
		// still checked against the blocklist, the rate limit still applies - but the
		// signature rules do not. A password is allowed to contain the characters a
		// SQL injection rule looks for, and refusing to let somebody sign in because
		// their password contains an apostrophe would be a rule blocking the person
		// it is protecting.
		w("%slocation = %s {", indent, loginPath)
		w("%s    access_by_lua_block { require(\"moswaf.access\").login() }", indent)
		w("%s    limit_req zone=moswaf_hard burst=10 nodelay;", indent)
		w("%s    limit_conn moswaf_conn 10;", indent)
		// Declared here, in the location that makes the subrequest, because this is
		// where ngx.location.capture fills them in. Declaring them in the target
		// location instead would reset them to empty in its rewrite phase, after the
		// values had been passed - the request would arrive at the control plane
		// naming no site and carrying no token.
		w("%s    set $moswaf_auth_site  \"\";", indent)
		w("%s    set $moswaf_auth_ip    \"\";", indent)
		w("%s    set $moswaf_auth_token \"\";", indent)
		w("%s    content_by_lua_block { require(\"moswaf.login\").serve() }", indent)
		w("%s}", indent)
		w("")
		w("%slocation = %s {", indent, logoutPath)
		w("%s    access_by_lua_block { require(\"moswaf.access\").login() }", indent)
		w("%s    content_by_lua_block { require(\"moswaf.login\").logout() }", indent)
		w("%s}", indent)
		w("")
		// Where the one request per session that carries a password goes.
		//
		// `internal` means nginx refuses it from outside entirely: it is reachable
		// from ngx.location.capture and from nowhere else. Without it, this would be
		// a public path that forwards an arbitrary body to the control plane's
		// internal listener with the internal token attached.
		w("%slocation = %s {", indent, authBackendPath)
		w("%s    internal;", indent)
		w("%s    access_by_lua_block { return }", indent)
		// Static values, every one of them from a variable this server filled in.
		// None is derived from a request header: "$http_x_moswaf_token" here would
		// be a client-supplied value being handed back as proof of who we are.
		w("%s    proxy_set_header X-MosWAF-Site  $moswaf_auth_site;", indent)
		w("%s    proxy_set_header X-MosWAF-IP    $moswaf_auth_ip;", indent)
		w("%s    proxy_set_header X-MosWAF-Token $moswaf_auth_token;", indent)
		w("%s    proxy_set_header Content-Type   \"application/json\";", indent)
		w("%s    proxy_set_header Cookie         \"\";", indent)
		w("%s    proxy_set_header Authorization  \"\";", indent)
		// Through a variable so the name is resolved per request rather than once at
		// startup. Named directly, nginx refuses to start whenever the control plane
		// is not up yet - which is every cold boot, and would take the whole data
		// plane down with it.
		w("%s    set $moswaf_mgmt \"%s\";", indent, opt.ControlInternal)
		w("%s    proxy_pass http://$moswaf_mgmt/internal/site-login;", indent)
		w("%s}", indent)
		w("")

		w("%slocation / {", indent)
		w("%s    proxy_pass %s;", indent, proxyTarget)
		if s.UpstreamScheme == "https" {
			w("%s    proxy_ssl_server_name on;", indent)
			w("%s    proxy_ssl_name %s;", indent, s.UpstreamHost)
		}
		w("%s}", indent)
	}

	// The ACME location has to be exempt from the engine, and saying so in a comment
	// is not enough: access_by_lua_block and the limits below are declared at server
	// level, and nginx inherits them into every location that does not redefine them.
	// Left inherited, a certificate could not be renewed at the exact moment it
	// matters most - under-attack mode answers the authority with a JavaScript
	// challenge it cannot solve, and a site set to challenge every visitor could
	// never obtain its first certificate at all.
	//
	// Exempt does not mean unbounded: the path still carries its own, much smaller
	// limits, so it cannot become the cheap flood channel the engine exists to stop.
	acme := func(indent string) {
		w("%slocation /.well-known/acme-challenge/ {", indent)
		w("%s    access_by_lua_block { return }", indent)
		w("%s    limit_req zone=moswaf_hard burst=10 nodelay;", indent)
		w("%s    limit_conn moswaf_conn 10;", indent)
		w("%s    content_by_lua_block { require(\"moswaf.acme\").serve() }", indent)
		w("%s}", indent)
	}

	if s.HasTLS {
		crt := filepath.Join(certsDir, s.ID+".crt")
		key := filepath.Join(certsDir, s.ID+".key")

		w("server {")
		w("    listen %d;", opt.HTTPPort)
		w("    server_name %s;", names)
		acme("    ")
		if s.ForceHTTPS {
			w("    location / { return 301 https://$host$request_uri; }")
		} else {
			body("    ")
		}
		w("}")
		w("")
		w("server {")
		w("    listen %d ssl;", opt.HTTPSPort)
		w("    http2 on;")
		w("    server_name %s;", names)
		w("")
		w("    ssl_certificate     %s;", crt)
		w("    ssl_certificate_key %s;", key)
		w("    ssl_protocols       TLSv1.2 TLSv1.3;")
		w("    ssl_ciphers         ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305;")
		w("    ssl_prefer_server_ciphers off;")
		w("    ssl_session_cache   shared:MosWAF:10m;")
		w("    ssl_session_timeout 1d;")
		w("    ssl_session_tickets off;")
		if s.ForceHTTPS {
			w("    add_header Strict-Transport-Security \"max-age=31536000\" always;")
		}
		w("")
		// Validation itself runs over port 80, but a CA is allowed to follow a
		// redirect to HTTPS, and some do. Answering here as well costs nothing and
		// avoids a renewal failing for a reason nobody would think to look for.
		acme("    ")
		w("")
		body("    ")
		w("}")
	} else {
		// No certificate yet. The HTTP block still carries the ACME location, which
		// is how a site with automatic certificates gets its first one.
		w("server {")
		w("    listen %d;", opt.HTTPPort)
		w("    server_name %s;", names)
		acme("    ")
		w("")
		body("    ")
		w("}")
	}

	return b.String(), nil
}

// WriteSiteConfigs rewrites every site config file and certificate and removes the
// files of deleted sites. The watcher inside the proxy container notices the change
// and reloads on its own.
func WriteSiteConfigs(sites []*store.Site, sitesDir string, opt SiteRender) error {
	opt = opt.normalized()
	certsDir := opt.CertsDir

	if err := os.MkdirAll(sitesDir, 0o755); err != nil {
		return err
	}
	if err := os.MkdirAll(certsDir, 0o700); err != nil {
		return err
	}

	keep := map[string]bool{}

	for _, s := range sites {
		if !s.Enabled {
			continue
		}
		conf, err := renderSite(s, opt)
		if err != nil {
			return fmt.Errorf("site %s: %w", s.Name, err)
		}

		if s.HasTLS {
			if err := os.WriteFile(filepath.Join(certsDir, s.ID+".crt"), []byte(s.TLSCert), 0o644); err != nil {
				return err
			}
			if err := os.WriteFile(filepath.Join(certsDir, s.ID+".key"), []byte(s.TLSKey), 0o600); err != nil {
				return err
			}
		}

		name := s.ID + ".conf"
		keep[name] = true

		// write to a temp file then rename, so nginx never reads a half-written file
		tmp := filepath.Join(sitesDir, "."+name+".tmp")
		if err := os.WriteFile(tmp, []byte(conf), 0o644); err != nil {
			return err
		}
		if err := os.Rename(tmp, filepath.Join(sitesDir, name)); err != nil {
			return err
		}
	}

	entries, err := os.ReadDir(sitesDir)
	if err != nil {
		return err
	}
	for _, e := range entries {
		n := e.Name()
		if strings.HasSuffix(n, ".conf") && !keep[n] {
			_ = os.Remove(filepath.Join(sitesDir, n))
			id := strings.TrimSuffix(n, ".conf")
			_ = os.Remove(filepath.Join(certsDir, id+".crt"))
			_ = os.Remove(filepath.Join(certsDir, id+".key"))
		}
	}
	return nil
}
