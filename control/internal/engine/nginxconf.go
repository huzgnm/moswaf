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

// SiteRender carries what is needed to render a site config file.
// Always 80/443 in the container; the ports are configurable for local development.
type SiteRender struct {
	CertsDir  string
	HTTPPort  int
	HTTPSPort int
}

func (o SiteRender) normalized() SiteRender {
	if o.HTTPPort == 0 {
		o.HTTPPort = 80
	}
	if o.HTTPSPort == 0 {
		o.HTTPSPort = 443
	}
	return o
}

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
	w("# MosWAF - %s (%s)", s.Name, s.ID)
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
		w("%slocation / {", indent)
		w("%s    proxy_pass %s;", indent, proxyTarget)
		if s.UpstreamScheme == "https" {
			w("%s    proxy_ssl_server_name on;", indent)
			w("%s    proxy_ssl_name %s;", indent, s.UpstreamHost)
		}
		w("%s}", indent)
	}

	acme := func(indent string) {
		w("%slocation /.well-known/acme-challenge/ {", indent)
		w("%s    root /var/www/acme;", indent)
		w("%s    try_files $uri =404;", indent)
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
		body("    ")
		w("}")
	} else {
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
