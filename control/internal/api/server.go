// Package api serves the REST API and the admin dashboard on their own port.
package api

import (
	"encoding/json"
	"io"
	"io/fs"
	"log"
	"net/http"
	"runtime/debug"
	"strconv"
	"strings"
	"time"

	"github.com/mosvpn/moswaf/control/internal/config"
	"github.com/mosvpn/moswaf/control/internal/engine"
	"github.com/mosvpn/moswaf/control/internal/store"
	"github.com/mosvpn/moswaf/control/internal/web"
	"github.com/redis/go-redis/v9"
)

type Server struct {
	cfg       *config.Config
	db        *store.Store
	rdb       *redis.Client
	geo       *engine.GeoIP
	pub       *engine.Publisher
	certifier *engine.Certifier
	login     *loginGuard
	// Separate from the dashboard's guard. They count different things - one
	// protects the administrator account, the other protects a visitor account on
	// one site - and sharing a counter would let failures against a site lock an
	// operator out of the dashboard they need in order to deal with it.
	siteLogin *loginGuard
}

func New(cfg *config.Config, db *store.Store, rdb *redis.Client, pub *engine.Publisher, certifier *engine.Certifier) *Server {
	return &Server{
		cfg: cfg, db: db, rdb: rdb, pub: pub, certifier: certifier,
		login:     newLoginGuard(),
		siteLogin: newLoginGuard(),
	}
}

func (s *Server) Handler() http.Handler {
	api := http.NewServeMux()

	// --- public ---
	api.HandleFunc("POST /api/auth/login", s.handleLogin)
	api.HandleFunc("GET /api/health", s.handleHealth)

	// --- authenticated ---
	auth := http.NewServeMux()
	auth.HandleFunc("GET /api/auth/me", s.handleMe)
	auth.HandleFunc("POST /api/auth/password", s.handleChangePassword)

	auth.HandleFunc("GET /api/sites", s.handleListSites)
	auth.HandleFunc("POST /api/sites", s.handleCreateSite)
	auth.HandleFunc("GET /api/sites/{id}", s.handleGetSite)
	auth.HandleFunc("PUT /api/sites/{id}", s.handleUpdateSite)
	auth.HandleFunc("DELETE /api/sites/{id}", s.handleDeleteSite)
	auth.HandleFunc("POST /api/sites/{id}/certificate", s.handleIssueCertificate)

	// The accounts behind a site's login gate. Separate from /api/users, which is
	// who may operate MosWAF - one table for both would mean an account created so
	// a colleague could see a staging server could also switch the firewall off.
	auth.HandleFunc("GET /api/sites/{id}/users", s.handleListSiteUsers)
	auth.HandleFunc("POST /api/sites/{id}/users", s.handleCreateSiteUser)
	auth.HandleFunc("PUT /api/sites/{id}/users/{uid}/password", s.handleSetSiteUserPassword)
	auth.HandleFunc("POST /api/sites/{id}/users/{uid}/revoke", s.handleRevokeSiteUser)
	auth.HandleFunc("DELETE /api/sites/{id}/users/{uid}", s.handleDeleteSiteUser)

	auth.HandleFunc("GET /api/rules", s.handleListRules)
	auth.HandleFunc("POST /api/rules", s.handleCreateRule)
	auth.HandleFunc("PUT /api/rules/{id}", s.handleUpdateRule)
	auth.HandleFunc("POST /api/rules/{id}/toggle", s.handleToggleRule)
	auth.HandleFunc("DELETE /api/rules/{id}", s.handleDeleteRule)

	auth.HandleFunc("GET /api/ips", s.handleListIPs)
	auth.HandleFunc("POST /api/ips", s.handleAddIP)
	auth.HandleFunc("DELETE /api/ips/{id}", s.handleDeleteIP)

	auth.HandleFunc("GET /api/bans", s.handleListBans)
	auth.HandleFunc("DELETE /api/bans/{ip}", s.handleUnban)

	auth.HandleFunc("GET /api/events", s.handleListEvents)

	// The country picker reads the loaded dataset, so it can never offer a country
	// that would produce no ranges - which in allow mode refuses every visitor.
	auth.HandleFunc("GET /api/geo/countries", s.handleListCountries)

	auth.HandleFunc("GET /api/stats/overview", s.handleOverview)
	auth.HandleFunc("GET /api/stats/timeseries", s.handleTimeseries)

	auth.HandleFunc("GET /api/settings", s.handleGetSettings)
	auth.HandleFunc("PUT /api/settings", s.handleUpdateSettings)
	auth.HandleFunc("POST /api/settings/under-attack", s.handleUnderAttack)

	auth.HandleFunc("POST /api/system/publish", s.handlePublish)
	auth.HandleFunc("GET /api/system/status", s.handleSystemStatus)

	api.Handle("/api/", s.requireAuth(auth))

	// --- dashboard (SPA) ---
	root := http.NewServeMux()
	root.Handle("/api/", api)
	root.Handle("/", s.spaHandler())

	return logging(secureHeaders(recoverer(root)))
}

// ------------------------------------------------------------- middleware

func recoverer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if v := recover(); v != nil {
				log.Printf("moswaf: panic while handling %s %s: %v\n%s", r.Method, r.URL.Path, v, debug.Stack())
				http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
			}
		}()
		next.ServeHTTP(w, r)
	})
}

func secureHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Content-Security-Policy",
			"default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; connect-src 'self'")
		h.Set("Strict-Transport-Security", "max-age=31536000")
		next.ServeHTTP(w, r)
	})
}

type statusWriter struct {
	http.ResponseWriter
	code int
}

func (w *statusWriter) WriteHeader(c int) {
	w.code = c
	w.ResponseWriter.WriteHeader(c)
}

func logging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/api/") {
			next.ServeHTTP(w, r)
			return
		}
		start := time.Now()
		sw := &statusWriter{ResponseWriter: w, code: 200}
		next.ServeHTTP(sw, r)
		log.Printf("%s %s %d %s", r.Method, r.URL.Path, sw.code, time.Since(start).Round(time.Millisecond))
	})
}

// ------------------------------------------------------------- SPA

func (s *Server) spaHandler() http.Handler {
	dist, err := fs.Sub(web.Dist, "dist")
	if err != nil {
		log.Printf("moswaf: cannot read the embedded dashboard: %v", err)
		return http.NotFoundHandler()
	}
	if _, err := fs.Stat(dist, "index.html"); err != nil {
		// The binary was built without a frontend build - say so instead of a bare 404
		log.Printf("moswaf: no dashboard build found (run `make web-build`)")
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte(`<!doctype html><meta charset="utf-8">
<body style="font-family:system-ui;background:#0b0e14;color:#c9d1d9;padding:40px">
<h2>MosWAF</h2><p>The dashboard has not been built. Run <code>make web-build</code> and restart the control plane.</p>
<p>The API at <code>/api/</code> works normally.</p></body>`))
		})
	}

	files := http.FileServer(http.FS(dist))

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := strings.TrimPrefix(r.URL.Path, "/")
		if p == "" {
			p = "index.html"
		}
		if _, err := fs.Stat(dist, p); err != nil {
			// vue-router path -> serve index.html and let the SPA route it
			r = r.Clone(r.Context())
			r.URL.Path = "/"
		}
		if strings.HasPrefix(p, "assets/") {
			w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		} else {
			w.Header().Set("Cache-Control", "no-cache")
		}
		files.ServeHTTP(w, r)
	})
}

// ------------------------------------------------------------- helpers

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	if v != nil {
		if err := json.NewEncoder(w).Encode(v); err != nil {
			log.Printf("moswaf: failed to write JSON: %v", err)
		}
	}
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

func readJSON(w http.ResponseWriter, r *http.Request, dst any) bool {
	defer r.Body.Close()
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "could not read the request body")
		return false
	}
	if err := json.Unmarshal(body, dst); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return false
	}
	return true
}

func queryInt(r *http.Request, key string, def int) int {
	if v := r.URL.Query().Get(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

// SetGeoIP attaches the geolocation dataset so its state can be reported.
func (s *Server) SetGeoIP(g *engine.GeoIP) { s.geo = g }

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	if err := s.db.Ping(r.Context()); err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"status": "degraded", "db": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok"})
}
