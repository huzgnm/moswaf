package api

import (
	"context"
	"errors"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/mosvpn/moswaf/control/internal/store"
)

type ctxKey string

const ctxUser ctxKey = "moswaf.user"

// ------------------------------------------------------- brute force guard

// How long a failure record is kept once the IP is no longer locked out, and how
// many records may exist at all.
const (
	guardRetention = 30 * time.Minute
	guardMaxIPs    = 50000
)

type attempt struct {
	fails int
	until time.Time
	last  time.Time // last failure, used to reap the record later
}

type loginGuard struct {
	mu   sync.Mutex
	data map[string]*attempt
}

func newLoginGuard() *loginGuard {
	g := &loginGuard{data: map[string]*attempt{}}
	go g.cleanup()
	return g
}

func (g *loginGuard) cleanup() {
	for range time.Tick(time.Minute) {
		g.reap()
	}
}

// reap drops records that are neither locked out nor recently active.
//
// The old condition was `fails == 0`, which fail() never produces and success()
// never leaves behind, so nothing was ever eligible and the map kept one record
// per source IP that had ever failed a login - for the lifetime of the process.
// /api/auth/login needs no authentication, so that was an unbounded allocation
// any client could drive.
func (g *loginGuard) reap() {
	now := time.Now()
	g.mu.Lock()
	defer g.mu.Unlock()
	for k, v := range g.data {
		if now.After(v.until) && now.Sub(v.last) > guardRetention {
			delete(g.data, k)
		}
	}
}

// blocked returns how many seconds are left to wait, or 0 when a retry is allowed.
func (g *loginGuard) blocked(ip string) int {
	g.mu.Lock()
	defer g.mu.Unlock()
	a := g.data[ip]
	if a == nil {
		return 0
	}
	if d := time.Until(a.until); d > 0 {
		return int(d.Seconds()) + 1
	}
	return 0
}

func (g *loginGuard) fail(ip string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	a := g.data[ip]
	if a == nil {
		// Hard ceiling as well as the timed reap: a distributed attempt can create
		// records faster than the reaper removes them.
		if len(g.data) >= guardMaxIPs {
			g.evictOldestLocked()
		}
		a = &attempt{}
		g.data[ip] = a
	}
	a.fails++
	a.last = time.Now()
	switch {
	case a.fails >= 10:
		a.until = time.Now().Add(30 * time.Minute)
	case a.fails >= 5:
		a.until = time.Now().Add(5 * time.Minute)
	}
}

// evictOldestLocked removes the least recently active record. Callers hold g.mu.
func (g *loginGuard) evictOldestLocked() {
	var oldestKey string
	var oldest time.Time
	for k, v := range g.data {
		if oldestKey == "" || v.last.Before(oldest) {
			oldestKey, oldest = k, v.last
		}
	}
	if oldestKey != "" {
		delete(g.data, oldestKey)
	}
}

func (g *loginGuard) success(ip string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	delete(g.data, ip)
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// ------------------------------------------------------- JWT

func (s *Server) issueToken(u *store.User) (string, time.Time, error) {
	exp := time.Now().Add(s.cfg.TokenTTL)
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": strconv.FormatInt(u.ID, 10),
		"usr": u.Username,
		"iat": time.Now().Unix(),
		"exp": exp.Unix(),
	})
	str, err := tok.SignedString(s.cfg.JWTSecret)
	return str, exp, err
}

func (s *Server) parseToken(raw string) (*store.User, error) {
	tok, err := jwt.Parse(raw, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unsupported signing algorithm")
		}
		return s.cfg.JWTSecret, nil
	}, jwt.WithValidMethods([]string{"HS256"}))
	if err != nil {
		return nil, err
	}
	claims, ok := tok.Claims.(jwt.MapClaims)
	if !ok || !tok.Valid {
		return nil, errors.New("invalid token")
	}
	sub, _ := claims["sub"].(string)
	id, err := strconv.ParseInt(sub, 10, 64)
	if err != nil {
		return nil, errors.New("token has no subject")
	}
	usr, _ := claims["usr"].(string)
	return &store.User{ID: id, Username: usr}, nil
}

func (s *Server) requireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := r.Header.Get("Authorization")
		if !strings.HasPrefix(h, "Bearer ") {
			writeErr(w, http.StatusUnauthorized, "not signed in")
			return
		}
		u, err := s.parseToken(strings.TrimPrefix(h, "Bearer "))
		if err != nil {
			writeErr(w, http.StatusUnauthorized, "session is invalid or has expired")
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxUser, u)))
	})
}

func userFrom(r *http.Request) *store.User {
	u, _ := r.Context().Value(ctxUser).(*store.User)
	return u
}

// ------------------------------------------------------- handlers

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)
	if wait := s.login.blocked(ip); wait > 0 {
		w.Header().Set("Retry-After", strconv.Itoa(wait))
		writeErr(w, http.StatusTooManyRequests,
			"Too many failed attempts. Try again in "+strconv.Itoa(wait)+" seconds.")
		return
	}

	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if !readJSON(w, r, &req) {
		return
	}

	u, err := s.db.Authenticate(r.Context(), strings.TrimSpace(req.Username), req.Password)
	if err != nil {
		s.login.fail(ip)
		writeErr(w, http.StatusUnauthorized, "Wrong username or password")
		return
	}
	s.login.success(ip)

	token, exp, err := s.issueToken(u)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "could not create a session")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"token":      token,
		"expires_at": exp,
		"user":       u,
	})
}

func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r)
	full, err := s.db.GetUser(r.Context(), u.ID)
	if err != nil {
		writeErr(w, http.StatusUnauthorized, "this account no longer exists")
		return
	}
	writeJSON(w, http.StatusOK, full)
}

func (s *Server) handleChangePassword(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r)
	var req struct {
		Current string `json:"current"`
		New     string `json:"new"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	if _, err := s.db.Authenticate(r.Context(), u.Username, req.Current); err != nil {
		writeErr(w, http.StatusUnauthorized, "Current password is incorrect")
		return
	}
	if len(req.New) < 8 {
		writeErr(w, http.StatusBadRequest, "The new password must be at least 8 characters")
		return
	}
	if err := s.db.SetPassword(r.Context(), u.Username, req.New); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "password changed"})
}
