package api

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/mosvpn/moswaf/control/internal/config"
	"github.com/mosvpn/moswaf/control/internal/store"
)

func testServer() *Server {
	return &Server{
		cfg: &config.Config{
			JWTSecret: []byte("test-secret-not-used-anywhere-else"),
			TokenTTL:  12 * time.Hour,
		},
		login: &loginGuard{data: map[string]*attempt{}},
	}
}

func TestTokenRoundTrip(t *testing.T) {
	s := testServer()
	raw, exp, err := s.issueToken(&store.User{ID: 7, Username: "admin"})
	if err != nil {
		t.Fatalf("issueToken: %v", err)
	}
	if time.Until(exp) > 13*time.Hour {
		t.Errorf("token lives longer than the configured TTL: %v", exp)
	}

	u, err := s.parseToken(raw)
	if err != nil {
		t.Fatalf("parseToken: %v", err)
	}
	if u.ID != 7 || u.Username != "admin" {
		t.Fatalf("round trip lost the identity: %+v", u)
	}
}

// alg=none is the classic JWT forgery. jwt.WithValidMethods should stop it.
func TestParseTokenRejectsAlgNone(t *testing.T) {
	s := testServer()

	b64 := func(v string) string {
		return base64.RawURLEncoding.EncodeToString([]byte(v))
	}
	forged := b64(`{"alg":"none","typ":"JWT"}`) + "." +
		b64(`{"sub":"1","usr":"admin","exp":99999999999}`) + "."

	if _, err := s.parseToken(forged); err == nil {
		t.Fatal("an alg=none token was accepted: full authentication bypass")
	}
}

func TestParseTokenRejectsAnotherSecret(t *testing.T) {
	s := testServer()
	other := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": "1", "usr": "admin", "exp": time.Now().Add(time.Hour).Unix(),
	})
	raw, err := other.SignedString([]byte("a-different-secret"))
	if err != nil {
		t.Fatalf("signing: %v", err)
	}
	if _, err := s.parseToken(raw); err == nil {
		t.Fatal("a token signed with the wrong secret was accepted")
	}
}

func TestParseTokenRejectsExpired(t *testing.T) {
	s := testServer()
	old := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": "1", "usr": "admin", "exp": time.Now().Add(-time.Minute).Unix(),
	})
	raw, err := old.SignedString(s.cfg.JWTSecret)
	if err != nil {
		t.Fatalf("signing: %v", err)
	}
	if _, err := s.parseToken(raw); err == nil {
		t.Fatal("an expired token was accepted")
	}
}

func TestRequireAuthRejectsUnauthenticatedRequests(t *testing.T) {
	s := testServer()
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("the handler ran without a valid token")
	})
	h := s.requireAuth(next)

	for _, hdr := range []string{"", "Bearer", "Bearer ", "Basic YWRtaW46YWRtaW4=", "Bearer not.a.token"} {
		req := httptest.NewRequest(http.MethodGet, "/api/sites", nil)
		if hdr != "" {
			req.Header.Set("Authorization", hdr)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("Authorization %q -> %d, want 401", hdr, rec.Code)
		}
	}
}

func TestLoginGuardLocksOutAfterRepeatedFailures(t *testing.T) {
	g := &loginGuard{data: map[string]*attempt{}}
	const ip = "203.0.113.9"

	for i := 0; i < 4; i++ {
		g.fail(ip)
		if w := g.blocked(ip); w != 0 {
			t.Fatalf("locked out after only %d failures (wait %ds)", i+1, w)
		}
	}
	g.fail(ip) // 5th
	if g.blocked(ip) == 0 {
		t.Fatal("no lockout after 5 failed logins")
	}

	g.success(ip)
	if g.blocked(ip) != 0 {
		t.Fatal("a successful login did not clear the lockout")
	}
}

// loginGuard.cleanup only deletes entries where `fails == 0`, but fail() always
// increments fails and success() deletes the entry outright - so no entry is ever
// eligible for reaping. The map keeps one *attempt per source IP that has ever
// failed a login, for the lifetime of the process.
//
// /api/auth/login is unauthenticated, so an attacker can grow that map at will from
// spoofed-source or distributed clients until the control plane runs out of memory.
func TestLoginGuardReleasesInertEntries(t *testing.T) {
	g := &loginGuard{data: map[string]*attempt{}}
	const ip = "203.0.113.9"

	g.fail(ip)
	if w := g.blocked(ip); w != 0 {
		t.Fatalf("a single failure should not block (wait %ds)", w)
	}

	g.mu.Lock()
	held := len(g.data)
	g.mu.Unlock()

	if held != 0 {
		t.Fatalf("%d inert entry/entries retained: cleanup() requires fails==0, which "+
			"fail() never leaves behind, so the map grows once per attacking IP and is "+
			"never freed", held)
	}
}

func TestSecureHeadersAreSet(t *testing.T) {
	h := secureHeaders(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	want := map[string]string{
		"X-Content-Type-Options": "nosniff",
		"X-Frame-Options":        "DENY",
		"Referrer-Policy":        "no-referrer",
	}
	for k, v := range want {
		if got := rec.Header().Get(k); got != v {
			t.Errorf("%s = %q, want %q", k, got, v)
		}
	}
	if csp := rec.Header().Get("Content-Security-Policy"); !strings.Contains(csp, "default-src 'self'") {
		t.Errorf("Content-Security-Policy = %q", csp)
	}
}
