package api

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/mosvpn/moswaf/control/internal/store"
)

// The login half of the site gate.
//
// Checking a session is done entirely in the data plane, from a signed cookie and
// a table in the published configuration - no database, no network, on every
// request. Issuing one cannot be: it needs the password hashes and it needs
// bcrypt, and neither belongs in a request path that an attacker can drive.
//
// So the split is: the data plane serves the login page and verifies every
// session, and hands the one request per session that contains a password to the
// control plane. The cost of that split is written down plainly - with the
// control plane stopped, nobody can sign in, but everybody already signed in
// stays signed in and the site keeps serving.

const (
	// Long enough that a working day does not interrupt itself, short enough that a
	// cookie lifted off a machine somebody walked away from stops working the same
	// day. There is no refresh and no "remember me": a session that renews itself
	// on use is a session that never expires for the one visitor who matters least.
	sessionTTL = 12 * time.Hour
)

// Failures are counted per site and per address together, not per address alone.
// Keyed by address only, somebody guessing at one site would lock the guesser out
// of every other site on the machine - which is a way to take a neighbour's login
// page down rather than a defence. Keyed by site only, one address could lock out
// every visitor to that site.
func siteLoginKey(site, ip string) string { return site + "|" + ip }

// SiteSessionSecret is the key both halves sign with.
//
// Shared with the JavaScript challenge rather than generated separately, and that
// is a decision rather than laziness: a second secret is a second thing to create
// at install, carry through an upgrade, and fail to rotate. Anything that can read
// one can read the other - they live in the same file, on the same host, for the
// same two processes - so a separate key would buy the appearance of separation
// and no separation.
//
// The reason the two uses cannot be confused for one another is the signed string,
// not the key: a challenge token and a session token have different shapes and
// different fields, and neither parses as the other.
func (s *Server) siteSessionSecret() string { return s.cfg.ChallengeSecret }

// signSession produces exactly what dataplane/lua/moswaf/auth.lua verifies.
//
// The site id is signed but not carried. The data plane already knows which site
// it is serving, and it must compare against that rather than against anything the
// cookie says - a value the token supplies can never be used to check the token.
// Leaving it out of the cookie makes that the only thing the code can do.
func signSession(secret, siteID string, userID, generation int64, exp int64) string {
	msg := fmt.Sprintf("%s|%d|%d|%d", siteID, userID, generation, exp)
	mac := hmac.New(sha1.New, []byte(secret))
	mac.Write([]byte(msg))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return fmt.Sprintf("%d.%d.%d.%s", userID, generation, exp, sig)
}

// InternalHandler is what the data plane talks to.
//
// Served on its own listener, which is never published outside the container
// network - see docker-compose.yml, where it has no ports entry. It carries the
// login endpoint and nothing else: the dashboard, the admin API and the session
// cookie that operates them are all on the other listener, so a mistake here
// cannot reach them.
func (s *Server) InternalHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /internal/site-login", s.handleSiteLogin)
	mux.HandleFunc("GET /internal/health", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"status": "ok"})
	})
	return recoverer(s.requireInternalToken(mux))
}

// requireInternalToken refuses anything that cannot prove it is the data plane.
//
// The listener is already unreachable from outside the container network, so this
// is the second lock rather than the first: it is what stands between a site whose
// upstream is a container on the same network - which is the normal way to run
// this - and that container being able to mint sessions for every gated site.
func (s *Server) requireInternalToken(next http.Handler) http.Handler {
	want := s.cfg.InternalToken
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if want == "" {
			// Refuse rather than allow. An install that somehow has no token would
			// otherwise have an unauthenticated session minter on its network.
			writeErr(w, http.StatusServiceUnavailable, "the internal token is not configured")
			return
		}
		got := r.Header.Get("X-MosWAF-Token")
		if subtle.ConstantTimeCompare([]byte(got), []byte(want)) != 1 {
			writeErr(w, http.StatusForbidden, "forbidden")
			return
		}
		next.ServeHTTP(w, r)
	})
}

type siteLoginRequest struct {
	Site     string `json:"site"`
	Username string `json:"username"`
	Password string `json:"password"`
	Next     string `json:"next"`
	IP       string `json:"ip"`
}

func (s *Server) handleSiteLogin(w http.ResponseWriter, r *http.Request) {
	var req siteLoginRequest
	if !readJSON(w, r, &req) {
		return
	}

	// The site is taken from the header the data plane sets from its own
	// configuration, never from the body. The body is written by whoever is trying
	// to sign in, and a body that could name the site would let an attacker with an
	// account on their own site request a session for somebody else's.
	site := strings.TrimSpace(r.Header.Get("X-MosWAF-Site"))
	if site == "" {
		writeErr(w, http.StatusBadRequest, "no site")
		return
	}

	// Likewise the address: used only for the attempt counter, and taken from the
	// data plane, which has already worked out the real client address behind
	// whatever proxies the operator configured.
	ip := strings.TrimSpace(r.Header.Get("X-MosWAF-IP"))
	if ip == "" {
		ip = "unknown"
	}

	key := siteLoginKey(site, ip)
	if wait := s.siteLogin.blocked(key); wait > 0 {
		// 429 rather than 401: this is not a statement about the password, and
		// answering 401 here would let an attacker use the lockout itself to test
		// whether they had guessed right.
		w.Header().Set("Retry-After", strconv.Itoa(wait))
		writeErr(w, http.StatusTooManyRequests,
			"too many attempts; wait a few minutes and try again")
		return
	}

	user, err := s.db.AuthenticateSiteUser(r.Context(), site, req.Username, req.Password)
	if err != nil {
		if errors.Is(err, store.ErrBadCredentials) {
			s.siteLogin.fail(key)
			// One message for a wrong name and a wrong password. Two would make this
			// endpoint a way to find out which accounts exist.
			writeErr(w, http.StatusUnauthorized, "wrong username or password")
			return
		}
		writeErr(w, http.StatusInternalServerError, "could not check those details")
		return
	}
	s.siteLogin.success(key)

	secret := s.siteSessionSecret()
	if secret == "" {
		writeErr(w, http.StatusServiceUnavailable, "the session secret is not configured")
		return
	}

	exp := time.Now().Add(sessionTTL).Unix()
	token := signSession(secret, site, user.ID, user.Generation, exp)

	writeJSON(w, http.StatusOK, map[string]any{
		"token": token,
		// Seconds, so the data plane does not have to agree with this one about what
		// time it is to set the cookie's lifetime.
		"max_age": int(sessionTTL / time.Second),
		"next":    safeNext(req.Next),
	})
}

// safeNext keeps the post-login redirect on this site.
//
// "next" arrives in a query string, which means an attacker chooses it: a link to
// the real login page of the real site, which after a real sign-in lands the
// visitor somewhere else entirely. Only a plain absolute path survives - no
// scheme, no "//host" that a browser reads as one, no backslash that some of them
// also read as one, and no control character that could be used to split a header.
func safeNext(v string) string {
	if v == "" || len(v) > 1024 {
		return "/"
	}
	if !strings.HasPrefix(v, "/") {
		return "/"
	}
	if len(v) > 1 && (v[1] == '/' || v[1] == '\\') {
		return "/"
	}
	if strings.ContainsAny(v, "\x00\r\n") {
		return "/"
	}
	for _, c := range v {
		if c < 0x20 || c == 0x7f {
			return "/"
		}
	}
	if strings.Contains(strings.ToLower(v), "://") {
		return "/"
	}
	return v
}
