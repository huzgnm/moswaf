package api

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"strings"
	"testing"
)

// The cookie is signed here and verified in dataplane/lua/moswaf/auth.lua, in a
// different language, in a different container, from a different build. Nothing
// makes the two agree except that somebody kept them agreeing - so this is the
// test that notices when they stop.
//
// A mismatch does not fail loudly. It refuses every session on every gated site
// with "bad signature", which reads exactly like a visitor typing the wrong
// password.
func TestSessionFormatMatchesWhatTheDataPlaneVerifies(t *testing.T) {
	const (
		secret = "a-secret"
		site   = "s0123456789"
		user   = int64(7)
		gen    = int64(3)
		exp    = int64(1700003600)
	)

	got := signSession(secret, site, user, gen, exp)

	// Written out by hand rather than by calling the same helper, so that a change
	// to the helper has to be repeated here deliberately.
	mac := hmac.New(sha1.New, []byte(secret))
	mac.Write([]byte("s0123456789|7|3|1700003600"))
	want := "7.3.1700003600." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	if got != want {
		t.Fatalf("the session format changed\n got: %s\nwant: %s\n\n"+
			"dataplane/lua/moswaf/auth.lua verifies exactly this shape; a change on "+
			"one side alone refuses every session on every gated site, and the "+
			"visitor sees it as a wrong password", got, want)
	}

	// The four fields, in order, separated the way the Lua pattern expects.
	parts := strings.Split(got, ".")
	if len(parts) != 4 {
		t.Fatalf("the cookie has %d fields, and the data plane matches on four", len(parts))
	}
	// Base64url with no padding: the Lua pattern accepts [%w%-_] and an "=" would
	// not match, so a padded encoding here is refused there.
	if strings.ContainsAny(parts[3], "+/=") {
		t.Errorf("the signature is %q; standard base64 characters do not match the "+
			"pattern the data plane uses, so every session would be rejected", parts[3])
	}
}

// The site is signed but not carried in the cookie. If it were carried, the
// obvious implementation on the other side reads it from there - and a value the
// token supplies can never be used to check the token.
func TestTheSiteIsSignedButNotCarried(t *testing.T) {
	a := signSession("k", "site-a", 7, 3, 1700003600)
	b := signSession("k", "site-b", 7, 3, 1700003600)

	if a == b {
		t.Fatal("two sites produced the same session. One secret signs every site, " +
			"so if the site is not part of the signed message, a cookie minted on " +
			"any site is valid on all of them")
	}
	if strings.Contains(a, "site-a") {
		t.Error("the site id is inside the cookie; leaving it out is what stops the " +
			"verifying side from checking the token against itself")
	}
	// Everything else is, so that none of it can be edited in transit.
	for _, field := range []string{"7", "3", "1700003600"} {
		if !strings.Contains(a, field) {
			t.Errorf("the cookie does not carry %q, which the verifier needs", field)
		}
	}
}

func TestChangingAnyFieldChangesTheSignature(t *testing.T) {
	base := signSession("k", "site-a", 7, 3, 1700003600)
	for name, other := range map[string]string{
		"a different account":    signSession("k", "site-a", 8, 3, 1700003600),
		"a different generation": signSession("k", "site-a", 7, 4, 1700003600),
		"a different expiry":     signSession("k", "site-a", 7, 3, 1700003601),
		"a different secret":     signSession("k2", "site-a", 7, 3, 1700003600),
	} {
		if sig(base) == sig(other) {
			t.Errorf("%s produced the same signature; that field can be edited in "+
				"transit without breaking the cookie", name)
		}
	}
}

func sig(token string) string {
	i := strings.LastIndexByte(token, '.')
	return token[i+1:]
}

// "next" arrives in a query string, which means an attacker chooses it. A link to
// the real login page of the real site that lands the visitor somewhere else after
// a real sign-in is a working phishing step, and the sign-in itself is genuine -
// nothing later in the flow looks wrong.
func TestNextOnlyEverStaysOnThisSite(t *testing.T) {
	for _, bad := range []string{
		"https://evil.example/",
		"//evil.example/",              // protocol-relative; the browser adds the scheme
		"/\\evil.example",              // several browsers read this as protocol-relative too
		"http:/evil.example",           //
		"javascript:alert(1)",          //
		"/ok\r\nSet-Cookie: a=b",       // header splitting, had it reached a header
		"/ok\nLocation: https://evil/", //
		"",
		"ok/relative",
		strings.Repeat("/a", 2000),
	} {
		if got := safeNext(bad); got != "/" {
			t.Errorf("safeNext(%q) = %q, want \"/\"", bad, got)
		}
	}

	for _, ok := range []string{"/", "/admin", "/admin/users?page=2", "/a%20b"} {
		if got := safeNext(ok); got != ok {
			t.Errorf("safeNext(%q) = %q; an ordinary path on this site was discarded, "+
				"which sends everybody to the home page after signing in", ok, got)
		}
	}
}
