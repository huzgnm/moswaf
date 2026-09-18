package store

import (
	"strings"
	"testing"
)

// The stored path and the path the gate compares against have to be the same
// shape, or a rule that reads as protection provides none. This is applied both
// where the operator types and again at publication, because a row can reach the
// table from an older version or from somebody's psql session.
func TestNormaliseAuthPaths(t *testing.T) {
	cases := []struct {
		in   []string
		want []string
		why  string
	}{
		{[]string{"/admin"}, []string{"/admin"}, "the ordinary case"},
		{[]string{"admin"}, []string{"/admin"}, "a missing leading slash"},
		{[]string{"/admin/"}, []string{"/admin"}, "a trailing slash is the same rule"},
		{[]string{"/admin/*"}, []string{"/admin"}, "the wildcard most people write"},
		{[]string{"  /admin  "}, []string{"/admin"}, "surrounding space"},
		{[]string{"/admin", "/ADMIN/"}, []string{"/admin"}, "the same rule twice"},
		{[]string{"/admin?x=1"}, []string{"/admin"}, "$uri never carries a query"},
		{[]string{"/a", "/"}, []string{"/"}, "the whole site absorbs the rest"},
		{nil, []string{"/"}, "nothing listed means the whole site, not nothing"},
		{[]string{}, []string{"/"}, "and so does an empty list"},
		{[]string{"   ", ""}, []string{"/"}, "and so does a list of nothing"},
		{[]string{"/a/../b"}, []string{"/"}, "$uri has .. collapsed out, so it could never match"},
		{[]string{"/a//b"}, []string{"/"}, "and repeated slashes too"},
		{[]string{"/a\nb"}, []string{"/"}, "a newline is not a path"},
	}

	for _, c := range cases {
		got := NormaliseAuthPaths(c.in)
		if strings.Join(got, ",") != strings.Join(c.want, ",") {
			t.Errorf("NormaliseAuthPaths(%q) = %q, want %q - %s", c.in, got, c.want, c.why)
		}
	}
}

// A list long enough to make the per-request loop expensive is a way to slow every
// request to a gated site down, from the dashboard.
func TestTheAuthPathListIsBounded(t *testing.T) {
	in := make([]string, 0, 500)
	for i := 0; i < 500; i++ {
		in = append(in, "/p"+string(rune('a'+i%26))+string(rune('a'+i/26)))
	}
	if got := NormaliseAuthPaths(in); len(got) > maxAuthPaths {
		t.Errorf("kept %d paths; every request to a gated site walks this list", len(got))
	}
}

// A username ends up in the identity header handed to the upstream. A newline in
// the middle of one writes a second header of somebody else's choosing.
func TestSiteUsernamesCannotCarryControlCharacters(t *testing.T) {
	for _, bad := range []string{
		"bob\nX-MosWAF-User: admin",
		"bob\rX-MosWAF-User: admin",
		"bo\x00b",
		"a\x7fb",
		"\x1bbob",
	} {
		if _, err := ValidateSiteUser(bad, "a-long-enough-password"); err == nil {
			t.Errorf("ValidateSiteUser(%q) was accepted; it reaches the upstream in a header", bad)
		}
	}

	// What comes back is what gets stored. The check and the INSERT used to trim
	// separately, which meant the string that was inspected and the string that was
	// written were only the same by agreement between two functions.
	got, err := ValidateSiteUser("  bob\r\n", "a-long-enough-password")
	if err != nil {
		t.Fatalf("surrounding whitespace made an ordinary username invalid: %v", err)
	}
	if got != "bob" {
		t.Errorf("ValidateSiteUser returned %q; the caller writes exactly this value, "+
			"so anything it does not strip is stored", got)
	}

	if _, err := ValidateSiteUser("bob", "short"); err == nil {
		t.Error("a five-character password was accepted")
	}
	if _, err := ValidateSiteUser("", "a-long-enough-password"); err == nil {
		t.Error("an empty username was accepted")
	}
}
