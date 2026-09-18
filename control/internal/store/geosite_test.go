package store

import "testing"

// A site rule that cannot be used must fall back to "follow the global rule", not
// to "off".
//
// The two are not interchangeable at site level and the difference is a loss of
// protection. Say the global rule blocks a country. An operator opens one site,
// picks "allow", and has not filled the list in yet - an unusable rule. Falling
// back to "off" makes that site stop inheriting the global block, so a half-typed
// rule leaves the site LESS protected than before anybody touched it, and the
// dashboard shows "off" as though somebody had asked for it.
func TestAnUnusableSiteRuleFallsBackToInheriting(t *testing.T) {
	s := &Site{
		Name: "X", Domains: []string{"x.example"}, UpstreamScheme: "http",
		UpstreamHost: "app", UpstreamPort: 80, Enabled: true,
		GeoMode: "allow", GeoCountries: []string{},
	}
	if err := ValidateSite(s); err != nil {
		t.Fatalf("validate: %v", err)
	}
	if s.GeoMode != "" {
		t.Errorf("an allow rule naming no countries became %q; at site level that "+
			"stops the global rule being inherited, so a half-finished rule removes "+
			"protection the site already had", s.GeoMode)
	}

	// "off" typed deliberately must survive untouched - that is an operator saying
	// "this site opts out", and it must not be undone by the next global change.
	s.GeoMode, s.GeoCountries = "off", []string{}
	if err := ValidateSite(s); err != nil {
		t.Fatal(err)
	}
	if s.GeoMode != "off" {
		t.Errorf("a deliberate \"off\" became %q", s.GeoMode)
	}

	// And a usable rule is kept.
	s.GeoMode, s.GeoCountries = "allow", []string{"vn"}
	if err := ValidateSite(s); err != nil {
		t.Fatal(err)
	}
	if s.GeoMode != "allow" || len(s.GeoCountries) != 1 || s.GeoCountries[0] != "VN" {
		t.Errorf("a usable rule was altered: %q %v", s.GeoMode, s.GeoCountries)
	}
}
