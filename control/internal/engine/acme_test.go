package engine

import (
	"testing"
	"time"

	"github.com/mosvpn/moswaf/control/internal/store"
)

func ptr(t time.Time) *time.Time { return &t }

// NeedsCertificate decides whether a live site keeps serving TLS or starts showing
// browser warnings, so each branch is pinned here.
func TestNeedsCertificate(t *testing.T) {
	now := time.Date(2026, 9, 17, 12, 0, 0, 0, time.UTC)

	cases := []struct {
		name string
		site store.Site
		want bool
	}{
		{"acme off is left alone", store.Site{
			Enabled: true, AcmeEnabled: false,
		}, false},
		{"a disabled site is not renewed", store.Site{
			Enabled: false, AcmeEnabled: true,
		}, false},
		{"no certificate yet", store.Site{
			Enabled: true, AcmeEnabled: true,
		}, true},
		{"a certificate well inside its life is left alone", store.Site{
			Enabled: true, AcmeEnabled: true, TLSCert: "x",
			CertExpiresAt: ptr(now.Add(60 * 24 * time.Hour)),
		}, false},
		{"renewed once inside the 30 day window", store.Site{
			Enabled: true, AcmeEnabled: true, TLSCert: "x",
			CertExpiresAt: ptr(now.Add(29 * 24 * time.Hour)),
		}, true},
		{"an already expired certificate is renewed", store.Site{
			Enabled: true, AcmeEnabled: true, TLSCert: "x",
			CertExpiresAt: ptr(now.Add(-time.Hour)),
		}, true},
		{"a recent failure is backed off", store.Site{
			Enabled: true, AcmeEnabled: true,
			AcmeLastError: "dns lookup failed", AcmeLastTry: ptr(now.Add(-5 * time.Minute)),
		}, false},
		{"the back-off expires", store.Site{
			Enabled: true, AcmeEnabled: true,
			AcmeLastError: "dns lookup failed", AcmeLastTry: ptr(now.Add(-2 * time.Hour)),
		}, true},
		{"a successful attempt does not back off", store.Site{
			Enabled: true, AcmeEnabled: true,
			AcmeLastTry: ptr(now.Add(-time.Minute)),
		}, true},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, why := NeedsCertificate(&c.site, now)
			if got != c.want {
				t.Fatalf("NeedsCertificate = %v (%q), want %v", got, why, c.want)
			}
			if got && why == "" {
				t.Error("a renewal was requested without saying why")
			}
		})
	}
}

// A certificate must never be requested for something a CA cannot validate.
func TestValidateSiteRejectsACMEWithoutARealDomain(t *testing.T) {
	for _, domain := range []string{"127.0.0.1", "localhost", "internal"} {
		s := &store.Site{
			Name: "demo", Domains: []string{domain}, UpstreamHost: "10.0.0.5",
			UpstreamPort: 8080, UpstreamScheme: "http",
			AcmeEnabled: true, AcmeEmail: "ops@example.com",
		}
		if err := store.ValidateSite(s); err == nil {
			t.Errorf("ACME was accepted for %q, which no CA can validate", domain)
		}
	}
}

func TestValidateSiteRequiresEmailForACME(t *testing.T) {
	s := &store.Site{
		Name: "demo", Domains: []string{"acme.test"}, UpstreamHost: "10.0.0.5",
		UpstreamPort: 8080, UpstreamScheme: "http", AcmeEnabled: true,
	}
	if err := store.ValidateSite(s); err == nil {
		t.Fatal("ACME was accepted with no contact address")
	}
}

// Domains a certificate authority can never validate over HTTP-01. Each failed
// order counts against the per-domain rate limit and the sweep would retry hourly
// forever, so they have to be refused when the site is saved.
func TestValidateSiteRejectsUnusableACMEDomains(t *testing.T) {
	cases := []struct {
		domain string
		why    string
	}{
		{"*.example.com", "wildcards need DNS-01"},
		{"1.2.3.4.", "an address with a trailing dot is still an address"},
		{"1.2.3.4", "a bare address"},
		{"localhost", "no public domain"},
		{"acme..test", "an empty label"},
		{"-bad.example.com", "a label starting with a hyphen"},
		{"bad-.example.com", "a label ending with a hyphen"},
	}

	for _, c := range cases {
		t.Run(c.domain, func(t *testing.T) {
			s := &store.Site{
				Name: "demo", Domains: []string{c.domain}, UpstreamHost: "10.0.0.5",
				UpstreamPort: 8080, UpstreamScheme: "http",
				AcmeEnabled: true, AcmeEmail: "ops@example.com",
			}
			if err := store.ValidateSite(s); err == nil {
				t.Errorf("accepted %q: %s", c.domain, c.why)
			}
		})
	}
}

func TestValidateSiteAcceptsOrdinaryACMEDomains(t *testing.T) {
	s := &store.Site{
		Name: "demo", Domains: []string{"example.com", "www.example.com"},
		UpstreamHost: "10.0.0.5", UpstreamPort: 8080, UpstreamScheme: "http",
		AcmeEnabled: true, AcmeEmail: "ops@example.com",
	}
	if err := store.ValidateSite(s); err != nil {
		t.Fatalf("a normal ACME site was rejected: %v", err)
	}
}

// The dashboard button places a real order, so it needs a floor between attempts -
// but a short one, since it exists to retry immediately after fixing DNS.
func TestManualIssueCooldown(t *testing.T) {
	now := time.Date(2026, 9, 17, 12, 0, 0, 0, time.UTC)

	if w := store.ManualIssueCooldown(&store.Site{}, now); w != 0 {
		t.Errorf("a site that has never been tried should be allowed, got %v", w)
	}
	recent := now.Add(-time.Minute)
	if w := store.ManualIssueCooldown(&store.Site{AcmeLastTry: &recent}, now); w <= 0 {
		t.Error("an attempt a minute ago should still be cooling down")
	}
	old := now.Add(-10 * time.Minute)
	if w := store.ManualIssueCooldown(&store.Site{AcmeLastTry: &old}, now); w != 0 {
		t.Errorf("an attempt ten minutes ago should be allowed, got %v", w)
	}
}
