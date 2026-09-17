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
