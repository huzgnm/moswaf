package engine

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/mosvpn/moswaf/control/internal/store"
)

// certFor builds a real certificate naming the given domains, so the coverage
// check is exercised against something x509 actually parses rather than a string
// that happens to contain the right words.
func certFor(t *testing.T, domains []string, notAfter time.Time) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating a key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: domains[0]},
		DNSNames:     domains,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     notAfter,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("creating the certificate: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func siteWith(t *testing.T, domains []string, certDomains []string, expires time.Time) *store.Site {
	t.Helper()
	s := &store.Site{
		Enabled: true, AcmeEnabled: true,
		Domains: domains,
	}
	if certDomains != nil {
		s.TLSCert = certFor(t, certDomains, expires)
		exp := expires
		s.CertExpiresAt = &exp
	}
	return s
}

// A certificate is issued for the domains a site had at the time. Add one
// afterwards and the stored certificate is still valid, still weeks from expiry,
// and simply does not name it - so nothing asked for a new one and the added
// domain was served the wrong certificate until the old one neared expiry. Up to
// two months of browser warnings on a domain the operator added and reasonably
// assumed was handled.
func TestACertificateThatDoesNotCoverEveryDomainIsWanted(t *testing.T) {
	now := time.Now()
	far := now.Add(60 * 24 * time.Hour)

	s := siteWith(t, []string{"example.com", "shop.example.com"}, []string{"example.com"}, far)
	want, reason := CertificateWanted(s, now)
	if !want {
		t.Fatal("a site whose certificate does not cover one of its domains was " +
			"reported as needing nothing; that domain would serve the wrong " +
			"certificate until the old one neared expiry")
	}
	if reason == "" {
		t.Error("the reason should name the uncovered domain")
	}

	// Covering every domain, with room before expiry, wants nothing.
	s = siteWith(t, []string{"example.com", "shop.example.com"},
		[]string{"example.com", "shop.example.com"}, far)
	if want, _ := CertificateWanted(s, now); want {
		t.Error("a certificate covering every domain and far from expiry was " +
			"reported as needing renewal")
	}

	// Case and a trailing dot are the same name.
	s = siteWith(t, []string{"Example.COM", "shop.example.com."},
		[]string{"example.com", "shop.example.com"}, far)
	if want, _ := CertificateWanted(s, now); want {
		t.Error("a difference of case or a trailing dot was treated as a different " +
			"domain, which would order a new certificate for no reason every sweep")
	}

	// An extra name in the certificate is not a problem; a missing one is.
	s = siteWith(t, []string{"example.com"},
		[]string{"example.com", "old.example.com"}, far)
	if want, _ := CertificateWanted(s, now); want {
		t.Error("a certificate naming more than the site does was treated as " +
			"insufficient")
	}
}

func TestCertificateWantedCoversTheOrdinaryCases(t *testing.T) {
	now := time.Now()

	if want, _ := CertificateWanted(siteWith(t, []string{"example.com"}, nil, time.Time{}), now); !want {
		t.Error("a site with no certificate should want one")
	}

	soon := now.Add(5 * 24 * time.Hour)
	if want, _ := CertificateWanted(
		siteWith(t, []string{"example.com"}, []string{"example.com"}, soon), now); !want {
		t.Error("a certificate five days from expiry should want renewal")
	}

	off := siteWith(t, []string{"example.com"}, nil, time.Time{})
	off.AcmeEnabled = false
	if want, _ := CertificateWanted(off, now); want {
		t.Error("a site with automatic certificates switched off should want nothing")
	}

	disabled := siteWith(t, []string{"example.com"}, nil, time.Time{})
	disabled.Enabled = false
	if want, _ := CertificateWanted(disabled, now); want {
		t.Error("a disabled site should want nothing")
	}
}

// The two questions are asked by different callers and must answer differently.
// The renewal sweep has to respect the back-off after a failure - that is what
// stops a broken DNS record from hammering the authority. The dashboard button
// exists to retry immediately after fixing DNS, so the back-off must not silence
// it; what must silence it is having nothing to do.
func TestBackOffSilencesTheSweepButNotTheButton(t *testing.T) {
	now := time.Now()
	s := siteWith(t, []string{"example.com"}, nil, time.Time{})
	justTried := now.Add(-time.Minute)
	s.AcmeLastTry = &justTried
	s.AcmeLastError = "dns lookup failed"

	if want, _ := NeedsCertificate(s, now); want {
		t.Error("the sweep ignored the back-off after a failure")
	}
	if want, _ := CertificateWanted(s, now); !want {
		t.Error("the back-off silenced the manual button, which exists precisely " +
			"to retry once the operator has fixed the problem")
	}
}

// Ordering counts against the authority's duplicate-certificate limit - five a
// week for the same set of domains - and unlike the hourly limits that one does
// not forgive itself by lunchtime. This is what the manual endpoint checks
// before placing an order.
func TestAHealthyCertificateIsNotWorthReordering(t *testing.T) {
	now := time.Now()
	s := siteWith(t, []string{"example.com"}, []string{"example.com"}, now.Add(60*24*time.Hour))

	for i := 0; i < 5; i++ {
		if want, reason := CertificateWanted(s, now); want {
			t.Fatalf("attempt %d reported a healthy certificate as needing renewal (%s); "+
				"five of those exhaust the week's duplicate allowance and the domain "+
				"is refused until it resets", i+1, reason)
		}
	}
}

func TestManualCooldownStaysUnderTheAuthoritysHourlyLimit(t *testing.T) {
	// Let's Encrypt refuses an account that fails validation five times for one
	// hostname within an hour. The cooldown is what bounds how often the button
	// can produce one of those.
	perHour := int(time.Hour / store.ManualIssueWindow)
	if perHour > 4 {
		t.Fatalf("a cooldown of %s allows %d attempts an hour; the authority refuses "+
			"after five failures for one hostname in an hour, and the refusal outlasts "+
			"the mistake - an operator fixing DNS would lock themselves out",
			store.ManualIssueWindow, perHour)
	}
}
