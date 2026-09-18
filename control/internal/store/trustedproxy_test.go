package store

import (
	"strings"
	"testing"
)

// A trusted list covering every address is the same as no list at all, but it
// reads like a configured one.
//
// The forwarded-for header is believed only when the peer is one of our proxies.
// Trust everybody and every peer qualifies - so the client's own header becomes
// its address, and it picks what the bans, the blocklist, the rate-limit counters
// and the allow rules are keyed on. An allow rule naming an address then stops
// being "who the request is from" and becomes "what the request says", which is
// the one thing that must never decide whether the firewall runs.
//
// It is a plausible thing to type: somebody behind a CDN who does not know its
// address ranges writes it to make the header work. It does work - for the
// attacker too.
func TestATrustedProxyListCannotCoverEveryAddress(t *testing.T) {
	for _, wide := range []string{"0.0.0.0/0", "::/0"} {
		st := DefaultSettings()
		st.RealIPHeader = "X-Forwarded-For"
		st.TrustedProxies = []string{wide}

		err := ValidateSettings(&st)
		if err == nil {
			t.Errorf("trusted_proxies = %q was accepted; any client could then set "+
				"its own address, and an allow rule keyed on an address would be "+
				"keyed on a value the attacker chooses", wide)
			continue
		}
		if !strings.Contains(err.Error(), "every address") {
			t.Errorf("%q was refused but the message does not explain why: %v", wide, err)
		}
	}

	// A wide entry hidden among real ones is the same hole.
	st := DefaultSettings()
	st.RealIPHeader = "X-Forwarded-For"
	st.TrustedProxies = []string{"198.51.100.0/24", "0.0.0.0/0"}
	if err := ValidateSettings(&st); err == nil {
		t.Error("an all-covering entry alongside real ranges was accepted")
	}
}

func TestRealProxyRangesAreStillAccepted(t *testing.T) {
	st := DefaultSettings()
	st.RealIPHeader = "X-Forwarded-For"
	st.TrustedProxies = []string{"198.51.100.0/24", "2001:db8::/32", "10.0.0.5"}
	if err := ValidateSettings(&st); err != nil {
		t.Fatalf("ordinary proxy ranges were refused: %v", err)
	}
	// Stored canonically. A bare address stays bare - the data plane reads both
	// forms - and what matters here is that the host bits are masked off, so what
	// is stored is what is compared against.
	if strings.Join(st.TrustedProxies, " ") != "198.51.100.0/24 2001:db8::/32 10.0.0.5" {
		t.Errorf("stored %v", st.TrustedProxies)
	}
}

// And the existing rule still holds: a header with no list behind it is a client
// naming itself, which is the same hole reached a different way.
func TestAHeaderWithNoTrustedListIsRefused(t *testing.T) {
	st := DefaultSettings()
	st.RealIPHeader = "X-Forwarded-For"
	st.TrustedProxies = []string{}
	if err := ValidateSettings(&st); err == nil {
		t.Error("a real-IP header with no trusted proxies was accepted")
	}
}

// The line is public versus private, not width.
//
// A /8 is enormous and 10.0.0.0/8 is an ordinary internal network behind an
// ordinary internal load balancer. Refusing it - or even nagging about it - would
// be objecting to a real deployment to prevent nothing, because an attacker
// cannot be inside a private range from outside. A public /8 is the opposite:
// nobody operates a sixteenth of the internet as their load balancer, and
// whoever is in it can set their own address.
func TestOnlyWidePUBLICProxyRangesAreWorthMentioning(t *testing.T) {
	worthSaying := []string{"1.0.0.0/8", "203.0.0.0/8", "2001:db8::/32"}
	for _, c := range worthSaying {
		if !WidePublicProxyRange(c) {
			t.Errorf("%q is a large public range and was not flagged; anybody inside "+
				"it can set their own address", c)
		}
	}

	quiet := []string{
		"10.0.0.0/8",      // RFC1918, and a perfectly normal internal LB
		"172.16.0.0/12",   //
		"192.168.0.0/16",  //
		"127.0.0.0/8",     // loopback
		"fd00::/8",        // unique local
		"fe80::/10",       // link local
		"198.51.100.0/24", // a real, narrow, public proxy range
		"2001:db8::/48",   // a real, narrow, public IPv6 range
		"0.0.0.0/0",       // refused outright elsewhere, not merely mentioned
		"not a prefix",
	}
	for _, c := range quiet {
		if WidePublicProxyRange(c) {
			t.Errorf("%q was flagged; objecting to it would be objecting to a real "+
				"deployment to prevent nothing", c)
		}
	}
}
