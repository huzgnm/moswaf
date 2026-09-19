package store

import (
	"sort"
	"strings"
	"time"
)

// Site is one domain, or a group of domains, protected by MosWAF.
type Site struct {
	ID             string   `json:"id"`
	Name           string   `json:"name"`
	Domains        []string `json:"domains"`
	UpstreamScheme string   `json:"upstream_scheme"` // http | https
	UpstreamHost   string   `json:"upstream_host"`
	UpstreamPort   int      `json:"upstream_port"`
	Mode           string   `json:"mode"`      // protect | monitor | off
	Challenge      string   `json:"challenge"` // auto | always | off
	RateRPS        int      `json:"rate_rps"`  // 0 means use the global value
	RateBurst      int      `json:"rate_burst"`
	FloodRPS       int      `json:"flood_rps"` // site-wide flood threshold, 0 means use the global value

	// A login gate in front of the site. Nobody reaches the upstream without a
	// session; AuthPaths limits which prefixes are behind it.
	AuthEnabled bool     `json:"auth_enabled"`
	AuthPaths   []string `json:"auth_paths"`

	// This site's own country rule. An empty GeoMode means "use the global one",
	// which is different from "off": "off" is a site deliberately opting out of a
	// rule everything else follows, and an operator who set it should not have it
	// silently undone the next time the global rule changes.
	GeoMode      string   `json:"geo_mode"`
	GeoCountries []string `json:"geo_countries"`
	TLSCert      string   `json:"tls_cert,omitempty"`
	TLSKey       string   `json:"tls_key,omitempty"`
	HasTLS       bool     `json:"has_tls"`
	ForceHTTPS   bool     `json:"force_https"`

	// Automatic certificates. When AcmeEnabled is set the control plane obtains a
	// certificate over ACME HTTP-01 and renews it before CertExpiresAt, filling in
	// the same TLSCert/TLSKey fields a manually pasted certificate uses.
	AcmeEnabled   bool       `json:"acme_enabled"`
	AcmeEmail     string     `json:"acme_email"`
	CertExpiresAt *time.Time `json:"cert_expires_at,omitempty"`
	AcmeLastError string     `json:"acme_last_error,omitempty"`
	AcmeLastTry   *time.Time `json:"acme_last_try,omitempty"`
	Enabled       bool       `json:"enabled"`
	RulesOff      []string   `json:"rules_off"`
	CreatedAt     time.Time  `json:"created_at"`
	UpdatedAt     time.Time  `json:"updated_at"`
}

// Rule is a single attack detection signature.
type Rule struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Category  string    `json:"category"` // sqli | xss | lfi | rce | bot | recon | ssrf | proto | custom
	Target    string    `json:"target"`   // uri | args | body | ua | header | cookie | any
	Pattern   string    `json:"pattern"`  // PCRE regular expression
	Action    string    `json:"action"`   // deny | challenge | ban | log
	Severity  string    `json:"severity"` // low | medium | high | critical
	Enabled   bool      `json:"enabled"`
	Builtin   bool      `json:"builtin"`
	CreatedAt time.Time `json:"created_at"`
}

// IPEntry is one row in the blocklist or the allowlist.
type IPEntry struct {
	ID        int64      `json:"id"`
	CIDR      string     `json:"cidr"`
	Kind      string     `json:"kind"` // black | white
	Reason    string     `json:"reason"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
	CreatedAt time.Time  `json:"created_at"`
}

// Event is a noteworthy request recorded by the data plane.
type Event struct {
	ID       int64     `json:"id"`
	TS       time.Time `json:"ts"`
	Ray      string    `json:"ray"`
	Site     string    `json:"site"`
	IP       string    `json:"ip"`
	Method   string    `json:"method"`
	Host     string    `json:"host"`
	URI      string    `json:"uri"`
	UA       string    `json:"ua"`
	Referer  string    `json:"referer"`
	Action   string    `json:"action"` // deny | challenge | monitor | log
	Reason   string    `json:"reason"`
	RuleID   string    `json:"rule_id"`
	RuleName string    `json:"rule_name"`
	Severity string    `json:"severity"`
	Status   int       `json:"status"`
	RT       float64   `json:"rt"`
	Country  string    `json:"country,omitempty"`
}

// Settings is the global policy, stored as a single JSONB row in the settings table.
type Settings struct {
	UnderAttack    bool     `json:"under_attack"`
	DefaultMode    string   `json:"default_mode"`
	RealIPHeader   string   `json:"real_ip_header"`
	TrustedProxies []string `json:"trusted_proxies"`
	// The per-address request budget, as a sustained rate plus a burst - the
	// same two numbers nginx's limit_req takes, and they mean different things.
	//
	// GlobalRateRPS is what one address may sustain indefinitely.
	// GlobalRateBurst is how many requests it may fire back to back before that
	// pace is enforced, and it has to exceed the number of requests in one page
	// render: opening a page with sixty assets is sixty requests from one click.
	// Sized below that, this stops catching attackers and starts catching
	// visitors - which is exactly how it was wrong before.
	GlobalRateRPS       int  `json:"global_rate_rps"`
	GlobalRateBurst     int  `json:"global_rate_burst"`
	BanSeconds          int  `json:"ban_seconds"`
	ChallengeDifficulty int  `json:"challenge_difficulty"`
	ChallengeTTL        int  `json:"challenge_ttl"`
	BlockStatus         int  `json:"block_status"`
	MaxBodyScan         int  `json:"max_body_scan"`
	ScanBody            bool `json:"scan_body"`
	LogAllowed          bool `json:"log_allowed"`
	LogRetainDays       int  `json:"log_retain_days"`

	// Automatic flood defence.
	//
	// Every other limit here is per IP, and a distributed flood is built to stay
	// under one: ten thousand addresses at 2 r/s each is 20,000 r/s at the origin
	// and nothing a per-IP threshold can object to. These thresholds are measured
	// across the whole site, and crossing one turns the JS challenge on for
	// everyone until the flood stops.
	FloodRPS       int `json:"flood_rps"`        // site-wide requests/second, 0 = off
	FloodErrorRate int `json:"flood_error_rate"` // origin 5xx percentage, 0 = off
	FloodHold      int `json:"flood_hold"`       // seconds to stay engaged after the last trigger

	// Blocking by country.
	//
	// "off", "block" (refuse the listed countries) or "allow" (refuse everything
	// except the listed countries). A site can override both, so the usual setup -
	// one rule everywhere, one site different - does not need the rule written out
	// per site.
	GeoMode      string   `json:"geo_mode"`
	GeoCountries []string `json:"geo_countries"`
}

// GeoPolicy is the country rule in effect for one request: a site's own if it
// sets one, otherwise the global one.
type GeoPolicy struct {
	Mode      string   `json:"mode"`
	Countries []string `json:"countries"`
}

// NormaliseGeo puts a country rule into one shape and refuses the states that
// would take a site off the air.
//
// The dangerous one is "allow" with nothing listed, which reads as "allow" and
// means "refuse everybody". It is reachable by removing the last country from the
// list rather than by asking for it, which is exactly why it is caught here
// instead of being left to whoever is watching the traffic graph.
func NormaliseGeo(mode string, countries []string) (string, []string) {
	seen := map[string]bool{}
	out := make([]string, 0, len(countries))
	for _, c := range countries {
		c = strings.ToUpper(strings.TrimSpace(c))
		if len(c) != 2 {
			continue
		}
		if c[0] < 'A' || c[0] > 'Z' || c[1] < 'A' || c[1] > 'Z' {
			continue
		}
		if seen[c] {
			continue
		}
		seen[c] = true
		out = append(out, c)
		if len(out) >= 250 { // there are fewer countries than this
			break
		}
	}
	sort.Strings(out)

	switch mode {
	case "block", "allow":
	default:
		return "off", out
	}
	// A rule naming no countries does nothing in one direction and everything in
	// the other. Neither is what an empty list was meant to say, so it means off.
	if len(out) == 0 {
		return "off", out
	}
	return mode, out
}

func DefaultSettings() Settings {
	return Settings{
		UnderAttack:    false,
		DefaultMode:    "protect",
		RealIPHeader:   "",
		TrustedProxies: []string{},
		// Twenty a second sustained, three hundred back to back.
		//
		// Both are chosen against what a person can do, not against what an
		// attack looks like - a distributed flood is flood.lua's job and no
		// per-address number reaches it. The busiest real browsing is roughly
		// ten page views a minute; at sixty requests each that is ten a second
		// on average, so twenty leaves room for somebody impatient. Three
		// hundred covers about five page loads with no pause between them,
		// which is what clicking quickly through a site looks like.
		//
		// These replace 60/s and 120-per-10s, which sound larger and were far
		// tighter: the old ten-second ceiling worked out at twelve a second
		// sustained, and one page load spent half of it.
		GlobalRateRPS:       20,
		GlobalRateBurst:     300,
		BanSeconds:          600,
		ChallengeDifficulty: 16,
		ChallengeTTL:        1800,
		BlockStatus:         403,
		MaxBodyScan:         65536,
		ScanBody:            true,
		LogAllowed:          false,
		LogRetainDays:       7,

		// 1000 r/s to one site is far above anything an ordinary site sees and far
		// below what a flood delivers, so it engages on an attack and not on a busy
		// afternoon. 50% of origin answers failing is the other way in: a slow
		// endpoint can be taken down with a fraction of that request rate, and the
		// origin failing is the symptom that shows up first.
		FloodRPS:       1000,
		FloodErrorRate: 50,
		FloodHold:      120,

		// Off by default and deliberately so. Every other default here is a limit a
		// legitimate visitor never reaches; this one turns whole countries away,
		// which is a business decision rather than a security default, and nobody
		// should find MosWAF made it on their behalf.
		GeoMode:      "off",
		GeoCountries: []string{},
	}
}

// StatPoint is one point on the traffic chart, bucketed per minute.
type StatPoint struct {
	Minute     time.Time `json:"minute"`
	Total      int64     `json:"total"`
	Blocked    int64     `json:"blocked"`
	Challenged int64     `json:"challenged"`
	Monitored  int64     `json:"monitored"`

	// What the visitor was served. Kept apart from Blocked because the question
	// an operator is answering when an error rate jumps is which side produced
	// it: Errors4xx counts every 4xx, Blocked4xx only the ones MosWAF produced.
	Errors4xx  int64 `json:"errors_4xx"`
	Blocked4xx int64 `json:"blocked_4xx"`
	Errors5xx  int64 `json:"errors_5xx"`
	PageViews  int64 `json:"page_views"`
}

// SiteUser may pass the login gate on one site. Not an administrator: these
// accounts reach a protected site, never MosWAF itself.
type SiteUser struct {
	ID         int64     `json:"id"`
	SiteID     string    `json:"site_id"`
	Username   string    `json:"username"`
	Generation int64     `json:"generation"`
	CreatedAt  time.Time `json:"created_at"`
}

// User is an administrator account.
type User struct {
	ID        int64     `json:"id"`
	Username  string    `json:"username"`
	CreatedAt time.Time `json:"created_at"`
}
