package store

import "time"

// Site is one domain, or a group of domains, protected by MosWAF.
type Site struct {
	ID             string    `json:"id"`
	Name           string    `json:"name"`
	Domains        []string  `json:"domains"`
	UpstreamScheme string    `json:"upstream_scheme"` // http | https
	UpstreamHost   string    `json:"upstream_host"`
	UpstreamPort   int       `json:"upstream_port"`
	Mode           string    `json:"mode"`      // protect | monitor | off
	Challenge      string    `json:"challenge"` // auto | always | off
	RateRPS        int       `json:"rate_rps"`  // 0 means use the global value
	RateBurst      int       `json:"rate_burst"`
	FloodRPS       int       `json:"flood_rps"` // site-wide flood threshold, 0 means use the global value
	TLSCert        string    `json:"tls_cert,omitempty"`
	TLSKey         string    `json:"tls_key,omitempty"`
	HasTLS         bool      `json:"has_tls"`
	ForceHTTPS     bool      `json:"force_https"`

	// Automatic certificates. When AcmeEnabled is set the control plane obtains a
	// certificate over ACME HTTP-01 and renews it before CertExpiresAt, filling in
	// the same TLSCert/TLSKey fields a manually pasted certificate uses.
	AcmeEnabled   bool       `json:"acme_enabled"`
	AcmeEmail     string     `json:"acme_email"`
	CertExpiresAt *time.Time `json:"cert_expires_at,omitempty"`
	AcmeLastError string     `json:"acme_last_error,omitempty"`
	AcmeLastTry   *time.Time `json:"acme_last_try,omitempty"`
	Enabled        bool      `json:"enabled"`
	RulesOff       []string  `json:"rules_off"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
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
}

// Settings is the global policy, stored as a single JSONB row in the settings table.
type Settings struct {
	UnderAttack         bool     `json:"under_attack"`
	DefaultMode         string   `json:"default_mode"`
	RealIPHeader        string   `json:"real_ip_header"`
	TrustedProxies      []string `json:"trusted_proxies"`
	GlobalRateRPS       int      `json:"global_rate_rps"`
	GlobalRateBurst     int      `json:"global_rate_burst"`
	BanSeconds          int      `json:"ban_seconds"`
	ChallengeDifficulty int      `json:"challenge_difficulty"`
	ChallengeTTL        int      `json:"challenge_ttl"`
	BlockStatus         int      `json:"block_status"`
	MaxBodyScan         int      `json:"max_body_scan"`
	ScanBody            bool     `json:"scan_body"`
	LogAllowed          bool     `json:"log_allowed"`
	LogRetainDays       int      `json:"log_retain_days"`

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
}

func DefaultSettings() Settings {
	return Settings{
		UnderAttack:         false,
		DefaultMode:         "protect",
		RealIPHeader:        "",
		TrustedProxies:      []string{},
		GlobalRateRPS:       60,
		GlobalRateBurst:     120,
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
	}
}

// StatPoint is one point on the traffic chart, bucketed per minute.
type StatPoint struct {
	Minute     time.Time `json:"minute"`
	Total      int64     `json:"total"`
	Blocked    int64     `json:"blocked"`
	Challenged int64     `json:"challenged"`
	Monitored  int64     `json:"monitored"`
}

// User is an administrator account.
type User struct {
	ID        int64     `json:"id"`
	Username  string    `json:"username"`
	CreatedAt time.Time `json:"created_at"`
}
