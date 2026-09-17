package store

import "time"

// Site - mot ten mien (hoac nhom ten mien) duoc MosWAF bao ve.
type Site struct {
	ID             string    `json:"id"`
	Name           string    `json:"name"`
	Domains        []string  `json:"domains"`
	UpstreamScheme string    `json:"upstream_scheme"` // http | https
	UpstreamHost   string    `json:"upstream_host"`
	UpstreamPort   int       `json:"upstream_port"`
	Mode           string    `json:"mode"`      // protect | monitor | off
	Challenge      string    `json:"challenge"` // auto | always | off
	RateRPS        int       `json:"rate_rps"`  // 0 = dung muc toan cuc
	RateBurst      int       `json:"rate_burst"`
	TLSCert        string    `json:"tls_cert,omitempty"`
	TLSKey         string    `json:"tls_key,omitempty"`
	HasTLS         bool      `json:"has_tls"`
	ForceHTTPS     bool      `json:"force_https"`
	Enabled        bool      `json:"enabled"`
	RulesOff       []string  `json:"rules_off"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}

// Rule - mot chu ky phat hien tan cong.
type Rule struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Category  string    `json:"category"` // sqli | xss | lfi | rce | bot | recon | ssrf | proto | custom
	Target    string    `json:"target"`   // uri | args | body | ua | header | cookie | any
	Pattern   string    `json:"pattern"`  // regex PCRE
	Action    string    `json:"action"`   // deny | challenge | ban | log
	Severity  string    `json:"severity"` // low | medium | high | critical
	Enabled   bool      `json:"enabled"`
	Builtin   bool      `json:"builtin"`
	CreatedAt time.Time `json:"created_at"`
}

// IPEntry - mot dong trong danh sach den hoac trang.
type IPEntry struct {
	ID        int64      `json:"id"`
	CIDR      string     `json:"cidr"`
	Kind      string     `json:"kind"` // black | white
	Reason    string     `json:"reason"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
	CreatedAt time.Time  `json:"created_at"`
}

// Event - mot request dang chu y do data plane ghi nhan.
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

// Settings - chinh sach toan cuc, luu 1 dong JSONB trong bang settings.
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
	}
}

// StatPoint - mot diem tren bieu do luu luong (gom theo phut).
type StatPoint struct {
	Minute     time.Time `json:"minute"`
	Total      int64     `json:"total"`
	Blocked    int64     `json:"blocked"`
	Challenged int64     `json:"challenged"`
	Monitored  int64     `json:"monitored"`
}

// User - tai khoan quan tri.
type User struct {
	ID        int64     `json:"id"`
	Username  string    `json:"username"`
	CreatedAt time.Time `json:"created_at"`
}
