// Package config doc cau hinh runtime cua control plane tu bien moi truong.
package config

import (
	"crypto/rand"
	"encoding/hex"
	"os"
	"strconv"
	"time"
)

type Config struct {
	Listen string // dia chi lang nghe cua dashboard admin, vd ":9443"

	DBDSN         string
	RedisAddr     string
	RedisPassword string
	RedisDB       int

	JWTSecret       []byte
	ChallengeSecret string
	TokenTTL        time.Duration

	AdminUser     string
	AdminPassword string // chi dung de tao tai khoan lan dau

	SitesDir   string // noi ghi file cau hinh nginx cho tung site
	CertsDir   string // noi ghi chung chi cua site
	AdminTLS   string // thu muc chung chi cua chinh dashboard
	ProxySync  string // URL endpoint /sync cua data plane
	RetainDays int    // so ngay giu attack log

	// Cong ma cac server block cua site se lang nghe. Trong container luon la
	// 80/443; doi duoc de chay thu tren may dev khi khong co quyen bind cong thap.
	SiteHTTPPort  int
	SiteHTTPSPort int
}

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func envInt(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

func randomSecret() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "moswaf-fallback-secret"
	}
	return hex.EncodeToString(b)
}

func Load() *Config {
	secret := env("MOSWAF_JWT_SECRET", "")
	if secret == "" {
		// Khong co secret => sinh tam, phien dang nhap se mat khi restart.
		secret = randomSecret()
	}

	return &Config{
		Listen:          env("MOSWAF_LISTEN", ":9443"),
		DBDSN:           env("MOSWAF_DB_DSN", "postgres://moswaf:moswaf@127.0.0.1:5432/moswaf?sslmode=disable"),
		RedisAddr:       env("MOSWAF_REDIS_ADDR", "127.0.0.1:6379"),
		RedisPassword:   env("MOSWAF_REDIS_PASSWORD", ""),
		RedisDB:         envInt("MOSWAF_REDIS_DB", 0),
		JWTSecret:       []byte(secret),
		ChallengeSecret: env("MOSWAF_CHALLENGE_SECRET", "moswaf-insecure-default"),
		TokenTTL:        time.Duration(envInt("MOSWAF_TOKEN_TTL_HOURS", 12)) * time.Hour,
		AdminUser:       env("MOSWAF_ADMIN_USER", "admin"),
		AdminPassword:   env("MOSWAF_ADMIN_PASSWORD", ""),
		SitesDir:        env("MOSWAF_SITES_DIR", "/etc/moswaf/sites"),
		CertsDir:        env("MOSWAF_CERTS_DIR", "/etc/moswaf/certs"),
		AdminTLS:        env("MOSWAF_ADMIN_TLS_DIR", "/etc/moswaf/admin-tls"),
		ProxySync:       env("MOSWAF_PROXY_SYNC_URL", "http://proxy:8081/sync"),
		RetainDays:      envInt("MOSWAF_LOG_RETAIN_DAYS", 7),
		SiteHTTPPort:    envInt("MOSWAF_SITE_HTTP_PORT", 80),
		SiteHTTPSPort:   envInt("MOSWAF_SITE_HTTPS_PORT", 443),
	}
}
