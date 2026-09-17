// Package config reads the control plane runtime configuration from the environment.
package config

import (
	"crypto/rand"
	"encoding/hex"
	"os"
	"strconv"
	"time"
)

type Config struct {
	Listen string // admin dashboard listen address, e.g. ":9443"

	DBDSN         string
	RedisAddr     string
	RedisPassword string
	RedisDB       int

	JWTSecret       []byte
	ChallengeSecret string
	TokenTTL        time.Duration

	AdminUser     string
	AdminPassword string // only used to create the very first account

	SitesDir   string // where per-site nginx config files are written
	CertsDir   string // where site certificates are written
	AdminTLS   string // certificate directory for the dashboard itself
	ProxySync  string // data plane /sync endpoint URL
	RetainDays int    // how many days to keep the attack log

	// Ports the generated site server blocks listen on. Always 80/443 inside the
	// container; configurable so it can run on a dev machine without the privilege
	// to bind low ports.
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
		// No secret provided, so generate a throwaway one; sessions will not survive a restart.
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
