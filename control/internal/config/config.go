// Package config reads the control plane runtime configuration from the environment.
package config

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
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

	// Shared with the data plane so its internal API can tell us apart from
	// anything else that happens to sit on the same Docker network.
	InternalToken string
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

// Values that must never reach production. "changeme" ships in .env.example, and
// "moswaf-insecure-default" used to be the built-in fallback on both sides of the
// challenge cookie - a key published in this repository.
var placeholderSecrets = map[string]bool{
	"changeme":                    true,
	"moswaf-insecure-default":     true,
	"moswaf-fallback-secret":      true,
	"moswaf-dev-jwt-secret":       false, // used by scripts/dev-local.sh on purpose
	"moswaf-dev-challenge-secret": false,
}

// Validate refuses to run with a secret an attacker can read off the internet.
//
// MOSWAF_JWT_SECRET at a known value means anyone can mint a valid dashboard
// token; MOSWAF_CHALLENGE_SECRET at a known value means anyone can forge the
// __moswaf cookie, which switches off the JS challenge and under-attack mode -
// the anti-DDoS feature itself. `make up` copies .env.example verbatim, so this
// is a real path, not a hypothetical one.
func (c *Config) Validate() error {
	for name, value := range map[string]string{
		"MOSWAF_JWT_SECRET":       string(c.JWTSecret),
		"MOSWAF_CHALLENGE_SECRET": c.ChallengeSecret,
	} {
		if value == "" {
			return fmt.Errorf("%s is not set; generate one with: openssl rand -hex 32", name)
		}
		if placeholder, known := placeholderSecrets[value]; known && placeholder {
			return fmt.Errorf("%s is still the placeholder %q; generate a real one with: openssl rand -hex 32",
				name, value)
		}
		if len(value) < 16 {
			return fmt.Errorf("%s is too short (%d characters, need at least 16)", name, len(value))
		}
	}
	return nil
}

func internalToken() string {
	if v := os.Getenv("MOSWAF_INTERNAL_TOKEN"); v != "" {
		return v
	}
	return randomSecret()
}

func Load() *Config {
	secret := env("MOSWAF_JWT_SECRET", "")
	if secret == "" {
		// No secret provided, so generate a throwaway one; sessions will not survive a
		// restart. Validate() rejects this before the server starts serving.
		secret = randomSecret()
	}

	return &Config{
		Listen:          env("MOSWAF_LISTEN", ":9443"),
		DBDSN:           env("MOSWAF_DB_DSN", "postgres://moswaf:moswaf@127.0.0.1:5432/moswaf?sslmode=disable"),
		RedisAddr:       env("MOSWAF_REDIS_ADDR", "127.0.0.1:6379"),
		RedisPassword:   env("MOSWAF_REDIS_PASSWORD", ""),
		RedisDB:         envInt("MOSWAF_REDIS_DB", 0),
		JWTSecret:       []byte(secret),
		ChallengeSecret: env("MOSWAF_CHALLENGE_SECRET", ""),
		TokenTTL:        time.Duration(envInt("MOSWAF_TOKEN_TTL_HOURS", 12)) * time.Hour,
		AdminUser:       env("MOSWAF_ADMIN_USER", "admin"),
		AdminPassword:   env("MOSWAF_ADMIN_PASSWORD", ""),
		SitesDir:        env("MOSWAF_SITES_DIR", "/etc/moswaf/sites"),
		CertsDir:        env("MOSWAF_CERTS_DIR", "/etc/moswaf/certs"),
		AdminTLS:        env("MOSWAF_ADMIN_TLS_DIR", "/etc/moswaf/admin-tls"),
		ProxySync:       env("MOSWAF_PROXY_SYNC_URL", "http://proxy:8081/sync"),
		// Generated when unset so an install that never edits .env still gets a real
		// token: it is published with the configuration, and the data plane picks it
		// up on its next sync. Only the two planes ever see it.
		InternalToken: internalToken(),
		RetainDays:      envInt("MOSWAF_LOG_RETAIN_DAYS", 7),
		SiteHTTPPort:    envInt("MOSWAF_SITE_HTTP_PORT", 80),
		SiteHTTPSPort:   envInt("MOSWAF_SITE_HTTPS_PORT", 443),
	}
}
