package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

const siteCols = `id, name, domains, upstream_scheme, upstream_host, upstream_port,
	mode, challenge, rate_rps, rate_burst, tls_cert, tls_key, force_https,
	enabled, rules_off, created_at, updated_at,
	acme_enabled, acme_email, cert_expires_at, acme_last_error, acme_last_try`

func scanSite(row pgx.Row) (*Site, error) {
	var s Site
	var domains, rulesOff []byte
	err := row.Scan(&s.ID, &s.Name, &domains, &s.UpstreamScheme, &s.UpstreamHost, &s.UpstreamPort,
		&s.Mode, &s.Challenge, &s.RateRPS, &s.RateBurst, &s.TLSCert, &s.TLSKey, &s.ForceHTTPS,
		&s.Enabled, &rulesOff, &s.CreatedAt, &s.UpdatedAt,
		&s.AcmeEnabled, &s.AcmeEmail, &s.CertExpiresAt, &s.AcmeLastError, &s.AcmeLastTry)
	if err != nil {
		return nil, err
	}
	_ = json.Unmarshal(domains, &s.Domains)
	_ = json.Unmarshal(rulesOff, &s.RulesOff)
	if s.Domains == nil {
		s.Domains = []string{}
	}
	if s.RulesOff == nil {
		s.RulesOff = []string{}
	}
	s.HasTLS = s.TLSCert != "" && s.TLSKey != ""
	return &s, nil
}

func (s *Store) ListSites(ctx context.Context) ([]*Site, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+siteCols+` FROM sites ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []*Site{}
	for rows.Next() {
		site, err := scanSite(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, site)
	}
	return out, rows.Err()
}

func (s *Store) GetSite(ctx context.Context, id string) (*Site, error) {
	site, err := scanSite(s.pool.QueryRow(ctx, `SELECT `+siteCols+` FROM sites WHERE id = $1`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	return site, err
}

// hasControlChar reports whether v contains a newline, carriage return or any
// other control character.
//
// Everything validated here ends up inside a generated nginx file. A newline in
// Site.Name breaks out of the comment line renderSite writes it into, which lets
// an admin inject arbitrary nginx directives - and the proxy workers run as root,
// so that reaches code execution through content_by_lua_block. In Domains and
// UpstreamHost a directive cannot be terminated, but a newline still produces a
// file nginx refuses to parse, after which the data plane stops reloading and
// every later configuration change silently has no effect.
func hasControlChar(v string) bool {
	return strings.ContainsFunc(v, func(r rune) bool {
		return r == '\n' || r == '\r' || r == 0 || (r < 0x20 && r != '\t') || r == 0x7f
	})
}

// ValidateSite normalises and checks a site before it is written.
func ValidateSite(s *Site) error {
	s.Name = strings.TrimSpace(s.Name)
	s.UpstreamHost = strings.TrimSpace(s.UpstreamHost)

	if s.Name == "" {
		return fmt.Errorf("the site name is required")
	}
	if hasControlChar(s.Name) {
		return fmt.Errorf("the site name cannot contain line breaks or control characters")
	}
	if len(s.Domains) == 0 {
		return fmt.Errorf("at least one domain is required")
	}
	for i, d := range s.Domains {
		d = strings.ToLower(strings.TrimSpace(d))
		if d == "" || strings.ContainsAny(d, " /\\:;{}\"'$") || hasControlChar(d) {
			return fmt.Errorf("invalid domain: %q", s.Domains[i])
		}
		s.Domains[i] = d
	}
	if s.UpstreamHost == "" {
		return fmt.Errorf("the upstream host is required")
	}
	if strings.ContainsAny(s.UpstreamHost, " /\\;{}\"'$") || hasControlChar(s.UpstreamHost) {
		return fmt.Errorf("invalid upstream host")
	}
	if s.UpstreamPort <= 0 || s.UpstreamPort > 65535 {
		return fmt.Errorf("invalid upstream port")
	}
	if s.UpstreamScheme != "http" && s.UpstreamScheme != "https" {
		s.UpstreamScheme = "http"
	}
	switch s.Mode {
	case "protect", "monitor", "off":
	default:
		s.Mode = "protect"
	}
	switch s.Challenge {
	case "auto", "always", "off":
	default:
		s.Challenge = "auto"
	}
	if s.RateRPS < 0 || s.RateBurst < 0 {
		return fmt.Errorf("rate limits cannot be negative")
	}
	if (s.TLSCert == "") != (s.TLSKey == "") {
		return fmt.Errorf("both the certificate and the private key are required")
	}
	// With ACME on, the certificate arrives on its own, so forcing HTTPS before the
	// first one is issued is allowed - it just takes effect when the cert lands.
	if s.ForceHTTPS && s.TLSCert == "" && !s.AcmeEnabled {
		return fmt.Errorf("forcing HTTPS requires a certificate")
	}
	if s.AcmeEnabled {
		s.AcmeEmail = strings.TrimSpace(s.AcmeEmail)
		if s.AcmeEmail == "" {
			return fmt.Errorf("an email address is required for automatic certificates")
		}
		if !strings.Contains(s.AcmeEmail, "@") || hasControlChar(s.AcmeEmail) {
			return fmt.Errorf("invalid email address: %q", s.AcmeEmail)
		}
		for _, d := range s.Domains {
			// A certificate authority will not validate an address or a private name
			if net.ParseIP(d) != nil || !strings.Contains(d, ".") {
				return fmt.Errorf("automatic certificates need a real domain name, not %q", d)
			}
		}
	}
	if s.RulesOff == nil {
		s.RulesOff = []string{}
	}
	return nil
}

func (s *Store) UpsertSite(ctx context.Context, site *Site) error {
	domains, _ := json.Marshal(site.Domains)
	rulesOff, _ := json.Marshal(site.RulesOff)
	site.UpdatedAt = time.Now()

	_, err := s.pool.Exec(ctx, `
		INSERT INTO sites (id, name, domains, upstream_scheme, upstream_host, upstream_port,
		                   mode, challenge, rate_rps, rate_burst, tls_cert, tls_key,
		                   force_https, enabled, rules_off, acme_enabled, acme_email,
		                   cert_expires_at, updated_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18, now())
		ON CONFLICT (id) DO UPDATE SET
			name = EXCLUDED.name,
			domains = EXCLUDED.domains,
			upstream_scheme = EXCLUDED.upstream_scheme,
			upstream_host = EXCLUDED.upstream_host,
			upstream_port = EXCLUDED.upstream_port,
			mode = EXCLUDED.mode,
			challenge = EXCLUDED.challenge,
			rate_rps = EXCLUDED.rate_rps,
			rate_burst = EXCLUDED.rate_burst,
			tls_cert = EXCLUDED.tls_cert,
			tls_key = EXCLUDED.tls_key,
			force_https = EXCLUDED.force_https,
			enabled = EXCLUDED.enabled,
			rules_off = EXCLUDED.rules_off,
			acme_enabled = EXCLUDED.acme_enabled,
			acme_email = EXCLUDED.acme_email,
			cert_expires_at = EXCLUDED.cert_expires_at,
			updated_at = now()`,
		site.ID, site.Name, domains, site.UpstreamScheme, site.UpstreamHost, site.UpstreamPort,
		site.Mode, site.Challenge, site.RateRPS, site.RateBurst, site.TLSCert, site.TLSKey,
		site.ForceHTTPS, site.Enabled, rulesOff, site.AcmeEnabled, site.AcmeEmail,
		site.CertExpiresAt)
	return err
}

func (s *Store) DeleteSite(ctx context.Context, id string) error {
	tag, err := s.pool.Exec(ctx, `DELETE FROM sites WHERE id = $1`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// StoreCertificate saves an issued certificate and clears the last failure.
func (s *Store) StoreCertificate(ctx context.Context, id, certPEM, keyPEM string, expires time.Time) error {
	tag, err := s.pool.Exec(ctx, `
		UPDATE sites SET tls_cert = $2, tls_key = $3, cert_expires_at = $4,
		                 acme_last_error = '', acme_last_try = now(), updated_at = now()
		WHERE id = $1`, id, certPEM, keyPEM, expires)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// RecordACMEAttempt remembers why an order failed, which both surfaces the reason
// on the dashboard and drives the back-off before the next attempt.
func (s *Store) RecordACMEAttempt(ctx context.Context, id, failure string) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE sites SET acme_last_error = $2, acme_last_try = now() WHERE id = $1`,
		id, failure)
	return err
}
