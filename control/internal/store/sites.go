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
	mode, challenge, rate_rps, rate_burst, flood_rps, tls_cert, tls_key, force_https,
	enabled, rules_off, created_at, updated_at,
	acme_enabled, acme_email, cert_expires_at, acme_last_error, acme_last_try,
	auth_enabled, auth_paths, geo_mode, geo_countries`

// NormaliseSiteGeo is NormaliseGeo with the one difference a site has: there is a
// rule above it to fall back to.
//
// NormaliseGeo answers "off" for two different things - a rule that says off, and
// a rule that cannot be used. Globally those are the same answer. On a site they
// are not, and treating them alike loses protection: if the global rule blocks a
// country and an operator picks "allow" here without filling the list in yet,
// answering "off" stops this site inheriting that block. A half-finished rule
// would leave the site less protected than before anybody touched it, and the
// dashboard would show "off" as though somebody had asked for it.
//
// So an unusable rule becomes "" - follow the global rule - which is what "I have
// not finished choosing" should mean. A deliberate "off" is left alone, because
// that is an operator opting this site out and it must survive the next change to
// the global rule.
//
// One function rather than the same three lines in the read path and the write
// path: two copies that have to agree are one edit away from not agreeing, which
// is how a site would validate as one thing and load as another.
func NormaliseSiteGeo(mode string, countries []string) (string, []string) {
	if mode == "" {
		if countries == nil {
			countries = []string{}
		}
		return "", countries
	}
	out, list := NormaliseGeo(mode, countries)
	if out == "off" && mode != "off" {
		out = ""
	}
	if list == nil {
		list = []string{}
	}
	return out, list
}

func scanSite(row pgx.Row) (*Site, error) {
	var s Site
	var domains, rulesOff, authPaths, geoCountries []byte
	err := row.Scan(&s.ID, &s.Name, &domains, &s.UpstreamScheme, &s.UpstreamHost, &s.UpstreamPort,
		&s.Mode, &s.Challenge, &s.RateRPS, &s.RateBurst, &s.FloodRPS, &s.TLSCert, &s.TLSKey, &s.ForceHTTPS,
		&s.Enabled, &rulesOff, &s.CreatedAt, &s.UpdatedAt,
		&s.AcmeEnabled, &s.AcmeEmail, &s.CertExpiresAt, &s.AcmeLastError, &s.AcmeLastTry,
		&s.AuthEnabled, &authPaths, &s.GeoMode, &geoCountries)
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
	_ = json.Unmarshal(authPaths, &s.AuthPaths)
	s.AuthPaths = NormaliseAuthPaths(s.AuthPaths)
	_ = json.Unmarshal(geoCountries, &s.GeoCountries)
	s.GeoMode, s.GeoCountries = NormaliseSiteGeo(s.GeoMode, s.GeoCountries)
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
			if err := checkACMEDomain(d); err != nil {
				return err
			}
		}
	}
	if s.RulesOff == nil {
		s.RulesOff = []string{}
	}

	s.AuthPaths = NormaliseAuthPaths(s.AuthPaths)

	s.GeoMode, s.GeoCountries = NormaliseSiteGeo(s.GeoMode, s.GeoCountries)

	// A login gate over plain HTTP hands the password and then the session cookie
	// to everybody between the visitor and the server. The gate would appear to
	// work, which is the worst version of not working: an operator would put their
	// admin panel behind it believing it was now private.
	//
	// ACME counts, because the certificate arrives on its own within the minute and
	// the alternative is telling somebody to set the gate up twice.
	if s.AuthEnabled && s.TLSCert == "" && !s.AcmeEnabled {
		return fmt.Errorf("the login gate needs HTTPS: add a certificate or switch on " +
			"automatic certificates first")
	}
	return nil
}

// Domains that can only ever produce a failed order. Every failure counts against
// the authority's per-domain rate limit, and the sweep would retry each one hourly
// forever, so they are refused when the site is saved rather than at 3am.
func checkACMEDomain(d string) error {
	// "*.example.com" parses as a perfectly good name, but HTTP-01 cannot prove
	// ownership of a wildcard - that needs DNS-01, which MosWAF does not do.
	if strings.Contains(d, "*") {
		return fmt.Errorf("a wildcard like %q needs a DNS challenge, which MosWAF does not support", d)
	}
	// "1.2.3.4." is not parsed as an address by net.ParseIP, but it is still one
	trimmed := strings.TrimSuffix(d, ".")
	if net.ParseIP(trimmed) != nil {
		return fmt.Errorf("automatic certificates need a domain name, not the address %q", d)
	}
	if !strings.Contains(trimmed, ".") {
		return fmt.Errorf("automatic certificates need a public domain name, not %q", d)
	}
	if len(trimmed) > 253 {
		return fmt.Errorf("domain name is too long: %q", d)
	}
	for _, label := range strings.Split(trimmed, ".") {
		if label == "" {
			return fmt.Errorf("domain name has an empty label: %q", d)
		}
		if len(label) > 63 {
			return fmt.Errorf("domain label is too long in %q", d)
		}
		if strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return fmt.Errorf("domain label cannot start or end with a hyphen: %q", d)
		}
	}
	return nil
}

// ManualIssueWindow is how long the dashboard button waits after an attempt.
//
// Sized against the authority's own limits rather than against impatience.
// Let's Encrypt refuses an account that fails validation five times for one
// hostname in an hour, and the refusal outlasts the mistake: an operator who
// retries every five minutes while fixing a DNS record burns that allowance in
// twenty-five minutes, and is then locked out for the rest of the hour even
// after the record is correct. Fifteen minutes keeps the worst case at four
// attempts an hour, just under the line.
const ManualIssueWindow = 15 * time.Minute

// ManualIssueCooldown returns how long is left before another manual order may be
// placed, or zero when one may be placed now.
func ManualIssueCooldown(s *Site, now time.Time) time.Duration {
	if s.AcmeLastTry == nil {
		return 0
	}
	if elapsed := now.Sub(*s.AcmeLastTry); elapsed < ManualIssueWindow {
		return ManualIssueWindow - elapsed
	}
	return 0
}

func (s *Store) UpsertSite(ctx context.Context, site *Site) error {
	domains, _ := json.Marshal(site.Domains)
	rulesOff, _ := json.Marshal(site.RulesOff)
	authPaths, _ := json.Marshal(NormaliseAuthPaths(site.AuthPaths))
	geoCountries, _ := json.Marshal(site.GeoCountries)
	site.UpdatedAt = time.Now()

	_, err := s.pool.Exec(ctx, `
		INSERT INTO sites (id, name, domains, upstream_scheme, upstream_host, upstream_port,
		                   mode, challenge, rate_rps, rate_burst, flood_rps, tls_cert, tls_key,
		                   force_https, enabled, rules_off, acme_enabled, acme_email,
		                   cert_expires_at, auth_enabled, auth_paths,
		                   geo_mode, geo_countries, updated_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23, now())
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
			flood_rps = EXCLUDED.flood_rps,
			tls_cert = EXCLUDED.tls_cert,
			tls_key = EXCLUDED.tls_key,
			force_https = EXCLUDED.force_https,
			enabled = EXCLUDED.enabled,
			rules_off = EXCLUDED.rules_off,
			acme_enabled = EXCLUDED.acme_enabled,
			acme_email = EXCLUDED.acme_email,
			cert_expires_at = EXCLUDED.cert_expires_at,
			auth_enabled = EXCLUDED.auth_enabled,
			auth_paths = EXCLUDED.auth_paths,
			geo_mode = EXCLUDED.geo_mode,
			geo_countries = EXCLUDED.geo_countries,
			updated_at = now()`,
		site.ID, site.Name, domains, site.UpstreamScheme, site.UpstreamHost, site.UpstreamPort,
		site.Mode, site.Challenge, site.RateRPS, site.RateBurst, site.FloodRPS, site.TLSCert,
		site.TLSKey, site.ForceHTTPS, site.Enabled, rulesOff, site.AcmeEnabled, site.AcmeEmail,
		site.CertExpiresAt, site.AuthEnabled, authPaths, site.GeoMode, geoCountries)
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
