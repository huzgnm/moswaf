package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

const siteCols = `id, name, domains, upstream_scheme, upstream_host, upstream_port,
	mode, challenge, rate_rps, rate_burst, tls_cert, tls_key, force_https,
	enabled, rules_off, created_at, updated_at`

func scanSite(row pgx.Row) (*Site, error) {
	var s Site
	var domains, rulesOff []byte
	err := row.Scan(&s.ID, &s.Name, &domains, &s.UpstreamScheme, &s.UpstreamHost, &s.UpstreamPort,
		&s.Mode, &s.Challenge, &s.RateRPS, &s.RateBurst, &s.TLSCert, &s.TLSKey, &s.ForceHTTPS,
		&s.Enabled, &rulesOff, &s.CreatedAt, &s.UpdatedAt)
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

// ValidateSite chuan hoa va kiem tra du lieu truoc khi ghi.
func ValidateSite(s *Site) error {
	s.Name = strings.TrimSpace(s.Name)
	s.UpstreamHost = strings.TrimSpace(s.UpstreamHost)

	if s.Name == "" {
		return fmt.Errorf("thieu ten site")
	}
	if len(s.Domains) == 0 {
		return fmt.Errorf("phai khai bao it nhat mot ten mien")
	}
	for i, d := range s.Domains {
		d = strings.ToLower(strings.TrimSpace(d))
		if d == "" || strings.ContainsAny(d, " /\\:;{}\"'$") {
			return fmt.Errorf("ten mien khong hop le: %q", s.Domains[i])
		}
		s.Domains[i] = d
	}
	if s.UpstreamHost == "" {
		return fmt.Errorf("thieu dia chi upstream")
	}
	if strings.ContainsAny(s.UpstreamHost, " /\\;{}\"'$") {
		return fmt.Errorf("dia chi upstream khong hop le")
	}
	if s.UpstreamPort <= 0 || s.UpstreamPort > 65535 {
		return fmt.Errorf("cong upstream khong hop le")
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
		return fmt.Errorf("gioi han toc do khong duoc am")
	}
	if (s.TLSCert == "") != (s.TLSKey == "") {
		return fmt.Errorf("phai cung cap ca chung chi va khoa rieng")
	}
	if s.ForceHTTPS && s.TLSCert == "" {
		return fmt.Errorf("bat ep HTTPS thi phai co chung chi")
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
		                   force_https, enabled, rules_off, updated_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15, now())
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
			updated_at = now()`,
		site.ID, site.Name, domains, site.UpstreamScheme, site.UpstreamHost, site.UpstreamPort,
		site.Mode, site.Challenge, site.RateRPS, site.RateBurst, site.TLSCert, site.TLSKey,
		site.ForceHTTPS, site.Enabled, rulesOff)
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
