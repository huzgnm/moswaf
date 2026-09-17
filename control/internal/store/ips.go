package store

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"
)

// NormalizeCIDR accepts both "1.2.3.4" and "10.0.0.0/8" and returns a canonical form.
func NormalizeCIDR(v string) (string, error) {
	v = strings.TrimSpace(v)
	if v == "" {
		return "", fmt.Errorf("empty address")
	}
	if strings.Contains(v, "/") {
		_, ipnet, err := net.ParseCIDR(v)
		if err != nil {
			return "", fmt.Errorf("invalid IP range: %s", v)
		}
		return ipnet.String(), nil
	}
	ip := net.ParseIP(v)
	if ip == nil {
		return "", fmt.Errorf("invalid IP address: %s", v)
	}
	return ip.String(), nil
}

func (s *Store) ListIPs(ctx context.Context, kind string) ([]*IPEntry, error) {
	q := `SELECT id, cidr, kind, reason, expires_at, created_at FROM ip_entries
	      WHERE (expires_at IS NULL OR expires_at > now())`
	args := []any{}
	if kind != "" {
		q += ` AND kind = $1`
		args = append(args, kind)
	}
	q += ` ORDER BY created_at DESC`

	rows, err := s.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []*IPEntry{}
	for rows.Next() {
		var e IPEntry
		if err := rows.Scan(&e.ID, &e.CIDR, &e.Kind, &e.Reason, &e.ExpiresAt, &e.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, &e)
	}
	return out, rows.Err()
}

func (s *Store) AddIP(ctx context.Context, cidr, kind, reason string, ttl time.Duration) (*IPEntry, error) {
	norm, err := NormalizeCIDR(cidr)
	if err != nil {
		return nil, err
	}
	if kind != "black" && kind != "white" {
		return nil, fmt.Errorf("invalid list type: %s", kind)
	}

	var expires *time.Time
	if ttl > 0 {
		t := time.Now().Add(ttl)
		expires = &t
	}

	var e IPEntry
	err = s.pool.QueryRow(ctx, `
		INSERT INTO ip_entries (cidr, kind, reason, expires_at)
		VALUES ($1,$2,$3,$4)
		ON CONFLICT (cidr, kind) DO UPDATE SET reason = EXCLUDED.reason, expires_at = EXCLUDED.expires_at
		RETURNING id, cidr, kind, reason, expires_at, created_at`,
		norm, kind, reason, expires).
		Scan(&e.ID, &e.CIDR, &e.Kind, &e.Reason, &e.ExpiresAt, &e.CreatedAt)
	if err != nil {
		return nil, err
	}
	return &e, nil
}

func (s *Store) DeleteIP(ctx context.Context, id int64) error {
	tag, err := s.pool.Exec(ctx, `DELETE FROM ip_entries WHERE id = $1`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// PurgeExpiredIPs removes expired rows; called periodically.
func (s *Store) PurgeExpiredIPs(ctx context.Context) (int64, error) {
	tag, err := s.pool.Exec(ctx, `DELETE FROM ip_entries WHERE expires_at IS NOT NULL AND expires_at <= now()`)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}
