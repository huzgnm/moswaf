package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
)

const settingsKey = "global"

func (s *Store) GetSettings(ctx context.Context) (Settings, error) {
	var raw []byte
	err := s.pool.QueryRow(ctx, `SELECT value FROM settings WHERE key = $1`, settingsKey).Scan(&raw)
	if errors.Is(err, pgx.ErrNoRows) {
		def := DefaultSettings()
		if err := s.SaveSettings(ctx, def); err != nil {
			return def, err
		}
		return def, nil
	}
	if err != nil {
		return DefaultSettings(), err
	}

	// Start from the defaults and overlay, so adding a field later never breaks an old row
	st := DefaultSettings()
	if err := json.Unmarshal(raw, &st); err != nil {
		return DefaultSettings(), fmt.Errorf("the stored configuration is corrupt: %w", err)
	}
	return st, nil
}

func ValidateSettings(st *Settings) error {
	switch st.DefaultMode {
	case "protect", "monitor", "off":
	default:
		st.DefaultMode = "protect"
	}
	if st.GlobalRateRPS < 0 || st.GlobalRateBurst < 0 {
		return fmt.Errorf("rate limits cannot be negative")
	}
	if st.ChallengeDifficulty < 8 {
		st.ChallengeDifficulty = 8
	}
	if st.ChallengeDifficulty > 24 {
		// above 24 bits a slow visitor machine can hang for tens of seconds
		return fmt.Errorf("the challenge difficulty is capped at 24 bits")
	}
	if st.ChallengeTTL < 60 {
		st.ChallengeTTL = 60
	}
	if st.BanSeconds < 10 {
		st.BanSeconds = 10
	}
	if st.BlockStatus < 400 || st.BlockStatus > 599 {
		st.BlockStatus = 403
	}
	if st.MaxBodyScan < 0 || st.MaxBodyScan > 1048576 {
		st.MaxBodyScan = 65536
	}
	if st.LogRetainDays < 1 {
		st.LogRetainDays = 7
	}
	if st.TrustedProxies == nil {
		st.TrustedProxies = []string{}
	}
	// Trusting a real-IP header from anyone means the client picks its own identity:
	// bans, the blocklist and every rate-limit counter are keyed on a value the
	// attacker controls, and a fresh header per request means a fresh counter per
	// request. The header is only meaningful behind a known set of proxies.
	if st.RealIPHeader != "" && len(st.TrustedProxies) == 0 {
		return fmt.Errorf("%s can only be trusted when trusted_proxies is set, "+
			"otherwise any client can spoof its own IP", st.RealIPHeader)
	}
	for i, p := range st.TrustedProxies {
		norm, err := NormalizeCIDR(p)
		if err != nil {
			return fmt.Errorf("invalid trusted proxy: %v", err)
		}
		st.TrustedProxies[i] = norm
	}
	return nil
}

func (s *Store) SaveSettings(ctx context.Context, st Settings) error {
	raw, err := json.Marshal(st)
	if err != nil {
		return err
	}
	_, err = s.pool.Exec(ctx, `
		INSERT INTO settings (key, value) VALUES ($1, $2)
		ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value`, settingsKey, raw)
	return err
}
