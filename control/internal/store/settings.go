package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"

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
	st.GeoMode, st.GeoCountries = NormaliseGeo(st.GeoMode, st.GeoCountries)
	if st.FloodRPS < 0 || st.FloodErrorRate < 0 {
		return fmt.Errorf("flood thresholds cannot be negative")
	}
	if st.FloodErrorRate > 100 {
		return fmt.Errorf("the origin error threshold is a percentage, so it cannot exceed 100")
	}
	if st.FloodHold < 10 {
		// Below this the defence drops as soon as the flood pauses for breath, and
		// every visitor pays for another challenge when it resumes.
		st.FloodHold = 10
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
		// A trusted list covering every address is the same as no list at all, but
		// it reads like a configured one.
		//
		// The header is believed only when the peer is one of our proxies. Trust
		// everybody and every peer qualifies, so the client's own forwarded-for
		// value becomes its address: it picks what the bans, the blocklist, the
		// rate-limit counters and - since the access rules - the allow rules are
		// keyed on. An allow rule naming an address stops being "who the request is
		// from" and becomes "what the request says", which is the one thing that
		// must never decide whether the firewall runs.
		//
		// It is a plausible thing to type. Somebody behind a CDN who does not know
		// its address ranges writes this to make the header work, and it does work -
		// for the attacker too.
		if bits, err := prefixBits(norm); err == nil && bits == 0 {
			return fmt.Errorf(
				"%q trusts every address, which means any client can set its own "+
					"address through %s - list your proxy's real ranges instead",
				p, st.RealIPHeader)
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

// GetSetting reads one raw JSON value, returning nil when the key is absent.
func (s *Store) GetSetting(ctx context.Context, key string) ([]byte, error) {
	var raw []byte
	err := s.pool.QueryRow(ctx, `SELECT value FROM settings WHERE key = $1`, key).Scan(&raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	return raw, err
}

func (s *Store) PutSetting(ctx context.Context, key string, raw []byte) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO settings (key, value) VALUES ($1, $2)
		ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value`, key, raw)
	return err
}

// prefixBits reports how many leading bits a normalised CIDR fixes. Zero means it
// covers every address.
func prefixBits(cidr string) (int, error) {
	p, err := netip.ParsePrefix(cidr)
	if err != nil {
		return 0, err
	}
	return p.Bits(), nil
}

// WidePublicProxyRange reports a trusted-proxy entry that covers a large amount
// of address space somebody else is using.
//
// Refusing these outright would be wrong, and the line is not "how wide". A /8 is
// enormous and 10.0.0.0/8 is an ordinary internal network behind an ordinary
// internal load balancer - refusing it would break real deployments to prevent
// nothing, because an attacker cannot reach a private address from outside.
//
// The line is public versus private, which is not arbitrary: it is whether the
// space being trusted is space an attacker can be in. A public /8 is almost never
// a real proxy - nobody operates a sixteenth of the internet as their load
// balancer - and any attacker inside it can set their own address. So it is worth
// saying, and not worth blocking: unlike 0.0.0.0/0 it has plausible narrow uses,
// and being wrong about somebody's network is worse than being noisy about it.
func WidePublicProxyRange(cidr string) bool {
	p, err := netip.ParsePrefix(cidr)
	if err != nil {
		return false
	}
	a := p.Addr()
	// Space no outsider can occupy. Trusting all of it is a local decision about a
	// local network, and none of our business.
	if a.IsPrivate() || a.IsLoopback() || a.IsLinkLocalUnicast() || a.IsUnspecified() {
		return false
	}
	if a.Is4() {
		return p.Bits() > 0 && p.Bits() <= 8
	}
	return p.Bits() > 0 && p.Bits() <= 32
}
