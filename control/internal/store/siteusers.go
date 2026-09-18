package store

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
	"golang.org/x/crypto/bcrypt"
)

// Accounts for the login gate in front of a site.
//
// Deliberately separate from the dashboard's own users. These people are allowed
// through to one site; they are not administrators of MosWAF. One table for both
// would mean an account created so a colleague could see a staging server could
// also turn the firewall off.

const minSitePasswordLength = 10

// ValidateSiteUser checks the details and returns the username as it will be
// stored.
//
// It returns the normalised name rather than only checking it, because the
// alternative is two places trimming separately - here and at the INSERT - and two
// places that have to agree are one change away from not agreeing. Whatever comes
// out of this function is what goes into the table, so what was checked and what
// is stored cannot be different strings.
func ValidateSiteUser(username, password string) (string, error) {
	username = strings.TrimSpace(username)
	if username == "" {
		return "", fmt.Errorf("a username is required")
	}
	if len(username) > 64 {
		return "", fmt.Errorf("the username is too long")
	}
	// Control characters in a username end up in log lines and in the identity
	// header handed to the upstream, where a newline is a way to write a second
	// header of somebody else's choosing.
	for _, r := range username {
		if r < 0x20 || r == 0x7f {
			return "", fmt.Errorf("the username contains a control character")
		}
	}
	if len(password) < minSitePasswordLength {
		return "", fmt.Errorf("the password must be at least %d characters", minSitePasswordLength)
	}
	return username, nil
}

const maxAuthPaths = 32

// NormaliseAuthPaths puts the protected paths into the one shape the data plane
// compares against, so that what an operator types and what the gate enforces
// cannot drift apart.
//
// Applied again at publication rather than only where it was typed: a row can
// reach the table from an older version of this code or from somebody's psql
// session, and a path the matcher does not recognise is a path that silently
// protects nothing.
//
// A path that survives covers itself and everything below it - "/admin" means
// "/admin" and "/admin/..." and stops there.
func NormaliseAuthPaths(paths []string) []string {
	out := make([]string, 0, len(paths))
	seen := map[string]bool{}

	for _, p := range paths {
		p = strings.TrimSpace(p)
		// "/admin/*" is how most people write this, and it means the same thing
		// here, so it is accepted and reduced rather than rejected.
		p = strings.TrimSuffix(p, "*")
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		// A path is matched against nginx's already-decoded $uri, which never
		// contains a query, a fragment, or a host. Anything carrying one was meant
		// as something else and would match nothing at all.
		if i := strings.IndexAny(p, "?#"); i >= 0 {
			p = p[:i]
		}
		if !strings.HasPrefix(p, "/") {
			p = "/" + p
		}
		// $uri has already had "." and ".." collapsed out of it before the gate sees
		// it, so a stored path containing either could never match - it would read
		// as protection and provide none.
		if strings.Contains(p, "/../") || strings.HasSuffix(p, "/..") ||
			strings.Contains(p, "//") {
			continue
		}
		if strings.ContainsAny(p, "\x00\n\r") {
			continue
		}
		// "/admin/" and "/admin" are the same rule; stored one way so they cannot be
		// entered twice and compared differently.
		for len(p) > 1 && strings.HasSuffix(p, "/") {
			p = p[:len(p)-1]
		}
		if len(p) > 256 {
			continue
		}
		// The whole site. Nothing else in the list can add to that.
		if p == "/" {
			return []string{"/"}
		}
		key := strings.ToLower(p)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, p)
		if len(out) >= maxAuthPaths {
			break
		}
	}

	// An empty list means the whole site, which is both the useful default and the
	// safe one: a gate switched on with nothing listed protects everything rather
	// than nothing.
	if len(out) == 0 {
		return []string{"/"}
	}
	return out
}

func (s *Store) ListSiteUsers(ctx context.Context, siteID string) ([]*SiteUser, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, site_id, username, generation, created_at
		 FROM site_users WHERE site_id = $1 ORDER BY username`, siteID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []*SiteUser{}
	for rows.Next() {
		var u SiteUser
		if err := rows.Scan(&u.ID, &u.SiteID, &u.Username, &u.Generation, &u.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, &u)
	}
	return out, rows.Err()
}

func (s *Store) CreateSiteUser(ctx context.Context, siteID, username, password string) (*SiteUser, error) {
	username, err := ValidateSiteUser(username, password)
	if err != nil {
		return nil, err
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}

	var u SiteUser
	err = s.pool.QueryRow(ctx,
		`INSERT INTO site_users (site_id, username, password_hash)
		 VALUES ($1,$2,$3) RETURNING id, site_id, username, generation, created_at`,
		siteID, username, string(hash)).
		Scan(&u.ID, &u.SiteID, &u.Username, &u.Generation, &u.CreatedAt)
	if err != nil {
		if strings.Contains(err.Error(), "site_users_site_id_username_key") {
			return nil, fmt.Errorf("that username already exists on this site")
		}
		return nil, err
	}
	return &u, nil
}

// SetSiteUserPassword changes the password and ends every session that account
// already had. A password is usually changed because the old one is suspect, and
// leaving the sessions it opened alive would make the change decorative.
func (s *Store) SetSiteUserPassword(ctx context.Context, id int64, password string) error {
	if len(password) < minSitePasswordLength {
		return fmt.Errorf("the password must be at least %d characters", minSitePasswordLength)
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	tag, err := s.pool.Exec(ctx,
		`UPDATE site_users SET password_hash = $1, generation = generation + 1 WHERE id = $2`,
		string(hash), id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// RevokeSiteUserSessions ends every session for one account without touching the
// password - the "sign out everywhere" button.
func (s *Store) RevokeSiteUserSessions(ctx context.Context, id int64) error {
	tag, err := s.pool.Exec(ctx,
		`UPDATE site_users SET generation = generation + 1 WHERE id = $1`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) DeleteSiteUser(ctx context.Context, id int64) error {
	tag, err := s.pool.Exec(ctx, `DELETE FROM site_users WHERE id = $1`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// AuthenticateSiteUser checks a password for one site.
//
// A wrong username and a wrong password are the same answer, and both cost the
// same time: returning early on an unknown username tells an attacker which
// names exist, so a hash is compared either way.
func (s *Store) AuthenticateSiteUser(ctx context.Context, siteID, username, password string) (*SiteUser, error) {
	var u SiteUser
	var hash string
	err := s.pool.QueryRow(ctx,
		`SELECT id, site_id, username, password_hash, generation, created_at
		 FROM site_users WHERE site_id = $1 AND username = $2`,
		siteID, strings.TrimSpace(username)).
		Scan(&u.ID, &u.SiteID, &u.Username, &hash, &u.Generation, &u.CreatedAt)

	if errors.Is(err, pgx.ErrNoRows) {
		_ = bcrypt.CompareHashAndPassword(
			[]byte("$2a$10$invalidinvalidinvalidinvalidinvalidinvalidinvalidinvalidin"),
			[]byte(password))
		return nil, ErrBadCredentials
	}
	if err != nil {
		return nil, err
	}
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)); err != nil {
		return nil, ErrBadCredentials
	}
	return &u, nil
}

// SiteGenerations is what the data plane needs to verify a session: which
// accounts exist on a site and which generation each is on.
//
// Published with the rest of the configuration so verification reads memory and
// nothing else. An account missing from this map is an account whose sessions
// are refused - which is how deleting a user revokes instantly, with no counter
// to raise and nothing to clean up.
func (s *Store) SiteGenerations(ctx context.Context) (map[string]map[int64]int64, error) {
	rows, err := s.pool.Query(ctx, `SELECT site_id, id, generation FROM site_users`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := map[string]map[int64]int64{}
	for rows.Next() {
		var site string
		var id, gen int64
		if err := rows.Scan(&site, &id, &gen); err != nil {
			return nil, err
		}
		if out[site] == nil {
			out[site] = map[int64]int64{}
		}
		out[site][id] = gen
	}
	return out, rows.Err()
}
