package store

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// Ordered access rules: the operator's own allow and deny decisions, evaluated
// before the firewall's.
//
// A rule is a list of conditions that must all hold, and an action to take when
// they do. Rules are tried in order and the first that matches decides, so the
// order is part of the meaning rather than a display preference.
//
// The dangerous action is "allow", and the shape of this file is mostly about
// containing it - see validateAllow.

const (
	MaxAccessRules     = 200
	MaxRuleConditions  = 10
	MaxConditionValues = 50
	maxConditionValue  = 256
	maxAccessRuleName  = 120
)

// AccessRule is one row.
type AccessRule struct {
	ID         string          `json:"id"`
	Name       string          `json:"name"`
	Action     string          `json:"action"`   // allow | deny | challenge | log
	Priority   int             `json:"priority"` // lower runs first
	Enabled    bool            `json:"enabled"`
	SiteID     string          `json:"site_id"` // "" means every site
	Conditions []RuleCondition `json:"conditions"`
	CreatedAt  time.Time       `json:"created_at"`
	UpdatedAt  time.Time       `json:"updated_at"`
}

// RuleCondition is one test. Values are alternatives - any one matching satisfies
// the condition - while the conditions of a rule must all hold.
type RuleCondition struct {
	Field  string   `json:"field"`
	Op     string   `json:"op"`
	Values []string `json:"values"`
}

// The fields a condition may test, and what may be done with each.
//
// Deliberately only things the data plane already establishes for every request.
// Nothing here costs a lookup, a parse, or a round trip that was not happening
// anyway.
var conditionOps = map[string][]string{
	"ip":      {"in_cidr"},
	"country": {"in"},
	"crawler": {"is"},
	"path":    {"prefix", "equals", "contains"},
	"host":    {"equals", "suffix"},
	"ua":      {"contains", "equals"},
	"method":  {"in"},
}

// Fields an "allow" rule may be triggered by, and the whole of the reasoning
// behind this feature's safety.
//
// "Allow" means "stop checking this request", so whoever controls the condition
// that fires it controls whether the firewall runs. A rule reading "allow if the
// user agent contains Mozilla" is not merely a broad rule - it is a back door any
// visitor opens by sending a header, because the user agent is a value the
// visitor chooses. The same is true of the path, the host and the method: they
// are the attacker's own request, offered as the reason to stop inspecting it.
//
// So allow may only be triggered by who the request is from, established by us
// and not claimable: an address, or a crawler verified against published address
// ranges. Everything else may still be matched on - by deny, challenge and log,
// where matching an attacker's own request is how you catch it rather than how
// you wave it through.
var allowFields = map[string]bool{"ip": true, "crawler": true}

func (s *Store) ListAccessRules(ctx context.Context, siteID string) ([]*AccessRule, error) {
	q := `SELECT id, name, action, priority, enabled, site_id, conditions, created_at, updated_at
	      FROM access_rules`
	args := []any{}
	if siteID != "" {
		q += ` WHERE site_id = $1`
		args = append(args, siteID)
	}
	q += ` ORDER BY priority, created_at`

	rows, err := s.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []*AccessRule{}
	for rows.Next() {
		var r AccessRule
		var conds []byte
		if err := rows.Scan(&r.ID, &r.Name, &r.Action, &r.Priority, &r.Enabled,
			&r.SiteID, &conds, &r.CreatedAt, &r.UpdatedAt); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(conds, &r.Conditions)
		if r.Conditions == nil {
			r.Conditions = []RuleCondition{}
		}
		out = append(out, &r)
	}
	return out, rows.Err()
}

func (s *Store) GetAccessRule(ctx context.Context, id string) (*AccessRule, error) {
	var r AccessRule
	var conds []byte
	err := s.pool.QueryRow(ctx,
		`SELECT id, name, action, priority, enabled, site_id, conditions, created_at, updated_at
		 FROM access_rules WHERE id = $1`, id).
		Scan(&r.ID, &r.Name, &r.Action, &r.Priority, &r.Enabled, &r.SiteID,
			&conds, &r.CreatedAt, &r.UpdatedAt)
	if err == pgx.ErrNoRows {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	_ = json.Unmarshal(conds, &r.Conditions)
	if r.Conditions == nil {
		r.Conditions = []RuleCondition{}
	}
	return &r, nil
}

// ValidateAccessRule normalises a rule and refuses the ones that would be a way
// past the firewall rather than a use of it.
func ValidateAccessRule(r *AccessRule) error {
	r.Name = strings.TrimSpace(r.Name)
	if r.Name == "" {
		return fmt.Errorf("the rule needs a name")
	}
	if len(r.Name) > maxAccessRuleName {
		return fmt.Errorf("the name is too long")
	}
	if hasControlChar(r.Name) {
		return fmt.Errorf("the name cannot contain line breaks or control characters")
	}

	switch r.Action {
	case "allow", "deny", "challenge", "log":
	default:
		return fmt.Errorf("unknown action %q", r.Action)
	}

	if len(r.Conditions) == 0 {
		// Every rule needs something to match on. An action with no condition is a
		// rule that fires on every request, which for "allow" is the firewall
		// switched off and for "deny" is the site switched off.
		return fmt.Errorf("the rule needs at least one condition")
	}
	if len(r.Conditions) > MaxRuleConditions {
		return fmt.Errorf("a rule may have at most %d conditions", MaxRuleConditions)
	}

	for i := range r.Conditions {
		if err := validateCondition(&r.Conditions[i]); err != nil {
			return err
		}
	}
	if r.Action == "allow" {
		if err := validateAllow(r); err != nil {
			return err
		}
	}

	r.SiteID = strings.TrimSpace(r.SiteID)
	if r.Priority < 0 {
		r.Priority = 0
	}
	if r.Priority > 100000 {
		r.Priority = 100000
	}
	return nil
}

func validateCondition(c *RuleCondition) error {
	c.Field = strings.ToLower(strings.TrimSpace(c.Field))
	c.Op = strings.ToLower(strings.TrimSpace(c.Op))

	ops, ok := conditionOps[c.Field]
	if !ok {
		return fmt.Errorf("unknown condition field %q", c.Field)
	}
	allowed := false
	for _, o := range ops {
		if o == c.Op {
			allowed = true
			break
		}
	}
	if !allowed {
		return fmt.Errorf("%q cannot be tested with %q", c.Field, c.Op)
	}

	clean := make([]string, 0, len(c.Values))
	for _, v := range c.Values {
		v = strings.TrimSpace(v)
		if v == "" || len(v) > maxConditionValue || hasControlChar(v) {
			continue
		}
		clean = append(clean, v)
		if len(clean) >= MaxConditionValues {
			break
		}
	}
	if len(clean) == 0 {
		return fmt.Errorf("the %q condition has no values", c.Field)
	}

	switch c.Field {
	case "ip":
		for i, v := range clean {
			p, err := parseRulePrefix(v)
			if err != nil {
				return fmt.Errorf("%q is not an address or range", v)
			}
			clean[i] = p.String()
		}
	case "country":
		for i, v := range clean {
			v = strings.ToUpper(v)
			if len(v) != 2 || v[0] < 'A' || v[0] > 'Z' || v[1] < 'A' || v[1] > 'Z' {
				return fmt.Errorf("%q is not a two-letter country code", v)
			}
			clean[i] = v
		}
	case "method":
		for i, v := range clean {
			v = strings.ToUpper(v)
			if strings.ContainsAny(v, " \t") {
				return fmt.Errorf("%q is not a method", v)
			}
			clean[i] = v
		}
	case "crawler":
		// One value, and only the two that mean anything. A free-form string here
		// would be read as "not true" and quietly invert the rule.
		if len(clean) != 1 || (clean[0] != "true" && clean[0] != "false") {
			return fmt.Errorf("the crawler condition must be true or false")
		}
	case "host":
		for i, v := range clean {
			clean[i] = strings.ToLower(v)
		}
	}

	c.Values = clean
	return nil
}

// parseRulePrefix accepts an address or a CIDR and returns it as a prefix.
func parseRulePrefix(v string) (netip.Prefix, error) {
	if strings.Contains(v, "/") {
		p, err := netip.ParsePrefix(v)
		if err != nil {
			return netip.Prefix{}, err
		}
		return p.Masked(), nil
	}
	a, err := netip.ParseAddr(v)
	if err != nil {
		return netip.Prefix{}, err
	}
	return netip.PrefixFrom(a, a.BitLen()), nil
}

// validateAllow is the check this whole feature rests on.
//
// "Allow" stops the firewall for a request. Whoever controls the condition that
// fires it therefore controls whether the firewall runs at all - so the condition
// may only be something the request cannot claim about itself.
func validateAllow(r *AccessRule) error {
	for _, c := range r.Conditions {
		if !allowFields[c.Field] {
			return fmt.Errorf(
				"an allow rule cannot be matched on %q: %q is part of the request, so "+
					"anyone could send it and switch the firewall off for themselves. "+
					"Allow rules may only match the address or a verified crawler. To "+
					"restrict who may reach a site by country, use the country rule in "+
					"the settings - that permits visitors rather than exempting them "+
					"from inspection", c.Field, c.Field)
		}
		// An address condition covering everything is the same rule with extra steps.
		if c.Field == "ip" {
			for _, v := range c.Values {
				p, err := parseRulePrefix(v)
				if err != nil {
					return err
				}
				if p.Bits() == 0 {
					return fmt.Errorf(
						"%q covers every address, so this allow rule would switch the "+
							"firewall off for everyone", v)
				}
			}
		}
		// "crawler is false" as an allow condition is "allow everyone who is not a
		// crawler", which is very nearly everyone.
		if c.Field == "crawler" && len(c.Values) == 1 && c.Values[0] == "false" {
			return fmt.Errorf(
				"an allow rule on \"not a verified crawler\" matches almost every " +
					"visitor, which would switch the firewall off for them")
		}
	}
	return nil
}

func (s *Store) UpsertAccessRule(ctx context.Context, r *AccessRule) error {
	if err := ValidateAccessRule(r); err != nil {
		return err
	}
	conds, err := json.Marshal(r.Conditions)
	if err != nil {
		return err
	}
	_, err = s.pool.Exec(ctx, `
		INSERT INTO access_rules (id, name, action, priority, enabled, site_id, conditions, updated_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7, now())
		ON CONFLICT (id) DO UPDATE SET
			name = EXCLUDED.name, action = EXCLUDED.action, priority = EXCLUDED.priority,
			enabled = EXCLUDED.enabled, site_id = EXCLUDED.site_id,
			conditions = EXCLUDED.conditions, updated_at = now()`,
		r.ID, r.Name, r.Action, r.Priority, r.Enabled, r.SiteID, conds)
	return err
}

func (s *Store) DeleteAccessRule(ctx context.Context, id string) error {
	tag, err := s.pool.Exec(ctx, `DELETE FROM access_rules WHERE id = $1`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// CountAccessRules is what the create endpoint checks before adding another.
func (s *Store) CountAccessRules(ctx context.Context) (int, error) {
	var n int
	err := s.pool.QueryRow(ctx, `SELECT count(*) FROM access_rules`).Scan(&n)
	return n, err
}

// ReorderAccessRules writes a new order in one transaction.
//
// All of it or none of it: a half-applied order is a different policy from both
// the old one and the new one, and with first-match-wins that is a policy nobody
// has ever looked at.
func (s *Store) ReorderAccessRules(ctx context.Context, ids []string) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	for i, id := range ids {
		if _, err := tx.Exec(ctx,
			`UPDATE access_rules SET priority = $1, updated_at = now() WHERE id = $2`,
			i+1, id); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

// RuleCountries lists every country any rule mentions, so the publisher can ship
// the address ranges those rules will be decided with.
//
// Missed, a country condition would have no data to test against and would simply
// never match - which reads as "the rule is not working" and gives no clue why.
func RuleCountries(rules []*AccessRule) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, r := range rules {
		if !r.Enabled {
			continue
		}
		for _, c := range r.Conditions {
			if c.Field != "country" {
				continue
			}
			for _, v := range c.Values {
				if !seen[v] {
					seen[v] = true
					out = append(out, v)
				}
			}
		}
	}
	return out
}
