package store

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/jackc/pgx/v5"
)

// BuiltinRules must match the ids and patterns of the default set in
// dataplane/lua/moswaf/rules.lua. They are seeded into the database on first run
// so an admin can toggle and edit them from the dashboard.
var BuiltinRules = []Rule{
	{ID: "sqli-union", Name: "SQLi - UNION SELECT", Category: "sqli", Target: "any",
		Pattern: `(?i)union[\s/*()]+(all[\s/*()]+)?select`, Action: "deny", Severity: "high"},
	{ID: "sqli-common", Name: "SQLi - common syntax", Category: "sqli", Target: "any",
		Pattern: `(?i)(\bselect\b[\s\S]{1,60}\bfrom\b|\binsert\b\s+into\b|\bdrop\b\s+table\b|\bupdate\b[\s\S]{1,40}\bset\b[\s\S]{1,40}=)`,
		Action:  "deny", Severity: "high"},
	{ID: "sqli-blind", Name: "SQLi - blind / time based", Category: "sqli", Target: "any",
		Pattern: `(?i)(sleep\s*\(\s*\d|benchmark\s*\(|pg_sleep\s*\(|waitfor\s+delay|\bor\b\s+\d+\s*=\s*\d+|'\s*or\s*'1'\s*=\s*'1)`,
		Action:  "deny", Severity: "high"},
	{ID: "sqli-meta", Name: "SQLi - metadata probing", Category: "sqli", Target: "any",
		Pattern: `(?i)(information_schema|load_file\s*\(|into\s+(out|dump)file|@@version|version\s*\(\s*\))`,
		Action:  "deny", Severity: "high"},

	{ID: "xss-tag", Name: "XSS - dangerous tags", Category: "xss", Target: "any",
		Pattern: `(?i)<\s*(script|iframe|object|embed|svg\b[^>]*onload)`, Action: "deny", Severity: "high"},
	{ID: "xss-event", Name: "XSS - event handler / js:", Category: "xss", Target: "any",
		Pattern: `(?i)(javascript\s*:|on(error|load|click|mouseover|focus)\s*=|document\.cookie|eval\s*\(|atob\s*\()`,
		Action:  "deny", Severity: "medium"},

	{ID: "lfi-traversal", Name: "Path traversal", Category: "lfi", Target: "any",
		Pattern: `(?i)(\.\./|\.\.\\|%2e%2e[/%5c]|\.\.%2f)`, Action: "deny", Severity: "high"},
	{ID: "lfi-file", Name: "System file access", Category: "lfi", Target: "any",
		Pattern: `(?i)(/etc/(passwd|shadow|hosts)|/proc/self/(environ|cmdline)|boot\.ini|win\.ini)`,
		Action:  "deny", Severity: "high"},
	{ID: "lfi-wrapper", Name: "PHP wrapper", Category: "lfi", Target: "any",
		Pattern: `(?i)(php://(input|filter|memory)|data://text|expect://|zip://)`, Action: "deny", Severity: "high"},

	{ID: "rce-shell", Name: "RCE - shell command injection", Category: "rce", Target: "any",
		Pattern: `(?i)([;|&` + "`" + `]\s*(cat|ls|id|pwd|whoami|uname|wget|curl|nc|ncat|bash|sh|python|perl)\b|\$\([^)]{1,40}\))`,
		Action:  "deny", Severity: "critical"},
	{ID: "rce-php", Name: "RCE - dangerous PHP functions", Category: "rce", Target: "any",
		Pattern: `(?i)\b(system|exec|passthru|shell_exec|popen|proc_open|assert|base64_decode)\s*\(`,
		Action:  "deny", Severity: "critical"},

	{ID: "path-secret", Name: "Secret file probing", Category: "recon", Target: "uri",
		Pattern: `(?i)/(\.env|\.git/|\.svn/|\.ssh/|\.aws/|wp-config\.php(\.bak)?|config\.php\.(bak|old|save)|\.DS_Store|docker-compose\.ya?ml|backup\.(sql|zip|tar\.gz))`,
		Action:  "deny", Severity: "medium"},
	{ID: "path-admin", Name: "Admin panel probing", Category: "recon", Target: "uri",
		Pattern: `(?i)/(phpmyadmin|pma|adminer\.php|phpinfo\.php)`, Action: "log", Severity: "low"},

	{ID: "ua-scanner", Name: "Vulnerability scanner", Category: "bot", Target: "ua",
		Pattern: `(?i)(sqlmap|nikto|nmap|masscan|zgrab|acunetix|nessus|openvas|dirbuster|gobuster|feroxbuster|wpscan|joomscan|hydra|havij|netsparker|arachni|w3af|xsstrike)`,
		Action:  "deny", Severity: "high"},
	{ID: "ua-empty", Name: "Missing User-Agent", Category: "bot", Target: "ua",
		Pattern: `^$`, Action: "challenge", Severity: "low"},
	{ID: "ua-lib", Name: "Automated HTTP client", Category: "bot", Target: "ua",
		Pattern: `(?i)^(python-requests|python-urllib|go-http-client|java/|okhttp|libwww-perl|axios/|scrapy|node-fetch)`,
		Action:  "log", Severity: "low"},

	{ID: "hdr-inject", Name: "Header injection / CRLF", Category: "proto", Target: "any",
		Pattern: `(?i)(%0d%0a|\r\n)(set-cookie|location|content-length)\s*:`, Action: "deny", Severity: "medium"},
	{ID: "ssrf-meta", Name: "SSRF - cloud metadata", Category: "ssrf", Target: "any",
		Pattern: `(?i)(169\.254\.169\.254|metadata\.google\.internal|100\.100\.100\.200)`,
		Action:  "deny", Severity: "high"},
}

const ruleCols = `id, name, category, target, pattern, action, severity, enabled, builtin, created_at`

func scanRule(row pgx.Row) (*Rule, error) {
	var r Rule
	err := row.Scan(&r.ID, &r.Name, &r.Category, &r.Target, &r.Pattern,
		&r.Action, &r.Severity, &r.Enabled, &r.Builtin, &r.CreatedAt)
	if err != nil {
		return nil, err
	}
	return &r, nil
}

// SeedRules loads the built-in rules on every start.
//
// Rows that already exist keep their behaviour - pattern, action, severity and
// whether they are enabled all belong to the admin, who can edit them from the
// dashboard. Only the display name and category are refreshed from the code, so a
// rename in a new version actually reaches an existing install: with a plain
// DO NOTHING the names stayed frozen at whatever the first run wrote, which is how
// an upgraded install ended up showing rule names in the old language.
func (s *Store) SeedRules(ctx context.Context) error {
	for _, r := range BuiltinRules {
		_, err := s.pool.Exec(ctx, `
			INSERT INTO rules (id, name, category, target, pattern, action, severity, enabled, builtin)
			VALUES ($1,$2,$3,$4,$5,$6,$7,true,true)
			ON CONFLICT (id) DO UPDATE SET
				name = EXCLUDED.name,
				category = EXCLUDED.category
			WHERE rules.builtin = true`,
			r.ID, r.Name, r.Category, r.Target, r.Pattern, r.Action, r.Severity)
		if err != nil {
			return fmt.Errorf("seeding rule %s: %w", r.ID, err)
		}
	}
	return nil
}

// actionOrder decides the order rules are evaluated in. The data plane walks this
// list and stops at the first match, so a rule that only logs must never be
// reached before one that blocks: ordering by category alone meant a `log` rule in
// category "bot" shadowed every sqli/xss/rce rule behind it.
const actionOrder = `CASE action WHEN 'deny' THEN 0 WHEN 'ban' THEN 1 WHEN 'challenge' THEN 2 ELSE 3 END`

func (s *Store) ListRules(ctx context.Context) ([]*Rule, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+ruleCols+` FROM rules ORDER BY `+actionOrder+`, builtin DESC, category, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []*Rule{}
	for rows.Next() {
		r, err := scanRule(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *Store) GetRule(ctx context.Context, id string) (*Rule, error) {
	r, err := scanRule(s.pool.QueryRow(ctx, `SELECT `+ruleCols+` FROM rules WHERE id = $1`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	return r, err
}

func ValidateRule(r *Rule) error {
	r.ID = strings.TrimSpace(r.ID)
	r.Name = strings.TrimSpace(r.Name)

	if r.Name == "" {
		return fmt.Errorf("the rule name is required")
	}
	if r.Pattern == "" {
		return fmt.Errorf("the pattern is required")
	}
	if err := validatePattern(r.Pattern); err != nil {
		return err
	}
	switch r.Target {
	case "uri", "args", "body", "ua", "header", "cookie", "any":
	default:
		return fmt.Errorf("invalid target: %s", r.Target)
	}
	switch r.Action {
	case "deny", "challenge", "ban", "log":
	default:
		return fmt.Errorf("invalid action: %s", r.Action)
	}
	switch r.Severity {
	case "low", "medium", "high", "critical":
	default:
		r.Severity = "medium"
	}
	if r.Category == "" {
		r.Category = "custom"
	}
	return nil
}

// A group that is itself quantified and whose body ends in a quantifier - (a+)+,
// (a*)* , (ab+)* - is the classic catastrophic-backtracking shape. RE2 runs it in
// linear time and accepts it happily, but the data plane runs patterns through
// PCRE, nginx.conf sets no lua_regex_match_limit, and rules.lua drops the error
// return of ngx.re.find. One such rule stalls a worker on every request.
var nestedQuantifier = regexp.MustCompile(`\([^()]*[+*][^()]*\)\s*[+*]`)

// validatePattern checks a rule pattern without pretending RE2 and PCRE are the
// same engine. RE2 rejects lookarounds and backreferences that PCRE handles fine,
// so a pattern RE2 calls "unsupported Perl syntax" is still valid for the data
// plane and must be accepted; anything RE2 calls malformed is malformed in both.
func validatePattern(pattern string) error {
	if nestedQuantifier.MatchString(pattern) {
		return fmt.Errorf("invalid pattern: a quantified group containing a quantifier " +
			"(for example `(a+)+`) can backtrack catastrophically in the data plane")
	}
	if _, err := regexp.Compile(pattern); err != nil {
		// Valid PCRE that RE2 simply does not implement - accept it.
		if strings.Contains(err.Error(), "invalid or unsupported Perl syntax") {
			return nil
		}
		return fmt.Errorf("invalid pattern: %v", err)
	}
	return nil
}

func (s *Store) UpsertRule(ctx context.Context, r *Rule) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO rules (id, name, category, target, pattern, action, severity, enabled, builtin)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
		ON CONFLICT (id) DO UPDATE SET
			name = EXCLUDED.name, category = EXCLUDED.category, target = EXCLUDED.target,
			pattern = EXCLUDED.pattern, action = EXCLUDED.action, severity = EXCLUDED.severity,
			enabled = EXCLUDED.enabled`,
		r.ID, r.Name, r.Category, r.Target, r.Pattern, r.Action, r.Severity, r.Enabled, r.Builtin)
	return err
}

func (s *Store) SetRuleEnabled(ctx context.Context, id string, enabled bool) error {
	tag, err := s.pool.Exec(ctx, `UPDATE rules SET enabled = $2 WHERE id = $1`, id, enabled)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// DeleteRule only removes custom rules. Built-in rules can be disabled but not
// deleted, so a later upgrade still has something to compare against.
func (s *Store) DeleteRule(ctx context.Context, id string) error {
	tag, err := s.pool.Exec(ctx, `DELETE FROM rules WHERE id = $1 AND builtin = false`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("cannot delete: the rule does not exist or is built in (disable it instead)")
	}
	return nil
}
