package store

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/jackc/pgx/v5"
)

// BuiltinRules phai trung ID va bieu thuc voi bo mac dinh trong
// dataplane/lua/moswaf/rules.lua. Chung duoc seed vao DB lan chay dau tien
// de admin bat/tat va chinh sua tren dashboard.
var BuiltinRules = []Rule{
	{ID: "sqli-union", Name: "SQLi - UNION SELECT", Category: "sqli", Target: "any",
		Pattern: `(?i)union[\s/*()]+(all[\s/*()]+)?select`, Action: "deny", Severity: "high"},
	{ID: "sqli-common", Name: "SQLi - cu phap pho bien", Category: "sqli", Target: "any",
		Pattern: `(?i)(\bselect\b[\s\S]{1,60}\bfrom\b|\binsert\b\s+into\b|\bdrop\b\s+table\b|\bupdate\b[\s\S]{1,40}\bset\b[\s\S]{1,40}=)`,
		Action:  "deny", Severity: "high"},
	{ID: "sqli-blind", Name: "SQLi - blind / time based", Category: "sqli", Target: "any",
		Pattern: `(?i)(sleep\s*\(\s*\d|benchmark\s*\(|pg_sleep\s*\(|waitfor\s+delay|\bor\b\s+\d+\s*=\s*\d+|'\s*or\s*'1'\s*=\s*'1)`,
		Action:  "deny", Severity: "high"},
	{ID: "sqli-meta", Name: "SQLi - do metadata", Category: "sqli", Target: "any",
		Pattern: `(?i)(information_schema|load_file\s*\(|into\s+(out|dump)file|@@version|version\s*\(\s*\))`,
		Action:  "deny", Severity: "high"},

	{ID: "xss-tag", Name: "XSS - the nguy hiem", Category: "xss", Target: "any",
		Pattern: `(?i)<\s*(script|iframe|object|embed|svg\b[^>]*onload)`, Action: "deny", Severity: "high"},
	{ID: "xss-event", Name: "XSS - event handler / js:", Category: "xss", Target: "any",
		Pattern: `(?i)(javascript\s*:|on(error|load|click|mouseover|focus)\s*=|document\.cookie|eval\s*\(|atob\s*\()`,
		Action:  "deny", Severity: "medium"},

	{ID: "lfi-traversal", Name: "Path traversal", Category: "lfi", Target: "any",
		Pattern: `(?i)(\.\./|\.\.\\|%2e%2e[/%5c]|\.\.%2f)`, Action: "deny", Severity: "high"},
	{ID: "lfi-file", Name: "Doc file he thong", Category: "lfi", Target: "any",
		Pattern: `(?i)(/etc/(passwd|shadow|hosts)|/proc/self/(environ|cmdline)|boot\.ini|win\.ini)`,
		Action:  "deny", Severity: "high"},
	{ID: "lfi-wrapper", Name: "PHP wrapper", Category: "lfi", Target: "any",
		Pattern: `(?i)(php://(input|filter|memory)|data://text|expect://|zip://)`, Action: "deny", Severity: "high"},

	{ID: "rce-shell", Name: "RCE - chen lenh shell", Category: "rce", Target: "any",
		Pattern: `(?i)([;|&` + "`" + `]\s*(cat|ls|id|pwd|whoami|uname|wget|curl|nc|ncat|bash|sh|python|perl)\b|\$\([^)]{1,40}\))`,
		Action:  "deny", Severity: "critical"},
	{ID: "rce-php", Name: "RCE - ham PHP nguy hiem", Category: "rce", Target: "any",
		Pattern: `(?i)\b(system|exec|passthru|shell_exec|popen|proc_open|assert|base64_decode)\s*\(`,
		Action:  "deny", Severity: "critical"},

	{ID: "path-secret", Name: "Do file bi mat", Category: "recon", Target: "uri",
		Pattern: `(?i)/(\.env|\.git/|\.svn/|\.ssh/|\.aws/|wp-config\.php(\.bak)?|config\.php\.(bak|old|save)|\.DS_Store|docker-compose\.ya?ml|backup\.(sql|zip|tar\.gz))`,
		Action:  "deny", Severity: "medium"},
	{ID: "path-admin", Name: "Do bang dieu khien", Category: "recon", Target: "uri",
		Pattern: `(?i)/(phpmyadmin|pma|adminer\.php|phpinfo\.php)`, Action: "log", Severity: "low"},

	{ID: "ua-scanner", Name: "Cong cu quet lo hong", Category: "bot", Target: "ua",
		Pattern: `(?i)(sqlmap|nikto|nmap|masscan|zgrab|acunetix|nessus|openvas|dirbuster|gobuster|feroxbuster|wpscan|joomscan|hydra|havij|netsparker|arachni|w3af|xsstrike)`,
		Action:  "deny", Severity: "high"},
	{ID: "ua-empty", Name: "Thieu User-Agent", Category: "bot", Target: "ua",
		Pattern: `^$`, Action: "challenge", Severity: "low"},
	{ID: "ua-lib", Name: "HTTP client tu dong", Category: "bot", Target: "ua",
		Pattern: `(?i)^(python-requests|python-urllib|go-http-client|java/|okhttp|libwww-perl|axios/|scrapy|node-fetch)`,
		Action:  "log", Severity: "low"},

	{ID: "hdr-inject", Name: "Chen header / CRLF", Category: "proto", Target: "any",
		Pattern: `(?i)(%0d%0a|\r\n)(set-cookie|location|content-length)\s*:`, Action: "deny", Severity: "medium"},
	{ID: "ssrf-meta", Name: "SSRF - metadata cloud", Category: "ssrf", Target: "any",
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

// SeedRules nap bo rule goc, chi chen khi chua ton tai -> khong de len
// chinh sua cua admin sau nay.
func (s *Store) SeedRules(ctx context.Context) error {
	for _, r := range BuiltinRules {
		_, err := s.pool.Exec(ctx, `
			INSERT INTO rules (id, name, category, target, pattern, action, severity, enabled, builtin)
			VALUES ($1,$2,$3,$4,$5,$6,$7,true,true)
			ON CONFLICT (id) DO NOTHING`,
			r.ID, r.Name, r.Category, r.Target, r.Pattern, r.Action, r.Severity)
		if err != nil {
			return fmt.Errorf("seed rule %s: %w", r.ID, err)
		}
	}
	return nil
}

func (s *Store) ListRules(ctx context.Context) ([]*Rule, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+ruleCols+` FROM rules ORDER BY builtin DESC, category, id`)
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
		return fmt.Errorf("thieu ten rule")
	}
	if r.Pattern == "" {
		return fmt.Errorf("thieu bieu thuc")
	}
	// Cu phap PCRE cua OpenResty rong hon RE2, nhung bat duoc phan lon loi go nham.
	if _, err := regexp.Compile(r.Pattern); err != nil {
		return fmt.Errorf("bieu thuc khong hop le: %v", err)
	}
	switch r.Target {
	case "uri", "args", "body", "ua", "header", "cookie", "any":
	default:
		return fmt.Errorf("target khong hop le: %s", r.Target)
	}
	switch r.Action {
	case "deny", "challenge", "ban", "log":
	default:
		return fmt.Errorf("action khong hop le: %s", r.Action)
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

// DeleteRule chi xoa rule tu tao; rule goc chi duoc tat, khong duoc xoa
// de lan nang cap sau con doi chieu duoc.
func (s *Store) DeleteRule(ctx context.Context, id string) error {
	tag, err := s.pool.Exec(ctx, `DELETE FROM rules WHERE id = $1 AND builtin = false`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("khong xoa duoc: rule khong ton tai hoac la rule goc (hay tat thay vi xoa)")
	}
	return nil
}
