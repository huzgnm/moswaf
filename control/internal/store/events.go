package store

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// InsertEvents writes a batch of events with COPY, which is far faster than one
// INSERT per row when an attack fills the queue.
func (s *Store) InsertEvents(ctx context.Context, evs []*Event) error {
	if len(evs) == 0 {
		return nil
	}
	rows := make([][]any, 0, len(evs))
	for _, e := range evs {
		rows = append(rows, []any{
			e.TS, e.Ray, e.Site, e.IP, e.Method, e.Host, e.URI, e.UA, e.Referer,
			e.Action, e.Reason, e.RuleID, e.RuleName, e.Severity, e.Status, e.RT,
		})
	}
	_, err := s.pool.CopyFrom(ctx,
		pgx.Identifier{"events"},
		[]string{"ts", "ray", "site", "ip", "method", "host", "uri", "ua", "referer",
			"action", "reason", "rule_id", "rule_name", "severity", "status", "rt"},
		pgx.CopyFromRows(rows))
	return err
}

type EventFilter struct {
	Site     string
	IP       string
	Action   string
	Severity string
	Search   string
	From     *time.Time
	To       *time.Time
	Limit    int
	Offset   int
}

func (f EventFilter) where() (string, []any) {
	var cond []string
	var args []any
	add := func(expr string, val any) {
		args = append(args, val)
		cond = append(cond, fmt.Sprintf(expr, len(args)))
	}
	if f.Site != "" {
		add("site = $%d", f.Site)
	}
	if f.IP != "" {
		add("ip = $%d", f.IP)
	}
	if f.Action != "" {
		add("action = $%d", f.Action)
	}
	if f.Severity != "" {
		add("severity = $%d", f.Severity)
	}
	if f.Search != "" {
		args = append(args, "%"+f.Search+"%")
		n := len(args)
		cond = append(cond, fmt.Sprintf("(uri ILIKE $%d OR ua ILIKE $%d OR rule_name ILIKE $%d)", n, n, n))
	}
	if f.From != nil {
		add("ts >= $%d", *f.From)
	}
	if f.To != nil {
		add("ts <= $%d", *f.To)
	}
	if len(cond) == 0 {
		return "", args
	}
	return " WHERE " + strings.Join(cond, " AND "), args
}

func (s *Store) ListEvents(ctx context.Context, f EventFilter) ([]*Event, int64, error) {
	where, args := f.where()

	var total int64
	if err := s.pool.QueryRow(ctx, `SELECT count(*) FROM events`+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	limit := f.Limit
	if limit <= 0 || limit > 500 {
		limit = 50
	}
	q := `SELECT id, ts, ray, site, ip, method, host, uri, ua, referer, action, reason,
	             rule_id, rule_name, severity, status, rt
	      FROM events` + where +
		fmt.Sprintf(" ORDER BY ts DESC, id DESC LIMIT %d OFFSET %d", limit, max(0, f.Offset))

	rows, err := s.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	out := []*Event{}
	for rows.Next() {
		var e Event
		if err := rows.Scan(&e.ID, &e.TS, &e.Ray, &e.Site, &e.IP, &e.Method, &e.Host, &e.URI,
			&e.UA, &e.Referer, &e.Action, &e.Reason, &e.RuleID, &e.RuleName,
			&e.Severity, &e.Status, &e.RT); err != nil {
			return nil, 0, err
		}
		out = append(out, &e)
	}
	return out, total, rows.Err()
}

type Bucket struct {
	Key   string `json:"key"`
	Label string `json:"label"`
	Count int64  `json:"count"`
}

func (s *Store) TopAttackers(ctx context.Context, since time.Time, limit int) ([]Bucket, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT ip, count(*) FROM events
		WHERE ts >= $1 AND action IN ('deny','challenge')
		GROUP BY ip ORDER BY count(*) DESC LIMIT $2`, since, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []Bucket{}
	for rows.Next() {
		var b Bucket
		if err := rows.Scan(&b.Key, &b.Count); err != nil {
			return nil, err
		}
		b.Label = b.Key
		out = append(out, b)
	}
	return out, rows.Err()
}

func (s *Store) TopRules(ctx context.Context, since time.Time, limit int) ([]Bucket, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT rule_id, coalesce(nullif(max(rule_name),''), rule_id), count(*)
		FROM events WHERE ts >= $1 AND rule_id <> ''
		GROUP BY rule_id ORDER BY count(*) DESC LIMIT $2`, since, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []Bucket{}
	for rows.Next() {
		var b Bucket
		if err := rows.Scan(&b.Key, &b.Label, &b.Count); err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, rows.Err()
}

func (s *Store) CountEventsSince(ctx context.Context, since time.Time) (map[string]int64, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT action, count(*) FROM events WHERE ts >= $1 GROUP BY action`, since)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := map[string]int64{}
	for rows.Next() {
		var k string
		var n int64
		if err := rows.Scan(&k, &n); err != nil {
			return nil, err
		}
		out[k] = n
	}
	return out, rows.Err()
}

func (s *Store) PurgeOldEvents(ctx context.Context, days int) (int64, error) {
	if days <= 0 {
		days = 7
	}
	tag, err := s.pool.Exec(ctx,
		fmt.Sprintf(`DELETE FROM events WHERE ts < now() - interval '%d days'`, days))
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

// ---------------------------------------------------------------- statistics

func (s *Store) UpsertStat(ctx context.Context, p StatPoint) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO stats_minute (minute, total, blocked, challenged, monitored)
		VALUES ($1,$2,$3,$4,$5)
		ON CONFLICT (minute) DO UPDATE SET
			total = GREATEST(stats_minute.total, EXCLUDED.total),
			blocked = GREATEST(stats_minute.blocked, EXCLUDED.blocked),
			challenged = GREATEST(stats_minute.challenged, EXCLUDED.challenged),
			monitored = GREATEST(stats_minute.monitored, EXCLUDED.monitored)`,
		p.Minute, p.Total, p.Blocked, p.Challenged, p.Monitored)
	return err
}

func (s *Store) Timeseries(ctx context.Context, since time.Time) ([]StatPoint, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT minute, total, blocked, challenged, monitored
		FROM stats_minute WHERE minute >= $1 ORDER BY minute`, since)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []StatPoint{}
	for rows.Next() {
		var p StatPoint
		if err := rows.Scan(&p.Minute, &p.Total, &p.Blocked, &p.Challenged, &p.Monitored); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func (s *Store) StatTotals(ctx context.Context, since time.Time) (StatPoint, error) {
	var p StatPoint
	err := s.pool.QueryRow(ctx, `
		SELECT coalesce(sum(total),0), coalesce(sum(blocked),0),
		       coalesce(sum(challenged),0), coalesce(sum(monitored),0)
		FROM stats_minute WHERE minute >= $1`, since).
		Scan(&p.Total, &p.Blocked, &p.Challenged, &p.Monitored)
	return p, err
}

func (s *Store) PurgeOldStats(ctx context.Context, days int) error {
	_, err := s.pool.Exec(ctx,
		fmt.Sprintf(`DELETE FROM stats_minute WHERE minute < now() - interval '%d days'`, days))
	return err
}
