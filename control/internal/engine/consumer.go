package engine

import (
	"context"
	"encoding/json"
	"log"
	"strconv"
	"strings"
	"time"

	"github.com/mosvpn/moswaf/control/internal/store"
	"github.com/redis/go-redis/v9"
)

const (
	queueKey   = "moswaf:events"
	statPrefix = "moswaf:stat:"
	batchSize  = 500
)

// The JSON shape pushed by dataplane/lua/moswaf/log.lua.
type rawEvent struct {
	TS       int64   `json:"ts"`
	Ray      string  `json:"ray"`
	Site     string  `json:"site"`
	IP       string  `json:"ip"`
	Method   string  `json:"method"`
	Host     string  `json:"host"`
	URI      string  `json:"uri"`
	UA       string  `json:"ua"`
	Referer  string  `json:"referer"`
	Action   string  `json:"action"`
	Reason   string  `json:"reason"`
	RuleID   string  `json:"rule_id"`
	RuleName string  `json:"rule_name"`
	Severity string  `json:"severity"`
	Status   int     `json:"status"`
	RT       float64 `json:"rt"`
}

type Consumer struct {
	db  *store.Store
	rdb *redis.Client

	// OnChange fires when the janitor deletes expired IP rows, so the configuration
	// can be republished and the data plane drops them from its lists.
	OnChange func(context.Context) error
}

func NewConsumer(db *store.Store, rdb *redis.Client) *Consumer {
	return &Consumer{db: db, rdb: rdb}
}

// Run works until ctx is cancelled: draining events, collecting stats and pruning old data.
func (c *Consumer) Run(ctx context.Context) {
	go c.consumeEvents(ctx)
	go c.collectStats(ctx)
	go c.janitor(ctx)
}

func (c *Consumer) consumeEvents(ctx context.Context) {
	for {
		if ctx.Err() != nil {
			return
		}
		n, err := c.drain(ctx)
		if err != nil {
			log.Printf("moswaf: failed to read the event queue: %v", err)
			time.Sleep(2 * time.Second)
			continue
		}
		if n < batchSize {
			// queue is drained -> pause a beat to keep CPU use flat
			select {
			case <-ctx.Done():
				return
			case <-time.After(300 * time.Millisecond):
			}
		}
	}
}

func (c *Consumer) drain(ctx context.Context) (int, error) {
	items, err := c.rdb.RPopCount(ctx, queueKey, batchSize).Result()
	if err == redis.Nil {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	if len(items) == 0 {
		return 0, nil
	}

	evs := make([]*store.Event, 0, len(items))
	for _, raw := range items {
		var r rawEvent
		if err := json.Unmarshal([]byte(raw), &r); err != nil {
			continue // skip a corrupt row rather than losing the whole batch
		}
		ts := time.Unix(r.TS, 0)
		if r.TS == 0 {
			ts = time.Now()
		}
		evs = append(evs, &store.Event{
			TS: ts, Ray: r.Ray, Site: r.Site, IP: r.IP, Method: r.Method, Host: r.Host,
			URI: r.URI, UA: r.UA, Referer: r.Referer, Action: r.Action, Reason: r.Reason,
			RuleID: r.RuleID, RuleName: r.RuleName, Severity: r.Severity,
			Status: r.Status, RT: r.RT,
		})
	}

	if err := c.db.InsertEvents(ctx, evs); err != nil {
		return 0, err
	}
	return len(items), nil
}

// collectStats folds the per-minute counters from Redis into the stats_minute table.
func (c *Consumer) collectStats(ctx context.Context) {
	ticker := time.NewTicker(20 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}

		// Sum across hosts before writing, rather than writing each key as it is
		// found. Each data plane ships its own absolute counters under its own
		// key, so a minute's real total is the sum of the hosts that served it -
		// and since the keys for one minute can land in different scan batches,
		// the whole scan has to finish before any of it is a total.
		perMinute := map[int64]*store.StatPoint{}

		var cursor uint64
		for {
			keys, next, err := c.rdb.Scan(ctx, cursor, statPrefix+"*", 200).Result()
			if err != nil {
				log.Printf("moswaf: failed to scan statistics: %v", err)
				break
			}
			for _, k := range keys {
				c.absorbStat(ctx, k, perMinute)
			}
			cursor = next
			if cursor == 0 {
				break
			}
		}

		for _, p := range perMinute {
			if err := c.db.UpsertStat(ctx, *p); err != nil {
				log.Printf("moswaf: failed to write statistics: %v", err)
			}
		}
	}
}

// statMinute pulls the minute out of a statistics key.
//
// Two shapes are accepted. "moswaf:stat:<minute>:<host>" is what a current data
// plane writes; "moswaf:stat:<minute>" is what one written before hosts were
// separated wrote, and those keys live for two hours after an upgrade. Dropping
// them would put a two hour hole in the graph of every installation that
// updates.
func statMinute(key string) (int64, bool) {
	rest := strings.TrimPrefix(key, statPrefix)
	if i := strings.IndexByte(rest, ':'); i >= 0 {
		rest = rest[:i]
	}
	secs, err := strconv.ParseInt(rest, 10, 64)
	if err != nil {
		return 0, false
	}
	return secs, true
}

// absorbStat adds one host's counters for one minute into the running total.
func (c *Consumer) absorbStat(ctx context.Context, key string, into map[int64]*store.StatPoint) {
	secs, ok := statMinute(key)
	if !ok {
		return
	}
	vals, err := c.rdb.HGetAll(ctx, key).Result()
	if err != nil || len(vals) == 0 {
		return
	}
	num := func(k string) int64 {
		n, _ := strconv.ParseInt(vals[k], 10, 64)
		return n
	}

	p := into[secs]
	if p == nil {
		p = &store.StatPoint{Minute: time.Unix(secs, 0).UTC()}
		into[secs] = p
	}
	p.Total += num("total")
	p.Blocked += num("blocked")
	p.Challenged += num("challenged")
	p.Monitored += num("monitored")
	p.Errors4xx += num("errors_4xx")
	p.Blocked4xx += num("blocked_4xx")
	p.Errors5xx += num("errors_5xx")
	p.PageViews += num("page_views")
}

// janitor prunes old events, old statistics and expired IP rows.
func (c *Consumer) janitor(ctx context.Context) {
	run := func() {
		st, err := c.db.GetSettings(ctx)
		days := 7
		if err == nil && st.LogRetainDays > 0 {
			days = st.LogRetainDays
		}
		if n, err := c.db.PurgeOldEvents(ctx, days); err != nil {
			log.Printf("moswaf: failed to prune old events: %v", err)
		} else if n > 0 {
			log.Printf("moswaf: pruned %d events older than %d days", n, days)
		}
		if err := c.db.PurgeOldStats(ctx, days*2); err != nil {
			log.Printf("moswaf: failed to prune old statistics: %v", err)
		}
		if n, err := c.db.PurgeExpiredIPs(ctx); err != nil {
			log.Printf("moswaf: failed to prune expired IPs: %v", err)
		} else if n > 0 && c.OnChange != nil {
			if err := c.OnChange(ctx); err != nil {
				log.Printf("moswaf: failed to republish after pruning IPs: %v", err)
			}
		}
	}

	timer := time.NewTimer(time.Minute)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			run()
			timer.Reset(time.Hour)
		}
	}
}
