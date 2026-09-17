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

// Cau truc JSON do dataplane/lua/moswaf/log.lua day len.
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

	// OnChange duoc goi khi janitor xoa cac dong IP het han, de day
	// lai cau hinh cho data plane bo chung khoi blacklist/whitelist.
	OnChange func(context.Context) error
}

func NewConsumer(db *store.Store, rdb *redis.Client) *Consumer {
	return &Consumer{db: db, rdb: rdb}
}

// Run chay den khi ctx bi huy: keo su kien, gom thong ke, don du lieu cu.
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
			log.Printf("moswaf: doc hang doi su kien loi: %v", err)
			time.Sleep(2 * time.Second)
			continue
		}
		if n < batchSize {
			// hang doi da can -> nghi mot nhip cho do dot CPU
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
			continue // bo qua dong hong, khong dung ca lo
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

// collectStats gom bo dem theo phut tu Redis vao bang stats_minute.
func (c *Consumer) collectStats(ctx context.Context) {
	ticker := time.NewTicker(20 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}

		var cursor uint64
		for {
			keys, next, err := c.rdb.Scan(ctx, cursor, statPrefix+"*", 200).Result()
			if err != nil {
				log.Printf("moswaf: quet thong ke loi: %v", err)
				break
			}
			for _, k := range keys {
				c.absorbStat(ctx, k)
			}
			cursor = next
			if cursor == 0 {
				break
			}
		}
	}
}

func (c *Consumer) absorbStat(ctx context.Context, key string) {
	secs, err := strconv.ParseInt(strings.TrimPrefix(key, statPrefix), 10, 64)
	if err != nil {
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
	p := store.StatPoint{
		Minute:     time.Unix(secs, 0).UTC(),
		Total:      num("total"),
		Blocked:    num("blocked"),
		Challenged: num("challenged"),
		Monitored:  num("monitored"),
	}
	if err := c.db.UpsertStat(ctx, p); err != nil {
		log.Printf("moswaf: ghi thong ke loi: %v", err)
	}
}

// janitor don log cu, thong ke cu va cac dong IP da het han.
func (c *Consumer) janitor(ctx context.Context) {
	run := func() {
		st, err := c.db.GetSettings(ctx)
		days := 7
		if err == nil && st.LogRetainDays > 0 {
			days = st.LogRetainDays
		}
		if n, err := c.db.PurgeOldEvents(ctx, days); err != nil {
			log.Printf("moswaf: don log cu loi: %v", err)
		} else if n > 0 {
			log.Printf("moswaf: da don %d su kien cu hon %d ngay", n, days)
		}
		if err := c.db.PurgeOldStats(ctx, days*2); err != nil {
			log.Printf("moswaf: don thong ke cu loi: %v", err)
		}
		if n, err := c.db.PurgeExpiredIPs(ctx); err != nil {
			log.Printf("moswaf: don IP het han loi: %v", err)
		} else if n > 0 && c.OnChange != nil {
			if err := c.OnChange(ctx); err != nil {
				log.Printf("moswaf: day lai cau hinh sau khi don IP loi: %v", err)
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
