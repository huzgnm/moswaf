package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/mosvpn/moswaf/control/internal/config"
	"github.com/mosvpn/moswaf/control/internal/store"
	"github.com/redis/go-redis/v9"
)

const configKey = "moswaf:config"

// The structures below are exactly what dataplane/lua/moswaf/config.lua reads.
// Renaming a field here means renaming it on the Lua side too.

type luaSite struct {
	ID        string   `json:"id"`
	Name      string   `json:"name"`
	Mode      string   `json:"mode"`
	Challenge string   `json:"challenge"`
	RateRPS   int      `json:"rate_rps"`
	RateBurst int      `json:"rate_burst"`
	FloodRPS  int      `json:"flood_rps"`
	RulesOff  []string `json:"rules_off"`
}

type luaRule struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Target   string `json:"target"`
	Pattern  string `json:"pattern"`
	Action   string `json:"action"`
	Severity string `json:"severity"`
	Enabled  bool   `json:"enabled"`
}

type luaConfig struct {
	Version int64 `json:"version"`
	// Shared with the data plane so its internal API can tell the control plane
	// apart from anything else on the same Docker network. Publishing it here means
	// an upgraded install is protected without anyone editing .env: whoever can read
	// this value from Redis can already rewrite the whole configuration.
	InternalToken string             `json:"internal_token"`
	Settings      store.Settings     `json:"settings"`
	Sites         map[string]luaSite `json:"sites"`
	Rules         []luaRule          `json:"rules"`
	Blacklist     []string           `json:"blacklist"`
	Whitelist     []string           `json:"whitelist"`

	// Published crawler address ranges, already validated. The data plane matches
	// against these instead of resolving DNS per request, which keeps the answer
	// out of the request path entirely.
	Crawlers map[string]luaCrawler `json:"crawlers"`
}

type luaCrawler struct {
	UA       string   `json:"ua"`
	Prefixes []string `json:"prefixes"`
}

type Publisher struct {
	db  *store.Store
	rdb *redis.Client
	cfg *config.Config

	// Published crawler ranges, refreshed on their own timer. Optional: a
	// Publisher without one simply publishes no crawler ranges, which means
	// nothing is exempt from the challenge - the safe direction.
	//
	// Guarded by its own mutex, not by mu. Publish holds mu for its whole body and
	// reads the crawler ranges from inside it; sharing one mutex deadlocked the
	// control plane on its first publish, before it ever served a request. A
	// second lock is cheaper than a rule about which one may be taken when.
	crawlersMu sync.RWMutex
	crawlers   *Crawlers

	mu      sync.Mutex
	version int64
}

func NewPublisher(db *store.Store, rdb *redis.Client, cfg *config.Config) *Publisher {
	return &Publisher{db: db, rdb: rdb, cfg: cfg}
}

func (p *Publisher) SetCrawlers(c *Crawlers) {
	p.crawlersMu.Lock()
	defer p.crawlersMu.Unlock()
	p.crawlers = c
}

// crawlerConfig turns the current ranges into what the data plane reads.
func (p *Publisher) crawlerConfig() map[string]luaCrawler {
	p.crawlersMu.RLock()
	c := p.crawlers
	p.crawlersMu.RUnlock()
	if c == nil {
		return nil
	}
	ua := c.UAFor()
	out := map[string]luaCrawler{}
	for name, prefixes := range c.Ranges() {
		if len(prefixes) == 0 {
			continue
		}
		out[name] = luaCrawler{UA: ua[name], Prefixes: prefixes}
	}
	return out
}

func (p *Publisher) Version() int64 {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.version
}

// Publish reads the whole configuration from the database, pushes it to Redis for
// the Lua engine, rewrites the nginx files and tells the data plane to reload now.
// Call it after every admin change.
func (p *Publisher) Publish(ctx context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	settings, err := p.db.GetSettings(ctx)
	if err != nil {
		return fmt.Errorf("reading settings: %w", err)
	}
	sites, err := p.db.ListSites(ctx)
	if err != nil {
		return fmt.Errorf("reading sites: %w", err)
	}
	rules, err := p.db.ListRules(ctx)
	if err != nil {
		return fmt.Errorf("reading rules: %w", err)
	}
	blacks, err := p.db.ListIPs(ctx, "black")
	if err != nil {
		return fmt.Errorf("reading the blocklist: %w", err)
	}
	whites, err := p.db.ListIPs(ctx, "white")
	if err != nil {
		return fmt.Errorf("reading the allowlist: %w", err)
	}

	cfg := luaConfig{
		Version:       time.Now().UnixMilli(),
		InternalToken: p.cfg.InternalToken,
		Settings:      settings,
		Sites:         map[string]luaSite{},
		Rules:         make([]luaRule, 0, len(rules)),
		Blacklist:     make([]string, 0, len(blacks)),
		Whitelist:     make([]string, 0, len(whites)),
		Crawlers:      p.crawlerConfig(),
	}

	for _, s := range sites {
		if !s.Enabled {
			continue
		}
		cfg.Sites[s.ID] = luaSite{
			ID: s.ID, Name: s.Name, Mode: s.Mode, Challenge: s.Challenge,
			RateRPS: s.RateRPS, RateBurst: s.RateBurst, FloodRPS: s.FloodRPS,
			RulesOff: s.RulesOff,
		}
	}
	for _, r := range rules {
		if !r.Enabled {
			continue
		}
		cfg.Rules = append(cfg.Rules, luaRule{
			ID: r.ID, Name: r.Name, Target: r.Target, Pattern: r.Pattern,
			Action: r.Action, Severity: r.Severity, Enabled: true,
		})
	}
	for _, e := range blacks {
		cfg.Blacklist = append(cfg.Blacklist, e.CIDR)
	}
	for _, e := range whites {
		cfg.Whitelist = append(cfg.Whitelist, e.CIDR)
	}

	raw, err := json.Marshal(cfg)
	if err != nil {
		return err
	}
	if err := p.rdb.Set(ctx, configKey, raw, 0).Err(); err != nil {
		return fmt.Errorf("publishing the config to redis: %w", err)
	}

	if err := WriteSiteConfigs(sites, p.cfg.SitesDir, SiteRender{
		CertsDir:  p.cfg.CertsDir,
		HTTPPort:  p.cfg.SiteHTTPPort,
		HTTPSPort: p.cfg.SiteHTTPSPort,
	}); err != nil {
		return fmt.Errorf("writing the nginx config: %w", err)
	}

	p.version = cfg.Version
	p.notifyProxy()
	return nil
}

// notifyProxy nudges the data plane to load the config immediately instead of waiting
// for the 3 second poll. A failure here is not serious: the timer will catch up.
func (p *Publisher) notifyProxy() {
	if p.cfg.ProxySync == "" {
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.cfg.ProxySync, nil)
		if err != nil {
			return
		}
		if p.cfg.InternalToken != "" {
			req.Header.Set("X-MosWAF-Token", p.cfg.InternalToken)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			log.Printf("moswaf: could not call the data plane /sync (%v), falling back to the poll", err)
			return
		}
		_ = resp.Body.Close()
	}()
}
