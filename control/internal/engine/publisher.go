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
	Version   int64              `json:"version"`
	Settings  store.Settings     `json:"settings"`
	Sites     map[string]luaSite `json:"sites"`
	Rules     []luaRule          `json:"rules"`
	Blacklist []string           `json:"blacklist"`
	Whitelist []string           `json:"whitelist"`
}

type Publisher struct {
	db  *store.Store
	rdb *redis.Client
	cfg *config.Config

	mu      sync.Mutex
	version int64
}

func NewPublisher(db *store.Store, rdb *redis.Client, cfg *config.Config) *Publisher {
	return &Publisher{db: db, rdb: rdb, cfg: cfg}
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
		Version:   time.Now().UnixMilli(),
		Settings:  settings,
		Sites:     map[string]luaSite{},
		Rules:     make([]luaRule, 0, len(rules)),
		Blacklist: make([]string, 0, len(blacks)),
		Whitelist: make([]string, 0, len(whites)),
	}

	for _, s := range sites {
		if !s.Enabled {
			continue
		}
		cfg.Sites[s.ID] = luaSite{
			ID: s.ID, Name: s.Name, Mode: s.Mode, Challenge: s.Challenge,
			RateRPS: s.RateRPS, RateBurst: s.RateBurst, RulesOff: s.RulesOff,
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
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			log.Printf("moswaf: could not call the data plane /sync (%v), falling back to the poll", err)
			return
		}
		_ = resp.Body.Close()
	}()
}
