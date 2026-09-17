package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/mosvpn/moswaf/control/internal/store"
	"github.com/redis/go-redis/v9"
)

const configKey = "moswaf:config"

// Cau truc duoi day chinh la thu ma dataplane/lua/moswaf/config.lua doc.
// Doi ten truong o day thi phai doi ca ben Lua.

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
	db       *store.Store
	rdb      *redis.Client
	sitesDir string
	certsDir string
	syncURL  string

	mu      sync.Mutex
	version int64
}

func NewPublisher(db *store.Store, rdb *redis.Client, sitesDir, certsDir, syncURL string) *Publisher {
	return &Publisher{db: db, rdb: rdb, sitesDir: sitesDir, certsDir: certsDir, syncURL: syncURL}
}

func (p *Publisher) Version() int64 {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.version
}

// Publish doc toan bo cau hinh tu DB, day sang Redis cho engine Lua,
// ghi lai file nginx, roi bao data plane nap ngay.
// Goi ham nay sau moi thay doi cua admin.
func (p *Publisher) Publish(ctx context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	settings, err := p.db.GetSettings(ctx)
	if err != nil {
		return fmt.Errorf("doc settings: %w", err)
	}
	sites, err := p.db.ListSites(ctx)
	if err != nil {
		return fmt.Errorf("doc sites: %w", err)
	}
	rules, err := p.db.ListRules(ctx)
	if err != nil {
		return fmt.Errorf("doc rules: %w", err)
	}
	blacks, err := p.db.ListIPs(ctx, "black")
	if err != nil {
		return fmt.Errorf("doc blacklist: %w", err)
	}
	whites, err := p.db.ListIPs(ctx, "white")
	if err != nil {
		return fmt.Errorf("doc whitelist: %w", err)
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
		return fmt.Errorf("day config sang redis: %w", err)
	}

	if err := WriteSiteConfigs(sites, p.sitesDir, p.certsDir); err != nil {
		return fmt.Errorf("ghi cau hinh nginx: %w", err)
	}

	p.version = cfg.Version
	p.notifyProxy()
	return nil
}

// notifyProxy giuc data plane nap cau hinh ngay thay vi doi chu ky 3 giay.
// That bai o day khong phai loi nghiem trong: timer se tu keo ve sau.
func (p *Publisher) notifyProxy() {
	if p.syncURL == "" {
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.syncURL, nil)
		if err != nil {
			return
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			log.Printf("moswaf: khong goi duoc /sync cua data plane (%v), se dong bo theo chu ky", err)
			return
		}
		_ = resp.Body.Close()
	}()
}
