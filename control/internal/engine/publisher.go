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

	// The login gate. AuthUsers maps account id to its current session generation,
	// and it is the whole of what the data plane needs to check a session: the
	// account being absent refuses its cookies, and the number not matching refuses
	// the ones issued before it changed.
	//
	// Carried in the configuration rather than looked up because it is consulted on
	// every request to a gated site. A database round trip there would put the
	// control plane in the path of ordinary traffic - the one place this design
	// keeps it out of.
	AuthEnabled bool            `json:"auth_enabled"`
	AuthPaths   []string        `json:"auth_paths"`
	AuthUsers   map[int64]int64 `json:"auth_users"`

	// The country rule in force here, already resolved: a site that follows the
	// global rule is published carrying the global rule, not a marker saying to go
	// and look it up. The data plane reads one field and decides; working out which
	// rule applies is done once per publish rather than once per request.
	GeoMode string `json:"geo_mode"`
	GeoSet  string `json:"geo_set"`
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

	// Address ranges for the country rules in use, keyed by the sorted country
	// list. Only the countries somebody is actually deciding on appear here - a
	// rule blocking two countries ships those two, not the whole world.
	GeoSets map[string]GeoSet `json:"geo_sets"`

	// The operator's own ordered rules, already sorted, already scoped, and with
	// each country condition pointing at the set it is decided against. Sorting
	// here rather than there is not an optimisation: order is the policy, and
	// leaving the data plane to establish it every request would be leaving it
	// somewhere it can differ between workers.
	AccessRules []luaAccessRule `json:"access_rules"`
}

type luaAccessRule struct {
	ID         string             `json:"id"`
	Name       string             `json:"name"`
	Action     string             `json:"action"`
	Enabled    bool               `json:"enabled"`
	Site       string             `json:"site"`
	Conditions []luaRuleCondition `json:"conditions"`
}

type luaRuleCondition struct {
	Field  string   `json:"field"`
	Op     string   `json:"op"`
	Values []string `json:"values"`
	// For a country condition: which published geo set answers it. Empty when the
	// ranges could not be built, and the data plane treats that as "does not
	// match" rather than guessing.
	Set string `json:"set,omitempty"`
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

	// The geolocation dataset, for building country rules. Optional and guarded the
	// same way as the crawler ranges, and for the same reason: Publish holds mu for
	// its whole body and reads this from inside it.
	geoMu sync.RWMutex
	geo   *GeoIP

	mu      sync.Mutex
	version int64
}

func NewPublisher(db *store.Store, rdb *redis.Client, cfg *config.Config) *Publisher {
	return &Publisher{db: db, rdb: rdb, cfg: cfg}
}

// SetGeoIP attaches the geolocation dataset. Without one, every country rule is
// published as off - the direction that keeps sites serving.
func (p *Publisher) SetGeoIP(g *GeoIP) {
	p.geoMu.Lock()
	defer p.geoMu.Unlock()
	p.geo = g
}

func (p *Publisher) geoIP() *GeoIP {
	p.geoMu.RLock()
	defer p.geoMu.RUnlock()
	return p.geo
}

func (p *Publisher) SetCrawlers(c *Crawlers) {
	p.crawlersMu.Lock()
	defer p.crawlersMu.Unlock()
	p.crawlers = c
}

// CrawlerStatus reports where each crawler list came from, for the dashboard.
func (p *Publisher) CrawlerStatus() []SourceStatus {
	p.crawlersMu.RLock()
	c := p.crawlers
	p.crawlersMu.RUnlock()
	if c == nil {
		return nil
	}
	return c.Status()
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
	// An existing install can already hold a trusted list that covers everything -
	// validation runs when settings are saved, and nobody saves settings on
	// upgrade. Said out loud on every publish rather than left to be discovered,
	// because while it holds, every address the firewall decides on is a value the
	// client chose for itself.
	if settings.RealIPHeader != "" {
		for _, p := range settings.TrustedProxies {
			if p == "0.0.0.0/0" || p == "::/0" {
				log.Printf("moswaf: trusted_proxies contains %s, so any client can set "+
					"its own address through %s - bans, the blocklist and allow rules "+
					"are all keyed on that value. List your proxy's real ranges.",
					p, settings.RealIPHeader)
			} else if store.WidePublicProxyRange(p) {
				// Not refused: unlike an all-covering entry this has plausible narrow
				// uses, and being wrong about somebody's network is worse than being
				// noisy about it. But anybody inside that range can set their own
				// address, and the range is public - so somebody is inside it.
				log.Printf("moswaf: trusted_proxies contains %s, a large range of public "+
					"addresses. Every client in it can set its own address through %s; "+
					"if that is wider than your proxy really is, narrow it.",
					p, settings.RealIPHeader)
			}
		}
	}

	generations, err := p.db.SiteGenerations(ctx)
	if err != nil {
		return fmt.Errorf("reading the site accounts: %w", err)
	}

	// The country rules in force, and the ranges each needs. Built before the sites
	// loop because a rule that cannot be built has to be published as "off" rather
	// than as itself - see geoResolver.
	accessRules, err := p.db.ListAccessRules(ctx, "")
	if err != nil {
		return fmt.Errorf("reading the access rules: %w", err)
	}

	geo := p.resolveGeo(settings, sites, accessRules)

	cfg := luaConfig{
		Version:       time.Now().UnixMilli(),
		InternalToken: p.cfg.InternalToken,
		Settings:      settings,
		Sites:         map[string]luaSite{},
		Rules:         make([]luaRule, 0, len(rules)),
		Blacklist:     make([]string, 0, len(blacks)),
		Whitelist:     make([]string, 0, len(whites)),
		Crawlers:      p.crawlerConfig(),
		GeoSets:       geo.sets,
		AccessRules:   buildAccessRules(accessRules, geo),
	}

	for _, s := range sites {
		if !s.Enabled {
			continue
		}
		users := generations[s.ID]

		// The gate is published as on only when somebody can actually get through
		// it. An enabled gate with no accounts refuses every request to the site
		// with no way to satisfy it - a site taken off the air by a setting that
		// reads as a security improvement. It can be reached by deleting the last
		// account rather than by asking for it, which is why the check is here, at
		// the point of publication, and not only where the operator typed.
		enabled := s.AuthEnabled && len(users) > 0
		if s.AuthEnabled && len(users) == 0 {
			log.Printf("moswaf: the login gate on %s has no accounts, so it is not being "+
				"applied; add one or switch it off", s.Name)
		}

		geoMode, geoSet := geo.forSite(s)

		cfg.Sites[s.ID] = luaSite{
			ID: s.ID, Name: s.Name, Mode: s.Mode, Challenge: s.Challenge,
			RateRPS: s.RateRPS, RateBurst: s.RateBurst, FloodRPS: s.FloodRPS,
			RulesOff: s.RulesOff,
			// Only ever carries account ids and counters - never a hash, and never a
			// name. Whoever can read this key can already rewrite the configuration,
			// but there is no reason to widen what a leak of it costs.
			AuthEnabled: enabled,
			AuthPaths:   store.NormaliseAuthPaths(s.AuthPaths),
			AuthUsers:   users,
			GeoMode:     geoMode,
			GeoSet:      geoSet,
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
		CertsDir:        p.cfg.CertsDir,
		HTTPPort:        p.cfg.SiteHTTPPort,
		HTTPSPort:       p.cfg.SiteHTTPSPort,
		ControlInternal: p.cfg.ControlInternal,
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
