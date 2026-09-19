// moswaf-kbans asks the host kernel to discard packets from addresses the WAF
// has already banned and which are still knocking.
//
// It runs on the host rather than in a container, because nftables belongs to the
// host's kernel and the proxy lives in a network namespace of its own. That means
// it is the one piece of MosWAF with the power to make the machine unreachable,
// so the shape of this program is mostly about refusing to use that power:
//
//	it will not start without being told which addresses administer the machine
//	it refuses to drop those, and every address no stranger can arrive from
//	it touches one nftables table and never any other
//	every element it adds carries the kernel's own expiry, so a dead agent
//	  leaves rules that drain rather than rules that stay
//	when anything goes wrong it does nothing, which leaves the WAF exactly where
//	  it was: refusing these addresses in userspace, more slowly
//
// None of that makes it safe to be careless with. It makes it survivable.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/netip"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/redis/go-redis/v9"
)

type config struct {
	redisAddr     string
	redisPassword string
	redisDB       int

	// Where the complete ban list is read for the periodic reconcile. The feed is
	// the fast path; this is the one that repairs anything the feed lost.
	bansURL       string
	internalToken string

	management []string
	docker     []string

	resyncEvery time.Duration
	maxElements int
	dryRun      bool
}

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func loadConfig() config {
	db, _ := strconv.Atoi(env("MOSWAF_KBANS_REDIS_DB", "0"))
	resync, err := time.ParseDuration(env("MOSWAF_KBANS_RESYNC", "60s"))
	if err != nil || resync < 10*time.Second {
		// Faster than this and the reconcile is reading the whole ban list often
		// enough to be its own load; the feed already covers latency.
		resync = 60 * time.Second
	}
	maxEl, _ := strconv.Atoi(env("MOSWAF_KBANS_MAX_ELEMENTS", "262144"))

	return config{
		redisAddr:     env("MOSWAF_KBANS_REDIS", "127.0.0.1:6379"),
		redisPassword: os.Getenv("MOSWAF_KBANS_REDIS_PASSWORD"),
		redisDB:       db,
		bansURL:       env("MOSWAF_KBANS_BANS_URL", "http://127.0.0.1:8081/bans?limit=0"),
		internalToken: os.Getenv("MOSWAF_INTERNAL_TOKEN"),
		management:    strings.Split(env("MOSWAF_KBANS_ALLOW", ""), ","),
		docker:        strings.Split(env("MOSWAF_KBANS_DOCKER_SUBNETS", "172.17.0.0/16,172.18.0.0/16"), ","),
		resyncEvery:   resync,
		maxElements:   maxEl,
		// Prints what it would do and touches nothing. The first thing to run on a
		// machine somebody cares about.
		dryRun: os.Getenv("MOSWAF_KBANS_DRY_RUN") == "1",
	}
}

type banEvent struct {
	Op     string `json:"op"`
	IP     string `json:"ip"`
	TTL    int    `json:"ttl"`
	Reason string `json:"reason"`
	TS     int64  `json:"ts"`
}

func main() {
	log.SetFlags(log.LstdFlags)
	cfg := loadConfig()

	nd, err := newNeverDrop(cfg.management, cfg.docker)
	if err != nil {
		// Refused at start, while somebody is watching, rather than at three in the
		// morning during the flood this was installed for.
		log.Fatalf("moswaf-kbans: %v", err)
	}
	log.Printf("moswaf-kbans: these will never be dropped: %s",
		strings.Join(nd.management, ", "))

	nft := &nftables{dryRun: cfg.dryRun, maxElements: cfg.maxElements}
	if err := nft.ensureTable(); err != nil {
		log.Fatalf("moswaf-kbans: could not set up the nftables table: %v", err)
	}
	if cfg.dryRun {
		log.Printf("moswaf-kbans: dry run - nothing will actually be dropped")
	}

	rdb := redis.NewClient(&redis.Options{
		Addr: cfg.redisAddr, Password: cfg.redisPassword, DB: cfg.redisDB,
	})
	defer rdb.Close()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	a := &agent{cfg: cfg, nd: nd, nft: nft, rdb: rdb}

	go a.reconcileLoop(ctx)
	a.consumeLoop(ctx)

	log.Printf("moswaf-kbans: stopping. Existing kernel entries will expire on " +
		"their own timeouts; nothing is left behind that needs removing.")
}

type agent struct {
	cfg config
	nd  *neverDrop
	nft *nftables
	rdb *redis.Client
}

// consumeLoop is the low-latency path: one event, one kernel change.
func (a *agent) consumeLoop(ctx context.Context) {
	for {
		if ctx.Err() != nil {
			return
		}
		res, err := a.rdb.BLPop(ctx, 5*time.Second, "moswaf:ban_events").Result()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			if err != redis.Nil {
				// Nothing is retried into a tight loop: a Redis that is down stays
				// down for a while, and hammering it helps nobody. The reconcile
				// below repairs whatever was missed once it comes back.
				log.Printf("moswaf-kbans: cannot read the ban feed: %v", err)
				time.Sleep(3 * time.Second)
			}
			continue
		}
		if len(res) < 2 {
			continue
		}
		a.apply(ctx, res[1])
	}
}

func (a *agent) apply(ctx context.Context, raw string) {
	var ev banEvent
	if err := json.Unmarshal([]byte(raw), &ev); err != nil {
		log.Printf("moswaf-kbans: ignoring an unreadable event: %v", err)
		return
	}

	// Checked before the address is parsed, because this one has no address. A
	// switch that parsed first would reject the event that clears everything.
	if ev.Op == "release_all" {
		if err := a.nft.flush(); err != nil {
			log.Printf("moswaf-kbans: could not release every address: %v", err)
			return
		}
		a.forgetAll(ctx)
		log.Printf("moswaf-kbans: released every address in the kernel")
		return
	}

	addr, err := netip.ParseAddr(strings.TrimSpace(ev.IP))
	if err != nil {
		log.Printf("moswaf-kbans: ignoring an event for %q, which is not an address", ev.IP)
		return
	}
	addr = addr.Unmap()

	switch ev.Op {
	case "drop":
		a.drop(ctx, addr, ev.TTL)
	case "release":
		// A release has to beat a drop that has not been applied yet, not only one
		// that has. Otherwise the reconcile a moment later re-adds a rule for an
		// address somebody has just let go, and the dashboard shows it released
		// while the packets are still being discarded.
		if err := a.nft.remove(addr); err != nil {
			log.Printf("moswaf-kbans: could not release %s: %v", addr, err)
			return
		}
		a.forget(ctx, addr)
	default:
		log.Printf("moswaf-kbans: ignoring an event of unknown kind %q", ev.Op)
	}
}

func (a *agent) drop(ctx context.Context, addr netip.Addr, ttl int) {
	if ttl <= 0 {
		return
	}
	if refusedBy, why := a.nd.covers(addr); refusedBy {
		// Loud, because somebody is going to have to explain why a ban did not
		// take effect, and this is the answer.
		log.Printf("moswaf-kbans: REFUSING to drop %s - it is covered by %s", addr, why)
		// And recorded, so the explanation reaches the dashboard rather than only
		// this log. An escalation that is never going to happen must not read as
		// one that has not happened yet: the first is a decision, the second is a
		// fault, and the person looking at the screen is trying to tell them apart.
		a.noteRefused(ctx, addr, why)
		return
	}
	if err := a.nft.add(addr, ttl); err != nil {
		log.Printf("moswaf-kbans: could not drop %s: %v", addr, err)
		return
	}
	// Published now rather than at the next reconcile. The minute in between is
	// exactly when somebody is watching to see whether the escalation worked.
	a.noteApplied(ctx, addr)
}

// reconcileLoop is the correctness backstop.
//
// The feed is destructive: an event read while the kernel call fails, or read by
// an agent that then restarts, is gone. Reading the whole ban list on a timer is
// what makes that survivable - anything the feed lost is repaired within a
// minute, and anything the kernel holds that is no longer banned is removed.
func (a *agent) reconcileLoop(ctx context.Context) {
	t := time.NewTicker(a.cfg.resyncEvery)
	defer t.Stop()

	a.reconcile(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			a.reconcile(ctx)
		}
	}
}

func (a *agent) reconcile(ctx context.Context) {
	bans, err := fetchBans(ctx, a.cfg.bansURL, a.cfg.internalToken)
	if err != nil {
		// Leaves the kernel exactly as it is. Removing everything because the list
		// could not be read would turn a lost connection into a lifted ban on every
		// address at once - during a flood, that is the worst possible moment.
		log.Printf("moswaf-kbans: skipping this reconcile, the ban list could not "+
			"be read: %v", err)
		a.reportHealth(ctx, -1)
		return
	}

	want := map[netip.Addr]int{}
	for _, b := range bans {
		addr, err := netip.ParseAddr(strings.TrimSpace(b.IP))
		if err != nil || b.TTL <= 0 {
			continue
		}
		addr = addr.Unmap()
		if refused, _ := a.nd.covers(addr); refused {
			continue
		}
		want[addr] = b.TTL
	}

	have, err := a.nft.list()
	if err != nil {
		log.Printf("moswaf-kbans: could not read the kernel set: %v", err)
		a.reportHealth(ctx, -1)
		return
	}

	added, removed := 0, 0
	for addr, ttl := range want {
		// Re-added even when present: that refreshes the kernel's own timeout, so
		// a ban that was extended is extended here too.
		if err := a.nft.add(addr, ttl); err != nil {
			log.Printf("moswaf-kbans: could not drop %s: %v", addr, err)
			continue
		}
		if _, ok := have[addr]; !ok {
			added++
		}
	}
	for addr := range have {
		if _, ok := want[addr]; !ok {
			if err := a.nft.remove(addr); err != nil {
				log.Printf("moswaf-kbans: could not release %s: %v", addr, err)
				continue
			}
			removed++
		}
	}

	if added > 0 || removed > 0 {
		log.Printf("moswaf-kbans: reconciled - %d added, %d released, %d in the kernel",
			added, removed, len(want))
	}

	// Read back rather than assumed.
	//
	// What gets published has to be what the kernel holds, not what this function
	// meant to put there. Those two agree on every ordinary cycle and differ
	// exactly when an add or a remove failed - which is the only cycle where
	// anybody reads the dashboard to find out what happened.
	final, err := a.nft.list()
	if err != nil {
		log.Printf("moswaf-kbans: could not read the kernel set back: %v", err)
		a.reportHealth(ctx, -1)
		return
	}

	applied := make(map[netip.Addr]int, len(final))
	var orphans []netip.Addr
	for addr := range final {
		if ttl, ok := want[addr]; ok {
			applied[addr] = ttl
			continue
		}
		// In the kernel with nothing banned behind it. The removal above tried and
		// did not succeed, so this address is being refused for a reason the ban
		// list cannot explain - which is worth saying out loud rather than leaving
		// somebody to discover by not being able to reach the site.
		applied[addr] = 0
		orphans = append(orphans, addr)
	}
	if len(orphans) > 0 {
		log.Printf("moswaf-kbans: %d address(es) are still dropped in the kernel "+
			"with no matching ban; they will be retried next cycle", len(orphans))
	}
	a.publishState(ctx, applied, orphans)
	a.reportHealth(ctx, len(applied))
}

// reportHealth writes what the dashboard reads to answer "is escalation working
// at all".
//
// Written on every reconcile, including the ones that failed - with a count of
// -1, so that "tried and could not" is distinguishable from "has not tried". A
// dashboard that could not tell those apart would show an agent that has been
// failing for an hour exactly like one that started a second ago.
func (a *agent) reportHealth(ctx context.Context, applied int) {
	now := time.Now()
	err := a.rdb.HSet(ctx, keyHealth,
		"seen_at", now.UTC().Format(time.RFC3339),
		// The same moment as an integer. seen_at is for people; this is for the
		// arithmetic that decides whether the agent is alive, and doing that
		// arithmetic on a formatted date would put timezone parsing in the path of
		// answering "is this machine protected".
		"seen_unix", now.Unix(),
		"applied", applied,
		"resync_every", int(a.cfg.resyncEvery/time.Second),
	).Err()
	if err != nil {
		log.Printf("moswaf-kbans: could not report health: %v", err)
		return
	}
	// Expires at a few times the reconcile interval, so a dead agent stops being
	// reported as present rather than leaving its last word there forever.
	a.rdb.Expire(ctx, keyHealth, a.expiry())
}

func init() {
	// Keeps the log readable when the agent is doing nothing, which is most of
	// the time on a healthy machine.
	log.SetPrefix("")
	_ = fmt.Sprint
}
