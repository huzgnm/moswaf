package engine

import (
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"sync"
	"time"
)

// Published crawler address ranges.
//
// Search engines publish the addresses their crawlers use, so a crawler can be
// recognised by where it came from rather than by what it says it is. A
// User-Agent is a string anyone can type; an address inside Google's published
// range is not.
//
// This fetches those lists, checks them, and hands them to the data plane. What
// it never does is resolve DNS per request, which is the other way to answer
// this question and brings a per-address cache to poison and a network round
// trip into the path of every request that claims to be a crawler.

//go:embed crawlers.json
var bundledCrawlers []byte

// How long a fetch may take and how much of it will be read.
//
// A source that has been compromised or intercepted can answer slowly and
// forever, or answer with gigabytes. Neither should be able to hold the control
// plane or exhaust its memory, and the real documents are tens of kilobytes.
const (
	crawlerFetchTimeout = 20 * time.Second
	crawlerMaxBody      = 4 << 20 // 4 MB
	crawlerRefreshEvery = 12 * time.Hour
)

// CrawlerSource is one operator's published list.
type CrawlerSource struct {
	Name string // matched against the User-Agent
	URL  string
	UA   string // substring that identifies the claim, case-insensitive
}

// The sources shipped by default. HTTPS in every case, and the certificate is
// validated - the whole point is that the answer comes from who it says it does.
var defaultCrawlerSources = []CrawlerSource{
	{Name: "googlebot", UA: "googlebot",
		URL: "https://developers.google.com/static/crawling/ipranges/common-crawlers.json"},
	{Name: "google-special", UA: "google",
		URL: "https://developers.google.com/static/crawling/ipranges/special-crawlers.json"},
	{Name: "bingbot", UA: "bingbot",
		URL: "https://www.bing.com/toolbox/bingbot.json"},
	{Name: "applebot", UA: "applebot",
		URL: "https://search.developer.apple.com/applebot.json"},
}

// The shape all four publish: a list of objects each carrying one prefix.
type publishedRanges struct {
	Prefixes []struct {
		IPv4 string `json:"ipv4Prefix"`
		IPv6 string `json:"ipv6Prefix"`
	} `json:"prefixes"`
}

// Crawlers holds the current lists and refreshes them in the background.
type Crawlers struct {
	mu      sync.RWMutex
	current map[string][]string // crawler name -> validated prefixes
	client  *http.Client
	sources []CrawlerSource
}

func NewCrawlers() *Crawlers {
	c := &Crawlers{
		current: map[string][]string{},
		sources: defaultCrawlerSources,
		client: &http.Client{
			Timeout: crawlerFetchTimeout,
			// Redirects are followed by default, which is fine: each hop is still
			// HTTPS with a validated certificate, and the body is checked either way.
		},
	}
	c.loadBundled()
	return c
}

// loadBundled seeds the lists from the snapshot compiled into the binary.
//
// This is what an installation with no route to the internet runs on, and what
// every installation runs on for the first few seconds. Without it a machine
// behind a firewall would verify no crawler at all, which means every search
// engine gets challenged the moment the site is under attack - losing search
// traffic at exactly the moment the site is already in trouble.
//
// The snapshot goes through the same validation as a fetched list. Shipping
// inside the repository is a reason to trust the pipeline, not a reason to skip
// the check: a fork, a bad merge or a tampered release all arrive that way.
func (c *Crawlers) loadBundled() {
	var bundled map[string][]string
	if err := json.Unmarshal(bundledCrawlers, &bundled); err != nil {
		log.Printf("moswaf: the bundled crawler ranges are unreadable: %v", err)
		return
	}
	for name, prefixes := range bundled {
		good, rejected, err := ValidateRanges(name, prefixes)
		if err != nil {
			log.Printf("moswaf: the bundled ranges for %s were refused: %v", name, err)
			continue
		}
		for _, r := range rejected {
			log.Printf("moswaf: bundled %s: %s", name, r)
		}
		c.current[name] = good
	}
}

// Ranges returns a copy of the current lists.
func (c *Crawlers) Ranges() map[string][]string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := make(map[string][]string, len(c.current))
	for k, v := range c.current {
		out[k] = append([]string(nil), v...)
	}
	return out
}

// UAFor returns the User-Agent substring that goes with each list.
func (c *Crawlers) UAFor() map[string]string {
	out := make(map[string]string, len(c.sources))
	for _, s := range c.sources {
		out[s.Name] = s.UA
	}
	return out
}

// fetchOne retrieves and validates a single source.
func (c *Crawlers) fetchOne(ctx context.Context, src CrawlerSource) ([]string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, src.URL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "MosWAF")

	res, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s answered %d", src.URL, res.StatusCode)
	}

	// Bounded: a source that has been taken over can answer with as much as it
	// likes, and reading all of it is the easy way to lose the control plane.
	body, err := io.ReadAll(io.LimitReader(res.Body, crawlerMaxBody+1))
	if err != nil {
		return nil, err
	}
	if len(body) > crawlerMaxBody {
		return nil, fmt.Errorf("%s answered with more than %d bytes", src.URL, crawlerMaxBody)
	}

	var doc publishedRanges
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("%s did not answer with a range list: %w", src.URL, err)
	}

	raw := make([]string, 0, len(doc.Prefixes))
	for _, p := range doc.Prefixes {
		if p.IPv4 != "" {
			raw = append(raw, p.IPv4)
		}
		if p.IPv6 != "" {
			raw = append(raw, p.IPv6)
		}
	}

	good, rejected, err := ValidateRanges(src.Name, raw)
	if err != nil {
		return nil, err
	}
	for _, r := range rejected {
		log.Printf("moswaf: %s: dropped a range: %s", src.Name, r)
	}
	return good, nil
}

// Refresh pulls every source once. A source that fails keeps the list it had.
//
// Never falling back to an empty list is the point. Empty means nothing is
// recognised as a crawler, which means every search engine is challenged the
// next time the site is under attack. A stale list is a far smaller problem than
// that: the worst it can do is fail to recognise an address a crawler started
// using recently, or keep recognising one it stopped using - and the only thing
// recognition grants is an exemption from the challenge.
func (c *Crawlers) Refresh(ctx context.Context) {
	for _, src := range c.sources {
		good, err := c.fetchOne(ctx, src)
		if err != nil {
			log.Printf("moswaf: keeping the previous ranges for %s: %v", src.Name, err)
			continue
		}
		c.mu.Lock()
		before := len(c.current[src.Name])
		c.current[src.Name] = good
		c.mu.Unlock()
		if before != len(good) {
			log.Printf("moswaf: %s now publishes %d ranges (was %d)", src.Name, len(good), before)
		}
	}
}

// Start refreshes on a timer until the context is cancelled.
func (c *Crawlers) Start(ctx context.Context, after func()) {
	go func() {
		// A short delay first: the bundled snapshot is already in use, so there is
		// nothing to wait for, and starting every installation with an outbound
		// request at the same moment as the rest of the boot helps nobody.
		timer := time.NewTimer(30 * time.Second)
		defer timer.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-timer.C:
			}
			c.Refresh(ctx)
			if after != nil {
				after()
			}
			timer.Reset(crawlerRefreshEvery)
		}
	}()
}
