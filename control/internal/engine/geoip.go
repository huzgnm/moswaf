package engine

import (
	"bufio"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"
)

// Which country an address belongs to, for the attack log.
//
// Looked up here and not in the data plane, deliberately. Seven hundred thousand
// ranges would have to live in shared memory and every request would pay for a
// search, to answer a question no blocking decision depends on: geography is
// reporting. Attack events already pass through the control plane on their way
// to the database, which is one lookup per recorded event rather than one per
// request - on an ordinary site, a difference of several orders of magnitude.
//
// The data is DB-IP Lite, which is free to download without an account. Its
// licence (CC BY 4.0) requires attribution, which the dashboard carries next to
// the figures it produces.

const (
	// The CSV is about four megabytes compressed and expands to some seventy.
	// Bounded so that a redirected or replaced download cannot exhaust memory.
	geoMaxDownload = 32 << 20
	geoTimeout     = 3 * time.Minute

	// DB-IP publish a new file monthly and keep the previous ones, so a daily
	// check finds the new one shortly after it appears without asking often.
	geoCheckEvery = 24 * time.Hour
)

type geoRange4 struct {
	lo, hi uint32
	cc     [2]byte
}

type geoRange6 struct {
	loHi, loLo uint64
	hiHi, hiLo uint64
	cc         [2]byte
}

// GeoIP answers "which country" for an address.
type GeoIP struct {
	mu     sync.RWMutex
	v4     []geoRange4
	v6     []geoRange6
	month  string // the dataset currently loaded, e.g. "2026-09"
	loaded time.Time
	err    string

	client *http.Client
}

func NewGeoIP() *GeoIP {
	return &GeoIP{client: &http.Client{Timeout: geoTimeout}}
}

// Status is what the dashboard reports about the dataset.
type GeoStatus struct {
	Ranges    int        `json:"ranges"`
	Month     string     `json:"month,omitempty"`
	LoadedAt  *time.Time `json:"loaded_at,omitempty"`
	LastError string     `json:"last_error,omitempty"`
}

func (g *GeoIP) Status() GeoStatus {
	g.mu.RLock()
	defer g.mu.RUnlock()
	st := GeoStatus{Ranges: len(g.v4) + len(g.v6), Month: g.month, LastError: g.err}
	if !g.loaded.IsZero() {
		t := g.loaded
		st.LoadedAt = &t
	}
	return st
}

// Lookup returns a two-letter country code, or "" when the address is not in the
// data or no data is loaded.
//
// "" is a normal answer, not a failure: the dataset does not cover every address,
// private ranges have no country, and an installation with no route to the
// internet has no dataset at all. Everything downstream treats it as unknown.
func (g *GeoIP) Lookup(ip string) string {
	addr, err := netip.ParseAddr(strings.TrimSpace(ip))
	if err != nil {
		return ""
	}
	// An IPv4 address written as IPv6 is an IPv4 address, and the IPv4 table is
	// the one that has it - the same folding the data plane does for its lists.
	addr = addr.Unmap()

	g.mu.RLock()
	defer g.mu.RUnlock()

	if addr.Is4() {
		n := be32(addr.As4())
		i := sort.Search(len(g.v4), func(i int) bool { return g.v4[i].hi >= n })
		if i < len(g.v4) && g.v4[i].lo <= n {
			return known(string(g.v4[i].cc[:]))
		}
		return ""
	}

	hi, lo := be64pair(addr.As16())
	i := sort.Search(len(g.v6), func(i int) bool {
		return g.v6[i].hiHi > hi || (g.v6[i].hiHi == hi && g.v6[i].hiLo >= lo)
	})
	if i < len(g.v6) {
		r := g.v6[i]
		if r.loHi < hi || (r.loHi == hi && r.loLo <= lo) {
			return known(string(r.cc[:]))
		}
	}
	return ""
}

// ZZ is how the dataset spells "not a country" - reserved blocks, documentation
// ranges, anything unallocated. Reporting it as a country would put a row on the
// dashboard labelled with a code no map has, above real countries with fewer
// attacks. Unknown is already how this answers when it has no idea, so it says
// that instead.
func known(cc string) string {
	if cc == "ZZ" {
		return ""
	}
	return cc
}

func be32(b [4]byte) uint32 {
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}

func be64pair(b [16]byte) (hi, lo uint64) {
	for i := 0; i < 8; i++ {
		hi = hi<<8 | uint64(b[i])
		lo = lo<<8 | uint64(b[i+8])
	}
	return hi, lo
}

// parseCSV reads "start,end,CC" lines into the two sorted tables.
//
// Malformed lines are skipped rather than fatal. The file is seven hundred
// thousand lines from a third party; refusing the whole dataset over one bad row
// would trade all of the reporting for none of it, and nothing here makes a
// security decision.
func parseCSV(r io.Reader) ([]geoRange4, []geoRange6, error) {
	var (
		v4      []geoRange4
		v6      []geoRange6
		skipped int
	)

	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	for sc.Scan() {
		line := sc.Text()
		a := strings.IndexByte(line, ',')
		if a < 0 {
			skipped++
			continue
		}
		b := strings.IndexByte(line[a+1:], ',')
		if b < 0 {
			skipped++
			continue
		}
		startS, endS := line[:a], line[a+1:a+1+b]
		ccS := strings.TrimSpace(line[a+b+2:])
		if len(ccS) != 2 {
			skipped++
			continue
		}

		start, err1 := netip.ParseAddr(startS)
		end, err2 := netip.ParseAddr(endS)
		if err1 != nil || err2 != nil || start.Is4() != end.Is4() {
			skipped++
			continue
		}

		var cc [2]byte
		cc[0], cc[1] = ccS[0], ccS[1]

		if start.Is4() {
			v4 = append(v4, geoRange4{lo: be32(start.As4()), hi: be32(end.As4()), cc: cc})
		} else {
			loHi, loLo := be64pair(start.As16())
			hiHi, hiLo := be64pair(end.As16())
			v6 = append(v6, geoRange6{loHi: loHi, loLo: loLo, hiHi: hiHi, hiLo: hiLo, cc: cc})
		}
	}
	if err := sc.Err(); err != nil {
		return nil, nil, err
	}
	if len(v4) == 0 && len(v6) == 0 {
		return nil, nil, fmt.Errorf("no usable ranges in the dataset")
	}
	if skipped > 0 {
		log.Printf("moswaf: skipped %d unreadable rows in the geolocation dataset", skipped)
	}

	// The lookup is a binary search, so the tables have to be ordered by their
	// upper bound whatever order the file arrived in.
	sort.Slice(v4, func(i, j int) bool { return v4[i].hi < v4[j].hi })
	sort.Slice(v6, func(i, j int) bool {
		if v6[i].hiHi != v6[j].hiHi {
			return v6[i].hiHi < v6[j].hiHi
		}
		return v6[i].hiLo < v6[j].hiLo
	})
	return v4, v6, nil
}

func geoURL(month string) string {
	return "https://download.db-ip.com/free/dbip-country-lite-" + month + ".csv.gz"
}

// fetch downloads and parses one month's dataset.
func (g *GeoIP) fetch(ctx context.Context, month string) ([]geoRange4, []geoRange6, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, geoURL(month), nil)
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("User-Agent", "MosWAF")

	res, err := g.client.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return nil, nil, fmt.Errorf("%s answered %d", geoURL(month), res.StatusCode)
	}

	gz, err := gzip.NewReader(io.LimitReader(res.Body, geoMaxDownload))
	if err != nil {
		return nil, nil, fmt.Errorf("the dataset is not gzip: %w", err)
	}
	defer gz.Close()

	return parseCSV(io.LimitReader(gz, geoMaxDownload*8))
}

// Refresh loads the newest dataset available, this month's or last month's.
//
// The current month's file does not exist until DB-IP publish it, so a check on
// the first of the month would fail and leave an installation with nothing.
// Falling back one month means the answer is at most a few weeks old, which for
// country-level geography is not a meaningful difference.
func (g *GeoIP) Refresh(ctx context.Context) {
	now := time.Now().UTC()
	months := []string{now.Format("2006-01"), now.AddDate(0, -1, 0).Format("2006-01")}

	g.mu.RLock()
	have := g.month
	g.mu.RUnlock()
	if have == months[0] {
		return // already on the newest there can be
	}

	var lastErr error
	for _, m := range months {
		v4, v6, err := g.fetch(ctx, m)
		if err != nil {
			lastErr = err
			continue
		}
		g.mu.Lock()
		g.v4, g.v6, g.month, g.loaded, g.err = v4, v6, m, time.Now().UTC(), ""
		g.mu.Unlock()
		log.Printf("moswaf: geolocation dataset %s loaded (%d ranges)", m, len(v4)+len(v6))
		return
	}

	// Keep whatever is already loaded. An older dataset answers nearly every
	// address correctly; no dataset answers none.
	g.mu.Lock()
	g.err = lastErr.Error()
	g.mu.Unlock()
	log.Printf("moswaf: could not refresh the geolocation dataset: %v", lastErr)
}

// Start refreshes in the background until the context is cancelled.
func (g *GeoIP) Start(ctx context.Context) {
	go func() {
		// A minute in: this is a several-megabyte download and nothing waits on it,
		// so it should not compete with the rest of the boot.
		timer := time.NewTimer(time.Minute)
		defer timer.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-timer.C:
			}
			g.Refresh(ctx)
			timer.Reset(geoCheckEvery)
		}
	}()
}
