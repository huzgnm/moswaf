package api

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/mosvpn/moswaf/control/internal/engine"
	"github.com/mosvpn/moswaf/control/internal/store"
)

// newSiteID generates a short id that is valid both as an nginx filename and a Redis key.
func newSiteID() string {
	b := make([]byte, 5)
	_, _ = rand.Read(b)
	return "s" + hex.EncodeToString(b)
}

// publish pushes the new configuration down to the data plane. A failure here must be
// surfaced to the admin, because the change has not actually taken effect.
func (s *Server) publish(w http.ResponseWriter, r *http.Request) bool {
	if err := s.pub.Publish(r.Context()); err != nil {
		writeErr(w, http.StatusInternalServerError, "saved, but could not apply it to the data plane: "+err.Error())
		return false
	}
	return true
}

func sanitizeSite(s *store.Site) *store.Site {
	c := *s
	c.TLSKey = "" // the private key never leaves the server
	return &c
}

// --------------------------------------------------------------- sites

func (s *Server) handleListSites(w http.ResponseWriter, r *http.Request) {
	sites, err := s.db.ListSites(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	out := make([]*store.Site, 0, len(sites))
	for _, site := range sites {
		out = append(out, sanitizeSite(site))
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleGetSite(w http.ResponseWriter, r *http.Request) {
	site, err := s.db.GetSite(r.Context(), r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) {
		writeErr(w, http.StatusNotFound, "site not found")
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, sanitizeSite(site))
}

func (s *Server) handleCreateSite(w http.ResponseWriter, r *http.Request) {
	var site store.Site
	if !readJSON(w, r, &site) {
		return
	}

	site.ID = newSiteID()
	site.Enabled = true
	if site.UpstreamPort == 0 {
		site.UpstreamPort = 80
	}
	if site.UpstreamScheme == "" {
		site.UpstreamScheme = "http"
	}
	if site.Mode == "" {
		site.Mode = "protect"
	}
	if site.Challenge == "" {
		site.Challenge = "auto"
	}
	site.HasTLS = site.TLSCert != "" && site.TLSKey != ""

	if err := store.ValidateSite(&site); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.db.UpsertSite(r.Context(), &site); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !s.publish(w, r) {
		return
	}
	writeJSON(w, http.StatusCreated, sanitizeSite(&site))
}

func (s *Server) handleUpdateSite(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	cur, err := s.db.GetSite(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		writeErr(w, http.StatusNotFound, "site not found")
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}

	// Start from what is stored and let the request overlay it, the same way
	// PUT /api/settings works. Decoding into an empty struct made every omitted
	// field revert to its zero value - and for `enabled` that meant a client which
	// simply did not mention it disabled the site, whereupon WriteSiteConfigs
	// deleted the generated nginx file and every request fell through to the
	// catch-all "domain is not configured" server.
	in := *cur
	if !readJSON(w, r, &in) {
		return
	}

	in.ID = cur.ID
	in.CreatedAt = cur.CreatedAt
	// Certificate state belongs to the renewal loop, not to whoever sends the
	// request. Accepting cert_expires_at from a client let one PUT push the date
	// years out, after which NeedsCertificate sees a healthy certificate and never
	// renews - the real one then expires in silence.
	in.CertExpiresAt = cur.CertExpiresAt
	in.AcmeLastError = cur.AcmeLastError
	in.AcmeLastTry = cur.AcmeLastTry
	// The UI does not resend the private key -> keep the one already in use
	if in.TLSCert == "" && in.TLSKey == "" {
		in.TLSCert, in.TLSKey = cur.TLSCert, cur.TLSKey
	} else if in.TLSKey == "" {
		in.TLSKey = cur.TLSKey
	}
	in.HasTLS = in.TLSCert != "" && in.TLSKey != ""

	if err := store.ValidateSite(&in); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.db.UpsertSite(r.Context(), &in); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !s.publish(w, r) {
		return
	}
	writeJSON(w, http.StatusOK, sanitizeSite(&in))
}

func (s *Server) handleDeleteSite(w http.ResponseWriter, r *http.Request) {
	if err := s.db.DeleteSite(r.Context(), r.PathValue("id")); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeErr(w, http.StatusNotFound, "site not found")
			return
		}
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !s.publish(w, r) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

// handleIssueCertificate runs an ACME order for one site immediately, instead of
// waiting for the renewal sweep. Useful right after pointing DNS at the server,
// and it returns the CA's actual complaint when validation fails - which is the
// thing an operator needs to see.
func (s *Server) handleIssueCertificate(w http.ResponseWriter, r *http.Request) {
	site, err := s.db.GetSite(r.Context(), r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) {
		writeErr(w, http.StatusNotFound, "site not found")
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !site.AcmeEnabled {
		writeErr(w, http.StatusBadRequest, "automatic certificates are not enabled for this site")
		return
	}
	// Refuse when there is nothing to get.
	//
	// Every order counts against the authority's duplicate-certificate limit -
	// five a week for the same set of domains - and that limit is not the hourly
	// kind that forgives itself by lunchtime. Re-issuing a healthy certificate
	// five times, whether by a hand on the button or a script calling this
	// endpoint to "make sure", locks the domain out for a week. Nothing breaks at
	// the time: it surfaces when the certificate genuinely needs renewing and the
	// authority says no.
	//
	// Deliberately checked with CertificateWanted and not NeedsCertificate: the
	// latter also refuses during the back-off after a failure, and retrying
	// immediately after fixing DNS is exactly what this button is for.
	if want, _ := engine.CertificateWanted(site, time.Now()); !want {
		writeErr(w, http.StatusConflict,
			"this site already has a certificate that covers its domains and is not "+
				"near expiry; ordering another would count against the authority's "+
				"duplicate-certificate limit of five a week")
		return
	}
	// Each call is a real order at the authority, whose rate limits are strict and
	// counted per domain per week. The hourly back-off the sweep uses would make the
	// button useless - it exists to retry right after fixing DNS - so this is a
	// short cooldown instead of no limit at all.
	if wait := store.ManualIssueCooldown(site, time.Now()); wait > 0 {
		w.Header().Set("Retry-After", strconv.Itoa(int(wait.Seconds())+1))
		writeErr(w, http.StatusTooManyRequests, fmt.Sprintf(
			"the last attempt was less than %s ago; wait %s before asking again",
			store.ManualIssueWindow, wait.Round(time.Second)))
		return
	}

	if err := s.certifier.Issue(r.Context(), site); err != nil {
		_ = s.db.RecordACMEAttempt(r.Context(), site.ID, err.Error())
		writeErr(w, http.StatusBadGateway, "the certificate authority refused: "+err.Error())
		return
	}
	if !s.publish(w, r) {
		return
	}

	updated, err := s.db.GetSite(r.Context(), site.ID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, sanitizeSite(updated))
}

// --------------------------------------------------------------- rules

func (s *Server) handleListRules(w http.ResponseWriter, r *http.Request) {
	rules, err := s.db.ListRules(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, rules)
}

func (s *Server) handleCreateRule(w http.ResponseWriter, r *http.Request) {
	var rule store.Rule
	if !readJSON(w, r, &rule) {
		return
	}
	rule.Builtin = false
	rule.Enabled = true
	if rule.ID == "" {
		rule.ID = "custom-" + hexID(4)
	}
	if !strings.HasPrefix(rule.ID, "custom-") {
		rule.ID = "custom-" + rule.ID
	}
	if err := store.ValidateRule(&rule); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if _, err := s.db.GetRule(r.Context(), rule.ID); err == nil {
		writeErr(w, http.StatusConflict, "that rule id already exists")
		return
	}
	if err := s.db.UpsertRule(r.Context(), &rule); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !s.publish(w, r) {
		return
	}
	writeJSON(w, http.StatusCreated, rule)
}

func (s *Server) handleUpdateRule(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	cur, err := s.db.GetRule(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		writeErr(w, http.StatusNotFound, "rule not found")
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}

	var in store.Rule
	if !readJSON(w, r, &in) {
		return
	}
	in.ID = cur.ID
	in.Builtin = cur.Builtin
	if err := store.ValidateRule(&in); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.db.UpsertRule(r.Context(), &in); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !s.publish(w, r) {
		return
	}
	writeJSON(w, http.StatusOK, in)
}

func (s *Server) handleToggleRule(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Enabled bool `json:"enabled"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	if err := s.db.SetRuleEnabled(r.Context(), r.PathValue("id"), req.Enabled); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeErr(w, http.StatusNotFound, "rule not found")
			return
		}
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !s.publish(w, r) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"id": r.PathValue("id"), "enabled": req.Enabled})
}

func (s *Server) handleDeleteRule(w http.ResponseWriter, r *http.Request) {
	if err := s.db.DeleteRule(r.Context(), r.PathValue("id")); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if !s.publish(w, r) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

// --------------------------------------------------------------- IP

func (s *Server) handleListIPs(w http.ResponseWriter, r *http.Request) {
	list, err := s.db.ListIPs(r.Context(), r.URL.Query().Get("kind"))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, list)
}

func (s *Server) handleAddIP(w http.ResponseWriter, r *http.Request) {
	var req struct {
		CIDR    string `json:"cidr"`
		Kind    string `json:"kind"`
		Reason  string `json:"reason"`
		Minutes int    `json:"minutes"` // 0 = vinh vien
	}
	if !readJSON(w, r, &req) {
		return
	}
	entry, err := s.db.AddIP(r.Context(), req.CIDR, req.Kind, req.Reason,
		time.Duration(req.Minutes)*time.Minute)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if !s.publish(w, r) {
		return
	}
	writeJSON(w, http.StatusCreated, entry)
}

func (s *Server) handleDeleteIP(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid id")
		return
	}
	if err := s.db.DeleteIP(r.Context(), id); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeErr(w, http.StatusNotFound, "not found")
			return
		}
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !s.publish(w, r) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

// --------------------------------------------------------------- events

func (s *Server) handleListEvents(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f := store.EventFilter{
		Site:     q.Get("site"),
		IP:       q.Get("ip"),
		Action:   q.Get("action"),
		Severity: q.Get("severity"),
		Search:   q.Get("q"),
		Limit:    queryInt(r, "limit", 50),
		Offset:   queryInt(r, "offset", 0),
	}
	if h := queryInt(r, "hours", 0); h > 0 {
		from := time.Now().Add(-time.Duration(h) * time.Hour)
		f.From = &from
	}

	events, total, err := s.db.ListEvents(r.Context(), f)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"items":  events,
		"total":  total,
		"limit":  f.Limit,
		"offset": f.Offset,
	})
}

// --------------------------------------------------------------- thong ke

// uniqueCounts merges the per-hour HyperLogLogs the data plane writes and returns
// the number of distinct addresses and distinct visitors over the window.
//
// PFCOUNT over several keys computes the union, which is the whole reason the
// sketches exist: summing per-hour counts would count a visitor who stayed for
// three hours three times. A missing key is simply an hour with no traffic, so
// the call is not an error when some of the range has expired or never existed.
func (s *Server) uniqueCounts(ctx context.Context, hours int) (ips, visitors int64) {
	if s.rdb == nil {
		return 0, 0
	}
	// One extra hour: the window starts partway through the earliest hour, and
	// leaving it out would drop traffic the totals above do include.
	now := time.Now().Unix()
	ipKeys := make([]string, 0, hours+1)
	uvKeys := make([]string, 0, hours+1)
	for h := 0; h <= hours; h++ {
		hour := (now - int64(h)*3600) / 3600 * 3600
		ipKeys = append(ipKeys, fmt.Sprintf("moswaf:uip:%d", hour))
		uvKeys = append(uvKeys, fmt.Sprintf("moswaf:uv:%d", hour))
	}
	ips, _ = s.rdb.PFCount(ctx, ipKeys...).Result()
	visitors, _ = s.rdb.PFCount(ctx, uvKeys...).Result()
	return ips, visitors
}

// rate returns part/whole as a percentage, rounded to one decimal. Zero traffic
// is 0%, not a division by zero and not "NaN" arriving in the dashboard.
func rate(part, whole int64) float64 {
	if whole <= 0 {
		return 0
	}
	return math.Round(float64(part)/float64(whole)*1000) / 10
}

// perSecond is rate's sibling, and it exists because writing the division inline
// is how the guard came to be left off.
//
// The first version computed qps inline, one line below a carefully guarded
// rate(), dividing by hours*3600 - so ?hours=0 produced +Inf on a busy site and
// NaN on a quiet one. Neither is representable in JSON: the encoder fails the
// whole document rather than that one field, and the 200 and the headers are
// already written by then, so the client gets a successful response with an
// empty body. One query parameter blanked the entire overview.
func perSecond(count int64, seconds int) float64 {
	if seconds <= 0 || count <= 0 {
		return 0
	}
	return math.Round(float64(count)/float64(seconds)*100) / 100
}

// Hours a statistics window may cover.
//
// Left unbounded this parameter reaches further than a division by zero.
// uniqueCounts builds one Redis key per hour and asks for their union, so a
// large value allocates a slice of millions and hands Redis a command to match;
// and time.Duration(hours)*time.Hour overflows int64 past about 2.5 million
// hours, after which the window start is garbage and the totals are quietly
// wrong rather than merely large.
const (
	minHours = 1
	maxHours = 168 // seven days, the longest range the dashboard offers
)

func clampHours(h int) int {
	if h < minHours {
		return minHours
	}
	if h > maxHours {
		return maxHours
	}
	return h
}

func (s *Server) handleOverview(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	hours := clampHours(queryInt(r, "hours", 24))
	since := time.Now().Add(-time.Duration(hours) * time.Hour)

	totals, err := s.db.StatTotals(ctx, since)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	byAction, err := s.db.CountEventsSince(ctx, since)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	attackers, err := s.db.TopAttackers(ctx, since, 10)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	topRules, err := s.db.TopRules(ctx, since, 10)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	countries, err := s.db.TopCountries(ctx, since, 10)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	sites, err := s.db.ListSites(ctx)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	settings, err := s.db.GetSettings(ctx)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}

	protected := 0
	for _, site := range sites {
		if site.Enabled && site.Mode != "off" {
			protected++
		}
	}

	uniqueIPs, visitors := s.uniqueCounts(ctx, hours)

	writeJSON(w, http.StatusOK, map[string]any{
		"hours":          hours,
		"requests":       totals.Total,
		"blocked":        totals.Blocked,
		"challenged":     totals.Challenged,
		"monitored":      totals.Monitored,
		"page_views":     totals.PageViews,
		"visitors":       visitors,
		"unique_ips":     uniqueIPs,
		"errors_4xx":     totals.Errors4xx,
		"blocked_4xx":    totals.Blocked4xx,
		"errors_5xx":     totals.Errors5xx,
		"blocked_rate":   rate(totals.Blocked, totals.Total),
		"rate_4xx":       rate(totals.Errors4xx, totals.Total),
		"rate_5xx":       rate(totals.Errors5xx, totals.Total),
		"qps":            perSecond(totals.Total, hours*3600),
		"events":         byAction,
		"top_attackers":  attackers,
		"top_rules":      topRules,
		"top_countries":  countries,
		"sites_total":    len(sites),
		"sites_active":   protected,
		"under_attack":   settings.UnderAttack,
		"config_version": s.pub.Version(),
	})
}

func (s *Server) handleTimeseries(w http.ResponseWriter, r *http.Request) {
	// Clamped rather than reset to a default: answering a different question than
	// the one asked is its own kind of wrong.
	hours := clampHours(queryInt(r, "hours", 6))
	points, err := s.db.Timeseries(r.Context(), time.Now().Add(-time.Duration(hours)*time.Hour))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, points)
}

// --------------------------------------------------------------- settings

func (s *Server) handleGetSettings(w http.ResponseWriter, r *http.Request) {
	st, err := s.db.GetSettings(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, st)
}

func (s *Server) handleUpdateSettings(w http.ResponseWriter, r *http.Request) {
	cur, err := s.db.GetSettings(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	// decode over the current values, so a client only has to send what it changes
	body := cur
	if !readJSON(w, r, &body) {
		return
	}
	if err := store.ValidateSettings(&body); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.db.SaveSettings(r.Context(), body); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !s.publish(w, r) {
		return
	}
	writeJSON(w, http.StatusOK, body)
}

// handleUnderAttack toggles under-attack mode. It is the switch that matters most
// during a flood, so it gets its own endpoint and a single button in the UI.
func (s *Server) handleUnderAttack(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Enabled bool `json:"enabled"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	st, err := s.db.GetSettings(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	st.UnderAttack = req.Enabled
	if err := s.db.SaveSettings(r.Context(), st); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !s.publish(w, r) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"under_attack": st.UnderAttack})
}

// --------------------------------------------------------------- he thong

func (s *Server) handlePublish(w http.ResponseWriter, r *http.Request) {
	if !s.publish(w, r) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "published", "version": s.pub.Version()})
}

func (s *Server) handleSystemStatus(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	out := map[string]any{
		"config_version": s.pub.Version(),
		"database":       "ok",
		"redis":          "ok",
		"dataplane":      "unknown",
	}
	if err := s.db.Ping(ctx); err != nil {
		out["database"] = "error: " + err.Error()
	}
	if err := s.rdb.Ping(ctx).Err(); err != nil {
		out["redis"] = "error: " + err.Error()
	}
	if n, err := s.rdb.LLen(ctx, "moswaf:events").Result(); err == nil {
		out["event_queue"] = n
	}
	// Where the crawler ranges came from. An installation with no route to the
	// internet runs on the snapshot compiled into the binary - correctly, and
	// silently. Reporting the origin is what lets an operator tell "bundled, never
	// refreshed" from "fetched this morning", which are different situations that
	// otherwise look identical from the outside.
	if st := s.pub.CrawlerStatus(); len(st) > 0 {
		out["crawlers"] = st
	}
	if s.geo != nil {
		out["geoip"] = s.geo.Status()
	}

	// ask the data plane directly
	client := &http.Client{Timeout: 2 * time.Second}
	if resp, err := client.Get(strings.Replace(s.cfg.ProxySync, "/sync", "/healthz", 1)); err == nil {
		defer resp.Body.Close()
		var health map[string]any
		if json.NewDecoder(resp.Body).Decode(&health) == nil {
			out["dataplane"] = health
		} else {
			out["dataplane"] = "ok"
		}
	} else {
		out["dataplane"] = "unreachable: " + err.Error()
	}

	writeJSON(w, http.StatusOK, out)
}

func hexID(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
