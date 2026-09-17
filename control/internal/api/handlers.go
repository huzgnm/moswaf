package api

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

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

	var in store.Site
	if !readJSON(w, r, &in) {
		return
	}

	in.ID = cur.ID
	in.CreatedAt = cur.CreatedAt
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

func (s *Server) handleOverview(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	hours := queryInt(r, "hours", 24)
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

	writeJSON(w, http.StatusOK, map[string]any{
		"hours":          hours,
		"requests":       totals.Total,
		"blocked":        totals.Blocked,
		"challenged":     totals.Challenged,
		"monitored":      totals.Monitored,
		"events":         byAction,
		"top_attackers":  attackers,
		"top_rules":      topRules,
		"sites_total":    len(sites),
		"sites_active":   protected,
		"under_attack":   settings.UnderAttack,
		"config_version": s.pub.Version(),
	})
}

func (s *Server) handleTimeseries(w http.ResponseWriter, r *http.Request) {
	hours := queryInt(r, "hours", 6)
	if hours <= 0 || hours > 168 {
		hours = 6
	}
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
