package api

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/mosvpn/moswaf/control/internal/store"
)

// The operator's own ordered allow and deny rules.

func newRuleID() string {
	b := make([]byte, 5)
	_, _ = rand.Read(b)
	return "r" + hex.EncodeToString(b)
}

func (s *Server) handleListAccessRules(w http.ResponseWriter, r *http.Request) {
	rules, err := s.db.ListAccessRules(r.Context(), r.URL.Query().Get("site"))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}

	// How often each rule fired today, read alongside the rules rather than from a
	// separate call. It is the figure that answers the question the list cannot:
	// which rule is actually deciding. A rule near the top matching everything
	// looks exactly like a rule near the top matching nothing until you can see
	// the count.
	hits := s.ruleHits(r.Context(), rules)

	out := make([]map[string]any, 0, len(rules))
	for _, rule := range rules {
		out = append(out, map[string]any{
			"id": rule.ID, "name": rule.Name, "action": rule.Action,
			"priority": rule.Priority, "enabled": rule.Enabled, "site_id": rule.SiteID,
			"conditions": rule.Conditions, "created_at": rule.CreatedAt,
			"updated_at": rule.UpdatedAt, "hits_today": hits[rule.ID],
		})
	}
	writeJSON(w, http.StatusOK, out)
}

// ruleHits reads today's counters. A missing counter is zero, not an error: the
// figure is reporting, and reporting must never be able to stop the page that
// carries it from loading.
func (s *Server) ruleHits(ctx context.Context, rules []*store.AccessRule) map[string]int64 {
	out := map[string]int64{}
	if len(rules) == 0 {
		return out
	}
	// One key per host, summed here. Two proxies behind a load balancer each count
	// what they saw; a single key would have them overwriting each other, and the
	// figure would silently be "whichever host flushed last" rather than the total.
	// Scanned rather than KEYS'd. There is only a handful of these - one per host
	// per day - but KEYS walks the whole keyspace to find them, and the rest of
	// that keyspace is one statistics key per minute per host. On a busy install
	// that is a single-threaded server stopping to answer a dashboard panel.
	day := time.Now().UTC().Format("2006-01-02")
	var cursor uint64
	for i := 0; i < 64; i++ { // bounded: a cursor that never returns to 0 must not hang the page
		keys, next, err := s.rdb.Scan(ctx, cursor, "moswaf:rulehits:"+day+":*", 64).Result()
		if err != nil {
			return out
		}
		for _, key := range keys {
			vals, err := s.rdb.HGetAll(ctx, key).Result()
			if err != nil {
				continue
			}
			for id, v := range vals {
				n, err := strconv.ParseInt(v, 10, 64)
				if err != nil {
					continue
				}
				out[id] += n
			}
		}
		if next == 0 {
			break
		}
		cursor = next
	}
	return out
}

func (s *Server) handleCreateAccessRule(w http.ResponseWriter, r *http.Request) {
	var rule store.AccessRule
	if !readJSON(w, r, &rule) {
		return
	}

	n, err := s.db.CountAccessRules(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if n >= store.MaxAccessRules {
		// Every rule is walked on every request until one matches, so the list has a
		// ceiling for the same reason a regular expression does not belong in it.
		writeErr(w, http.StatusBadRequest,
			"there are already the maximum number of rules; delete one first")
		return
	}

	rule.ID = newRuleID()
	if rule.Priority == 0 {
		// New rules go to the bottom. Anywhere else would change what an existing
		// rule does without anybody editing it - with first-match-wins, inserting
		// above is how a rule stops being reached.
		rule.Priority = 1000 + n
	}
	if err := s.db.UpsertAccessRule(r.Context(), &rule); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if !s.publish(w, r) {
		return
	}
	writeJSON(w, http.StatusCreated, rule)
}

func (s *Server) handleUpdateAccessRule(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	existing, err := s.db.GetAccessRule(r.Context(), id)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeErr(w, http.StatusNotFound, "no such rule")
			return
		}
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}

	var rule store.AccessRule
	if !readJSON(w, r, &rule) {
		return
	}
	// The id comes from the path, never from the body: a body that could rename a
	// rule could overwrite a different one.
	rule.ID = existing.ID
	if rule.Priority == 0 {
		rule.Priority = existing.Priority
	}

	if err := s.db.UpsertAccessRule(r.Context(), &rule); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if !s.publish(w, r) {
		return
	}
	writeJSON(w, http.StatusOK, rule)
}

func (s *Server) handleDeleteAccessRule(w http.ResponseWriter, r *http.Request) {
	if err := s.db.DeleteAccessRule(r.Context(), r.PathValue("id")); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeErr(w, http.StatusNotFound, "no such rule")
			return
		}
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !s.publish(w, r) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleReorderAccessRules(w http.ResponseWriter, r *http.Request) {
	var body struct {
		IDs []string `json:"ids"`
	}
	if !readJSON(w, r, &body) {
		return
	}
	if len(body.IDs) == 0 || len(body.IDs) > store.MaxAccessRules {
		writeErr(w, http.StatusBadRequest, "send the full list of rule ids in the new order")
		return
	}
	if err := s.db.ReorderAccessRules(r.Context(), body.IDs); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !s.publish(w, r) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// handleTestAccessRules answers "which of my rules would this request hit".
//
// Forwarded to the data plane rather than answered here, and that is the whole
// point of it. A second matcher living in the control plane would be a second
// thing to keep in agreement with the first, and the moment they disagreed this
// endpoint would start giving confident answers about a policy that is not the
// one in force - exactly where an operator is relying on it, which is deciding
// whether a rule near the top is quietly shadowing the rest.
func (s *Server) handleTestAccessRules(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<16))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "could not read the request")
		return
	}
	var sample map[string]any
	if err := json.Unmarshal(body, &sample); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON")
		return
	}

	url := strings.TrimSuffix(s.cfg.ProxySync, "/sync") + "/rule-test"
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-MosWAF-Token", s.cfg.InternalToken)

	res, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
	if err != nil {
		// Said plainly rather than dressed up as "no rule matched", which would be a
		// wrong answer instead of a missing one.
		writeErr(w, http.StatusServiceUnavailable,
			"could not reach the firewall to run the test: "+err.Error())
		return
	}
	defer res.Body.Close()

	out, _ := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(res.StatusCode)
	_, _ = w.Write(out)
}
