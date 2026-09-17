package api

import (
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Temporary bans are created by the engine when it detects a flood. They only exist
// in the data plane shared dict and expire on their own; Postgres knows nothing about
// them, so the control plane has to ask the data plane over its internal API.

var dataplaneClient = &http.Client{Timeout: 3 * time.Second}

func (s *Server) dataplaneURL(path string) string {
	return strings.Replace(s.cfg.ProxySync, "/sync", path, 1)
}

func (s *Server) callDataplane(w http.ResponseWriter, target string) {
	req, err := http.NewRequest(http.MethodGet, target, nil)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if s.cfg.InternalToken != "" {
		req.Header.Set("X-MosWAF-Token", s.cfg.InternalToken)
	}

	resp, err := dataplaneClient.Do(req)
	if err != nil {
		writeErr(w, http.StatusBadGateway, "cannot reach the data plane: "+err.Error())
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		writeErr(w, http.StatusBadGateway, "failed to read the response: "+err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(resp.StatusCode)
	_, _ = w.Write(body)
}

func (s *Server) handleListBans(w http.ResponseWriter, r *http.Request) {
	s.callDataplane(w, s.dataplaneURL("/bans"))
}

// handleUnban lifts the ban for one IP, or for every IP when the id is "*".
func (s *Server) handleUnban(w http.ResponseWriter, r *http.Request) {
	ip := r.PathValue("ip")
	if ip == "" {
		writeErr(w, http.StatusBadRequest, "missing IP address")
		return
	}
	s.callDataplane(w, s.dataplaneURL("/unban")+"?ip="+url.QueryEscape(ip))
}
