package api

import (
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Ban tam thoi do engine tu sinh khi phat hien flood. Chung chi ton tai trong
// shared dict cua data plane (het han la tu bay), Postgres khong biet gi ve
// chung - nen control plane phai hoi thang data plane qua API noi bo.

var dataplaneClient = &http.Client{Timeout: 3 * time.Second}

func (s *Server) dataplaneURL(path string) string {
	return strings.Replace(s.cfg.ProxySync, "/sync", path, 1)
}

func (s *Server) callDataplane(w http.ResponseWriter, target string) {
	resp, err := dataplaneClient.Get(target)
	if err != nil {
		writeErr(w, http.StatusBadGateway, "khong hoi duoc data plane: "+err.Error())
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		writeErr(w, http.StatusBadGateway, "doc phan hoi that bai: "+err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(resp.StatusCode)
	_, _ = w.Write(body)
}

func (s *Server) handleListBans(w http.ResponseWriter, r *http.Request) {
	s.callDataplane(w, s.dataplaneURL("/bans"))
}

// handleUnban go ban cho mot IP, hoac tat ca khi id la "*".
func (s *Server) handleUnban(w http.ResponseWriter, r *http.Request) {
	ip := r.PathValue("ip")
	if ip == "" {
		writeErr(w, http.StatusBadRequest, "thieu dia chi IP")
		return
	}
	s.callDataplane(w, s.dataplaneURL("/unban")+"?ip="+url.QueryEscape(ip))
}
