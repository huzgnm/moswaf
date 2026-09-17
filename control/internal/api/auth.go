package api

import (
	"context"
	"errors"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/mosvpn/moswaf/control/internal/store"
)

type ctxKey string

const ctxUser ctxKey = "moswaf.user"

// ------------------------------------------------------- chong do mat khau

type attempt struct {
	fails int
	until time.Time
}

type loginGuard struct {
	mu   sync.Mutex
	data map[string]*attempt
}

func newLoginGuard() *loginGuard {
	g := &loginGuard{data: map[string]*attempt{}}
	go g.cleanup()
	return g
}

func (g *loginGuard) cleanup() {
	for range time.Tick(10 * time.Minute) {
		g.mu.Lock()
		for k, v := range g.data {
			if time.Now().After(v.until) && v.fails == 0 {
				delete(g.data, k)
			}
		}
		g.mu.Unlock()
	}
}

// blocked tra ve so giay con phai cho, 0 neu duoc thu tiep.
func (g *loginGuard) blocked(ip string) int {
	g.mu.Lock()
	defer g.mu.Unlock()
	a := g.data[ip]
	if a == nil {
		return 0
	}
	if d := time.Until(a.until); d > 0 {
		return int(d.Seconds()) + 1
	}
	return 0
}

func (g *loginGuard) fail(ip string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	a := g.data[ip]
	if a == nil {
		a = &attempt{}
		g.data[ip] = a
	}
	a.fails++
	switch {
	case a.fails >= 10:
		a.until = time.Now().Add(30 * time.Minute)
	case a.fails >= 5:
		a.until = time.Now().Add(5 * time.Minute)
	}
}

func (g *loginGuard) success(ip string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	delete(g.data, ip)
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// ------------------------------------------------------- JWT

func (s *Server) issueToken(u *store.User) (string, time.Time, error) {
	exp := time.Now().Add(s.cfg.TokenTTL)
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": strconv.FormatInt(u.ID, 10),
		"usr": u.Username,
		"iat": time.Now().Unix(),
		"exp": exp.Unix(),
	})
	str, err := tok.SignedString(s.cfg.JWTSecret)
	return str, exp, err
}

func (s *Server) parseToken(raw string) (*store.User, error) {
	tok, err := jwt.Parse(raw, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("thuat toan ky khong duoc chap nhan")
		}
		return s.cfg.JWTSecret, nil
	}, jwt.WithValidMethods([]string{"HS256"}))
	if err != nil {
		return nil, err
	}
	claims, ok := tok.Claims.(jwt.MapClaims)
	if !ok || !tok.Valid {
		return nil, errors.New("token khong hop le")
	}
	sub, _ := claims["sub"].(string)
	id, err := strconv.ParseInt(sub, 10, 64)
	if err != nil {
		return nil, errors.New("token thieu chu the")
	}
	usr, _ := claims["usr"].(string)
	return &store.User{ID: id, Username: usr}, nil
}

func (s *Server) requireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := r.Header.Get("Authorization")
		if !strings.HasPrefix(h, "Bearer ") {
			writeErr(w, http.StatusUnauthorized, "chua dang nhap")
			return
		}
		u, err := s.parseToken(strings.TrimPrefix(h, "Bearer "))
		if err != nil {
			writeErr(w, http.StatusUnauthorized, "phien dang nhap khong hop le hoac da het han")
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxUser, u)))
	})
}

func userFrom(r *http.Request) *store.User {
	u, _ := r.Context().Value(ctxUser).(*store.User)
	return u
}

// ------------------------------------------------------- handler

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)
	if wait := s.login.blocked(ip); wait > 0 {
		w.Header().Set("Retry-After", strconv.Itoa(wait))
		writeErr(w, http.StatusTooManyRequests,
			"Sai qua nhieu lan. Thu lai sau "+strconv.Itoa(wait)+" giay.")
		return
	}

	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if !readJSON(w, r, &req) {
		return
	}

	u, err := s.db.Authenticate(r.Context(), strings.TrimSpace(req.Username), req.Password)
	if err != nil {
		s.login.fail(ip)
		writeErr(w, http.StatusUnauthorized, "Sai tai khoan hoac mat khau")
		return
	}
	s.login.success(ip)

	token, exp, err := s.issueToken(u)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "khong tao duoc phien dang nhap")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"token":      token,
		"expires_at": exp,
		"user":       u,
	})
}

func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r)
	full, err := s.db.GetUser(r.Context(), u.ID)
	if err != nil {
		writeErr(w, http.StatusUnauthorized, "tai khoan khong con ton tai")
		return
	}
	writeJSON(w, http.StatusOK, full)
}

func (s *Server) handleChangePassword(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r)
	var req struct {
		Current string `json:"current"`
		New     string `json:"new"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	if _, err := s.db.Authenticate(r.Context(), u.Username, req.Current); err != nil {
		writeErr(w, http.StatusUnauthorized, "Mat khau hien tai khong dung")
		return
	}
	if len(req.New) < 8 {
		writeErr(w, http.StatusBadRequest, "Mat khau moi phai tu 8 ky tu tro len")
		return
	}
	if err := s.db.SetPassword(r.Context(), u.Username, req.New); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "da doi mat khau"})
}
