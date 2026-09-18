package api

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/mosvpn/moswaf/control/internal/store"
)

// Administration of the accounts behind a site's login gate.
//
// Every one of these is behind the dashboard's own authentication - they are on
// the authenticated mux - and every one that changes something republishes, because
// the data plane decides from the published configuration and a change nobody
// published is a change that has not happened.

// siteUserID reads the account id from the path and checks it belongs to the site
// in the same path.
//
// The check matters: without it, /api/sites/a/users/{id of an account on site b}
// would delete or re-password somebody else's account. The id alone is enough to
// find the row, so the row has to be asked which site it is on.
func (s *Server) siteUserID(w http.ResponseWriter, r *http.Request) (*store.SiteUser, bool) {
	siteID := r.PathValue("id")
	raw := r.PathValue("uid")
	id, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid account id")
		return nil, false
	}
	users, err := s.db.ListSiteUsers(r.Context(), siteID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return nil, false
	}
	for _, u := range users {
		if u.ID == id {
			return u, true
		}
	}
	// Not "wrong site" and not "no such account" - one answer, because the two
	// together are a way to learn which ids exist elsewhere.
	writeErr(w, http.StatusNotFound, "no such account on this site")
	return nil, false
}

func (s *Server) handleListSiteUsers(w http.ResponseWriter, r *http.Request) {
	users, err := s.db.ListSiteUsers(r.Context(), r.PathValue("id"))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	// SiteUser has no password field at all, so there is nothing here to forget to
	// strip. That is why the struct is shaped that way.
	writeJSON(w, http.StatusOK, users)
}

func (s *Server) handleCreateSiteUser(w http.ResponseWriter, r *http.Request) {
	siteID := r.PathValue("id")
	if _, err := s.db.GetSite(r.Context(), siteID); err != nil {
		writeErr(w, http.StatusNotFound, "no such site")
		return
	}

	var body struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if !readJSON(w, r, &body) {
		return
	}
	if _, err := store.ValidateSiteUser(body.Username, body.Password); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}

	u, err := s.db.CreateSiteUser(r.Context(), siteID, body.Username, body.Password)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	// The data plane cannot let this account in until the generation map reaches
	// it, so publishing is part of creating the account rather than something to
	// remember afterwards - and a failure to publish is reported, because the
	// account exists and still cannot sign in.
	if !s.publish(w, r) {
		return
	}
	writeJSON(w, http.StatusCreated, u)
}

func (s *Server) handleSetSiteUserPassword(w http.ResponseWriter, r *http.Request) {
	u, ok := s.siteUserID(w, r)
	if !ok {
		return
	}
	var body struct {
		Password string `json:"password"`
	}
	if !readJSON(w, r, &body) {
		return
	}
	if err := s.db.SetSiteUserPassword(r.Context(), u.ID, body.Password); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeErr(w, http.StatusNotFound, "no such account")
			return
		}
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	// Changing the password also ended every session it had opened. Until this is
	// published, those sessions still work - which would make the change look
	// complete while the thing it was meant to stop carried on. So a publish that
	// fails is an error the operator sees, not a line in a log.
	if !s.publish(w, r) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleRevokeSiteUser(w http.ResponseWriter, r *http.Request) {
	u, ok := s.siteUserID(w, r)
	if !ok {
		return
	}
	if err := s.db.RevokeSiteUserSessions(r.Context(), u.ID); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !s.publish(w, r) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleDeleteSiteUser(w http.ResponseWriter, r *http.Request) {
	u, ok := s.siteUserID(w, r)
	if !ok {
		return
	}
	if err := s.db.DeleteSiteUser(r.Context(), u.ID); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !s.publish(w, r) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}
