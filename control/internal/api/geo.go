package api

import (
	"net/http"

	"github.com/mosvpn/moswaf/control/internal/engine"
)

// handleListCountries answers the country picker.
//
// Read out of the loaded dataset rather than from a list compiled into the
// dashboard, for a reason that only shows up in one direction: a picker offering
// a country the data does not contain lets somebody build an allow rule that
// matches nothing, and an allow rule matching nothing refuses every visitor. The
// only list that cannot do that is the one the decision will actually be made
// against.
//
// The range count travels with each code because it is what makes a rule cheap or
// enormous, and seeing that before choosing is better than discovering it after.
func (s *Server) handleListCountries(w http.ResponseWriter, r *http.Request) {
	var (
		countries []engine.CountryCount
		status    engine.GeoStatus
	)
	if s.geo != nil {
		countries = s.geo.Countries()
		status = s.geo.Status()
	}
	if countries == nil {
		countries = []engine.CountryCount{}
	}

	// "ready" is the one the dashboard has to act on. The dataset is downloaded in
	// the background a minute after boot, so a fresh install spends a little while
	// with none, and during that time no country rule can be built. Saying so is
	// what stops an operator setting a rule, seeing nothing happen, and concluding
	// the feature is broken.
	writeJSON(w, http.StatusOK, map[string]any{
		"ready":     len(countries) > 0,
		"countries": countries,
		"dataset":   status,
	})
}
