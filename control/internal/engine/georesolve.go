package engine

import (
	"log"

	"github.com/mosvpn/moswaf/control/internal/store"
)

// Working out which country rule applies where, once per publish.
//
// Two things happen here that must not happen in the data plane. Inheritance is
// resolved - a site following the global rule is published carrying that rule
// rather than a marker meaning "go and look" - and a rule whose ranges cannot be
// built is turned off rather than shipped as an empty set.
//
// The second is the one worth stating plainly. An allow rule with no ranges is
// not a permissive rule; it is a rule that refuses every visitor on earth. It is
// reachable without anybody asking for it: the dataset has not downloaded yet on
// a fresh install, or the machine has no route to the internet, or a country was
// named that the dataset does not contain. Publishing it as written would take
// every site with an allow rule off the air, for a reason that appears nowhere
// except in a graph going to zero.

type geoResolver struct {
	sets map[string]GeoSet

	// Country lists whose ranges could not be built. Kept so the same list is not
	// attempted once per site, and so it is reported once rather than per site.
	failed map[string]bool

	globalMode string
	globalSet  string
}

func (p *Publisher) resolveGeo(settings store.Settings, sites []*store.Site) *geoResolver {
	r := &geoResolver{sets: map[string]GeoSet{}, failed: map[string]bool{}}

	g := p.geoIP()
	if g == nil {
		// No geolocation at all. Every rule becomes "off", which is the direction
		// that keeps sites serving.
		if settings.GeoMode != "off" && settings.GeoMode != "" {
			log.Printf("moswaf: country rules are configured but geolocation is not " +
				"available, so they are not being applied")
		}
		return r
	}

	r.globalMode, r.globalSet = r.build(g, settings.GeoMode, settings.GeoCountries, "the global rule")
	for _, s := range sites {
		if !s.Enabled || s.GeoMode == "" {
			continue
		}
		r.build(g, s.GeoMode, s.GeoCountries, "the rule on "+s.Name)
	}
	return r
}

// build registers the ranges a rule needs and returns the mode that will actually
// be published - "off" when they could not be produced.
func (r *geoResolver) build(g *GeoIP, mode string, countries []string, what string) (string, string) {
	if mode != "block" && mode != "allow" {
		return "off", ""
	}
	key := GeoSetKey(countries)
	if _, done := r.sets[key]; done {
		return mode, key
	}
	if r.failed[key] {
		return "off", ""
	}

	set, ok := g.SetFor(countries)
	if !ok {
		r.failed[key] = true
		// Said out loud, and said differently for the two modes, because the
		// consequences are not remotely alike: a block rule that cannot be applied
		// lets through traffic somebody wanted stopped, and an allow rule that
		// cannot be applied would have stopped everybody.
		if mode == "allow" {
			log.Printf("moswaf: %s allows only %v, but those ranges could not be "+
				"prepared; it is not being applied, because applying it would refuse "+
				"every visitor", what, countries)
		} else {
			log.Printf("moswaf: %s blocks %v, but those ranges could not be prepared; "+
				"it is not being applied", what, countries)
		}
		return "off", ""
	}
	r.sets[key] = set
	return mode, key
}

// forSite returns the rule to publish for one site: its own if it set one,
// otherwise the global one.
//
// An empty GeoMode on a site means "follow the global rule". "off" means this site
// deliberately opts out of a rule the others follow, and the two have to stay
// distinguishable - an operator who exempted one site should not have that undone
// the next time the global list changes.
func (r *geoResolver) forSite(s *store.Site) (string, string) {
	if s.GeoMode == "" {
		return r.globalMode, r.globalSet
	}
	if s.GeoMode != "block" && s.GeoMode != "allow" {
		return "off", ""
	}
	key := GeoSetKey(s.GeoCountries)
	if _, ok := r.sets[key]; !ok {
		return "off", ""
	}
	return s.GeoMode, key
}
