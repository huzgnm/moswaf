package engine

import (
	"log"
	"sort"

	"github.com/mosvpn/moswaf/control/internal/store"
)

// Preparing the operator's rules for the data plane.
//
// Two things are settled here rather than there. The order, because order is the
// policy - first match wins - and establishing it once is the only way every
// worker agrees on it. And the conditions within each rule, which are put in the
// order they are cheapest to test, so a rule that cannot match is abandoned on
// its first condition rather than its last.

// How expensive each field is to test, lowest first.
//
// The numbers are only a ranking. A method is a string compare against a handful
// of values; an address is a walk over a prefix list; a country is a binary search
// over a published range set. On a rule whose conditions cannot all hold, the
// order decides how much of that is paid before finding out.
var conditionCost = map[string]int{
	"method":  1,
	"crawler": 2,
	"host":    3,
	"path":    4,
	"ua":      5,
	"ip":      6,
	"country": 7,
}

func buildAccessRules(rules []*store.AccessRule, geo *geoResolver) []luaAccessRule {
	out := make([]luaAccessRule, 0, len(rules))

	for _, r := range rules {
		if !r.Enabled {
			continue
		}

		conds := make([]luaRuleCondition, 0, len(r.Conditions))
		usable := true

		for _, c := range r.Conditions {
			lc := luaRuleCondition{Field: c.Field, Op: c.Op, Values: c.Values}

			if c.Field == "country" {
				key, ok := geo.setFor(c.Values)
				if !ok {
					// The ranges could not be built - no dataset yet, or a country the
					// data does not contain. The condition cannot be answered, so the
					// rule cannot fire, so publishing it would be publishing a rule that
					// silently never matches. Dropping it and saying so is the honest
					// version of the same outcome.
					usable = false
					break
				}
				lc.Set = key
			}
			conds = append(conds, lc)
		}

		if !usable {
			log.Printf("moswaf: access rule %q names a country with no address data, "+
				"so it cannot be applied yet", r.Name)
			continue
		}

		// Cheapest condition first. All of them have to hold, so the order changes
		// nothing about which requests match - only how much work a request that
		// does not match costs on the way to finding out.
		sort.SliceStable(conds, func(i, j int) bool {
			return conditionCost[conds[i].Field] < conditionCost[conds[j].Field]
		})

		out = append(out, luaAccessRule{
			ID: r.ID, Name: r.Name, Action: r.Action,
			Enabled: true, Site: r.SiteID, Conditions: conds,
		})
	}

	return out
}
