package engine

import (
	"encoding/hex"
	"sort"
	"strings"
)

// Turning the country dataset into something the data plane can decide with.
//
// Geolocation was built for reporting: seven hundred thousand ranges answered one
// lookup per recorded event, in the control plane, where the cost did not matter.
// Blocking is the opposite shape - one lookup per request, in the data plane, on
// the hot path - so shipping the whole dataset there would spend memory in every
// worker and time on every request to answer a question most installations never
// ask.
//
// So only what is actually being decided on gets published. A rule that blocks two
// countries publishes those two countries' ranges and nothing else, which for a
// typical rule is one or two per cent of the dataset.
//
// Two further reductions fall out of that:
//
// The country code is dropped. A rule asks "is this address in the listed set?",
// which is one bit, so the published set is the union of the listed countries with
// the labels thrown away. Adjacent ranges from different listed countries then
// merge into one, which shrinks it again. Nothing is lost by it: the attack log's
// country label is written by the control plane, which still has the full dataset.
//
// Identical rules share one published set. The ordinary installation has one rule
// for everything, so that is one set no matter how many sites there are.

const (
	// A ceiling on what one rule may pull down. The realistic rules are far under
	// it - the largest single country is some tens of thousands of ranges - so this
	// is here for the rule nobody meant to write: fifty countries in allow mode,
	// which would put several megabytes into every worker to answer a question that
	// could have been asked the other way round.
	maxGeoRanges = 250_000

	// More than this in one rule is a list nobody typed on purpose, and it is the
	// cheap check that stops the expensive one being reached.
	maxGeoCountries = 60
)

// GeoSet is one rule's worth of address ranges, ready for the data plane.
//
// Flat and interleaved - lo, hi, lo, hi - because that is what a binary search
// over a Lua array wants and it is the most compact thing JSON can carry.
type GeoSet struct {
	// IPv4 bounds as plain numbers. A 32-bit value is exact in a double, so the
	// data plane compares numbers rather than parsing anything.
	V4 []uint32 `json:"v4"`
	// IPv6 bounds as 32 lowercase hex characters each. Fixed-width big-endian hex
	// compares lexicographically in exactly numeric order, so the data plane can
	// use a plain string comparison and never has to do 128-bit arithmetic in a
	// language whose numbers stop being exact at 53 bits.
	V6 []string `json:"v6"`
}

// GeoSetKey is the name a rule and its published set share.
//
// The sorted country list itself, so two rules listing the same countries in a
// different order are one set rather than two - which is the common case, since
// the ordinary installation has one rule that every site follows.
func GeoSetKey(countries []string) string {
	c := append([]string(nil), countries...)
	sort.Strings(c)
	return strings.Join(c, ",")
}

// SetFor builds the merged ranges for a list of country codes.
//
// Returns ok=false when the rule is larger than the ceiling. The caller must treat
// that as "this rule cannot be applied" rather than as an empty set: an empty set
// in allow mode refuses every visitor on earth, so a size limit that quietly
// produced one would take a site off the air to save memory.
func (g *GeoIP) SetFor(countries []string) (GeoSet, bool) {
	var out GeoSet
	if len(countries) == 0 || len(countries) > maxGeoCountries {
		return out, false
	}

	want := make(map[string]bool, len(countries))
	for _, c := range countries {
		want[strings.ToUpper(strings.TrimSpace(c))] = true
	}

	g.mu.RLock()
	defer g.mu.RUnlock()

	// No dataset loaded. Not an empty set - an unanswerable question, and the
	// difference matters: with no data, "is this address in China?" has no answer,
	// and answering "no" would let an allow rule refuse everybody.
	if len(g.v4) == 0 && len(g.v6) == 0 {
		return out, false
	}

	type r4 struct{ lo, hi uint32 }
	picked4 := make([]r4, 0, 4096)
	for _, r := range g.v4 {
		if want[strings.ToUpper(string(r.cc[:]))] {
			picked4 = append(picked4, r4{r.lo, r.hi})
		}
	}

	type r6 struct{ lo, hi [16]byte }
	picked6 := make([]r6, 0, 1024)
	for _, r := range g.v6 {
		if !want[strings.ToUpper(string(r.cc[:]))] {
			continue
		}
		picked6 = append(picked6, r6{lo: bytes16(r.loHi, r.loLo), hi: bytes16(r.hiHi, r.hiLo)})
	}

	if len(picked4)+len(picked6) > maxGeoRanges {
		return out, false
	}

	// Merged, which needs them ordered by their lower bound - the stored tables are
	// ordered by the upper one, because that is what their own lookup searches on.
	sort.Slice(picked4, func(i, j int) bool { return picked4[i].lo < picked4[j].lo })
	sort.Slice(picked6, func(i, j int) bool {
		return string(picked6[i].lo[:]) < string(picked6[j].lo[:])
	})

	for _, r := range picked4 {
		n := len(out.V4)
		// Touching counts as overlapping: 1.0.0.0-1.0.0.255 followed by
		// 1.0.1.0-… leaves no address between them, so keeping them apart would
		// store two ranges to say what one says.
		if n > 0 && r.lo <= out.V4[n-1]+1 {
			if r.hi > out.V4[n-1] {
				out.V4[n-1] = r.hi
			}
			continue
		}
		out.V4 = append(out.V4, r.lo, r.hi)
	}

	for _, r := range picked6 {
		lo, hi := hex.EncodeToString(r.lo[:]), hex.EncodeToString(r.hi[:])
		n := len(out.V6)
		// Only merged on a real overlap. "The next address along" would mean
		// incrementing a 128-bit number to find out, which is a lot of work to save
		// an entry in a table that is already the small half.
		if n > 0 && lo <= out.V6[n-1] {
			if hi > out.V6[n-1] {
				out.V6[n-1] = hi
			}
			continue
		}
		out.V6 = append(out.V6, lo, hi)
	}

	if len(out.V4) == 0 && len(out.V6) == 0 {
		// Every listed country is missing from the dataset. Same reasoning as an
		// unloaded dataset: not an empty answer, no answer.
		return out, false
	}
	return out, true
}

// CountryCount is one country the loaded dataset knows about.
type CountryCount struct {
	Code   string `json:"code"`
	Ranges int    `json:"ranges"`
}

// Countries lists what is actually in the dataset, for the country picker.
//
// Taken from the data rather than from a list compiled into the dashboard, so the
// picker cannot offer a country that would then produce no ranges - which in allow
// mode is the difference between a working rule and a site that refuses everyone.
// The range count comes with it because it is what decides whether a rule is cheap
// or enormous, and that is worth seeing before choosing rather than after.
func (g *GeoIP) Countries() []CountryCount {
	g.mu.RLock()
	defer g.mu.RUnlock()

	n := map[string]int{}
	for _, r := range g.v4 {
		if cc := known(string(r.cc[:])); cc != "" {
			n[strings.ToUpper(cc)]++
		}
	}
	for _, r := range g.v6 {
		if cc := known(string(r.cc[:])); cc != "" {
			n[strings.ToUpper(cc)]++
		}
	}

	out := make([]CountryCount, 0, len(n))
	for code, count := range n {
		out = append(out, CountryCount{Code: code, Ranges: count})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Code < out[j].Code })
	return out
}

func bytes16(hi, lo uint64) [16]byte {
	var b [16]byte
	for i := 0; i < 8; i++ {
		b[7-i] = byte(hi >> (8 * i))
		b[15-i] = byte(lo >> (8 * i))
	}
	return b
}
