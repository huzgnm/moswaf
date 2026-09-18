package engine

import (
	"strings"
	"testing"
)

const geoSample = `1.0.0.0,1.0.0.255,AU
1.0.1.0,1.0.1.255,CN
1.0.2.0,1.0.2.255,CN
8.8.8.0,8.8.8.255,US
14.160.0.0,14.191.255.255,VN
203.0.113.0,203.0.113.255,SE
2001:200::,2001:200:ffff:ffff:ffff:ffff:ffff:ffff,JP
2401:d800::,2401:d800:ffff:ffff:ffff:ffff:ffff:ffff,VN
`

func geoWithSample(t *testing.T) *GeoIP {
	t.Helper()
	v4, v6, err := parseCSV(strings.NewReader(geoSample))
	if err != nil {
		t.Fatalf("parsing the sample: %v", err)
	}
	g := NewGeoIP()
	g.v4, g.v6 = v4, v6
	return g
}

// Two ranges of the same country that leave no address between them say one
// thing, so they are stored as one. The country labels are gone by this point -
// a rule asks "is this address in the listed set", which is one bit - so ranges
// of DIFFERENT listed countries merge just as readily.
func TestAdjacentRangesAreMerged(t *testing.T) {
	g := geoWithSample(t)

	set, ok := g.SetFor([]string{"CN"})
	if !ok {
		t.Fatal("a country present in the dataset produced no set")
	}
	if len(set.V4) != 2 {
		t.Errorf("CN produced %d bounds, want 2 - its two touching ranges should be one", len(set.V4)/1)
	}

	// AU ends at 1.0.0.255 and CN starts at 1.0.1.0: nothing between them, so
	// listing both is one range, not three.
	set, ok = g.SetFor([]string{"AU", "CN"})
	if !ok {
		t.Fatal("no set for AU+CN")
	}
	if len(set.V4) != 2 {
		t.Errorf("AU+CN produced %d bounds, want 2", len(set.V4))
	}
}

func TestSetForCoversBothFamilies(t *testing.T) {
	g := geoWithSample(t)
	set, ok := g.SetFor([]string{"VN"})
	if !ok {
		t.Fatal("no set for VN")
	}
	if len(set.V4) != 2 {
		t.Errorf("VN has %d IPv4 bounds, want 2", len(set.V4))
	}
	if len(set.V6) != 2 {
		t.Errorf("VN has %d IPv6 bounds, want 2 - an IPv6 visitor would walk "+
			"straight past a country rule that only covers IPv4", len(set.V6))
	}
	// Fixed-width lowercase hex, so the data plane can compare with < and never
	// has to do 128-bit arithmetic.
	for _, v := range set.V6 {
		if len(v) != 32 || strings.ToLower(v) != v {
			t.Errorf("IPv6 bound %q is not 32 lowercase hex characters; the data "+
				"plane compares these as strings and the ordering only matches the "+
				"numeric one at a fixed width", v)
		}
	}
	if !(set.V6[0] < set.V6[1]) {
		t.Errorf("the IPv6 bounds are not in order: %q then %q", set.V6[0], set.V6[1])
	}
}

// The states that must NOT produce an empty set, because an empty set in allow
// mode refuses every visitor on earth. Each has to be refused outright so the
// caller keeps the previous rule instead of applying a rule that means "nobody".
func TestUnanswerableRulesAreRefusedRatherThanEmptied(t *testing.T) {
	g := geoWithSample(t)

	if _, ok := g.SetFor(nil); ok {
		t.Error("an empty country list produced a set")
	}
	if _, ok := g.SetFor([]string{"XX"}); ok {
		t.Error("a country that is not in the dataset produced a set; in allow mode " +
			"that set would refuse everybody")
	}
	if _, ok := NewGeoIP().SetFor([]string{"CN"}); ok {
		t.Error("an unloaded dataset produced a set. With no data, \"is this address " +
			"in China\" has no answer, and answering \"no\" lets an allow rule refuse " +
			"every visitor")
	}

	many := make([]string, maxGeoCountries+1)
	for i := range many {
		many[i] = "CN"
	}
	if _, ok := g.SetFor(many); ok {
		t.Error("a list past the country ceiling was accepted")
	}
}

// Two rules naming the same countries are one published set, however they were
// typed. The ordinary installation has one rule that every site follows, and it
// should cost one set no matter how many sites there are.
func TestTheSetKeyIgnoresOrder(t *testing.T) {
	if GeoSetKey([]string{"RU", "CN"}) != GeoSetKey([]string{"CN", "RU"}) {
		t.Error("the same two countries in a different order produced different keys")
	}
	if GeoSetKey([]string{"CN"}) == GeoSetKey([]string{"CN", "RU"}) {
		t.Error("different country lists produced the same key")
	}
}

func TestCaseDoesNotMatter(t *testing.T) {
	g := geoWithSample(t)
	upper, ok1 := g.SetFor([]string{"VN"})
	lower, ok2 := g.SetFor([]string{"vn"})
	if !ok1 || !ok2 || len(upper.V4) != len(lower.V4) {
		t.Error("a lowercase country code produced a different set from an uppercase one")
	}
}
