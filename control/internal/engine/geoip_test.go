package engine

import (
	"strings"
	"testing"
)

// A small dataset in the shape DB-IP publish: start,end,country, one range per
// line, IPv4 and IPv6 mixed, and deliberately not in order - the lookup is a
// binary search, so the parser has to sort rather than trust the file.
const sampleCSV = `
2001:200::,2001:200:ffff:ffff:ffff:ffff:ffff:ffff,JP
203.0.113.0,203.0.113.255,SE
1.0.0.0,1.0.0.255,AU
14.160.0.0,14.191.255.255,VN
2401:d800::,2401:d800:ffff:ffff:ffff:ffff:ffff:ffff,VN
8.8.8.0,8.8.8.255,US
192.0.2.0,192.0.2.255,ZZ
this line is not a range
1.2.3.4,not-an-address,XX
5.6.7.8,5.6.7.9,TOOLONG
`

func loadSample(t *testing.T) *GeoIP {
	t.Helper()
	v4, v6, err := parseCSV(strings.NewReader(sampleCSV))
	if err != nil {
		t.Fatalf("parsing the sample: %v", err)
	}
	g := NewGeoIP()
	g.v4, g.v6 = v4, v6
	return g
}

func TestLookupFindsTheRightCountry(t *testing.T) {
	g := loadSample(t)

	cases := map[string]string{
		"1.0.0.1":      "AU",
		"1.0.0.0":      "AU", // the first address of a range
		"1.0.0.255":    "AU", // and the last
		"8.8.8.8":      "US",
		"14.177.0.1":   "VN",
		"203.0.113.9":  "SE",
		"2001:200::1":  "JP",
		"2401:d800::5": "VN",

		// Outside every range: a normal answer, not an error.
		"9.9.9.9":      "",
		"2606:4700::1": "",

		// The addresses either side of a range must not match it.
		"1.0.1.0":   "",
		"8.8.7.255": "",

		// ZZ is the dataset's way of saying "not a country" - reserved and
		// documentation ranges. Reporting it as one would put a row on the
		// dashboard labelled with a code no map has.
		"192.0.2.9": "",
	}

	for ip, want := range cases {
		if got := g.Lookup(ip); got != want {
			t.Errorf("Lookup(%s) = %q, want %q", ip, got, want)
		}
	}
}

// An IPv4 address written as IPv6 is an IPv4 address, and the IPv4 table is the
// one that holds it. Without the unmapping a dual-stack client would be reported
// as unknown while the identical client on a v4 socket was reported correctly -
// the same class of confusion that let a mapped address dodge the blocklist.
func TestMappedAddressesAreLookedUpAsIPv4(t *testing.T) {
	g := loadSample(t)
	for _, ip := range []string{"::ffff:8.8.8.8", "::ffff:808:808"} {
		if got := g.Lookup(ip); got != "US" {
			t.Errorf("Lookup(%s) = %q, want US", ip, got)
		}
	}
}

func TestLookupHandlesNonsenseWithoutPanicking(t *testing.T) {
	g := loadSample(t)
	for _, ip := range []string{"", "   ", "not an address", "1.2.3", "999.999.999.999",
		"1.2.3.4:80", "<script>"} {
		if got := g.Lookup(ip); got != "" {
			t.Errorf("Lookup(%q) = %q, want empty", ip, got)
		}
	}
}

// No dataset at all is the state of a fresh install and of any machine with no
// route to the internet. It has to answer "unknown" rather than misbehave -
// geography is reporting, and reporting must not be able to break anything.
func TestAnEmptyDatasetAnswersUnknown(t *testing.T) {
	g := NewGeoIP()
	if got := g.Lookup("8.8.8.8"); got != "" {
		t.Errorf("with no data loaded, Lookup = %q, want empty", got)
	}
	if st := g.Status(); st.Ranges != 0 {
		t.Errorf("an empty dataset reported %d ranges", st.Ranges)
	}
}

func TestParserSkipsBadRowsRatherThanFailing(t *testing.T) {
	v4, v6, err := parseCSV(strings.NewReader(sampleCSV))
	if err != nil {
		t.Fatalf("three bad rows in a good file made the whole dataset unusable: %v", err)
	}
	if len(v4) != 5 {
		t.Errorf("kept %d IPv4 ranges, want 5", len(v4))
	}
	if len(v6) != 2 {
		t.Errorf("kept %d IPv6 ranges, want 2", len(v6))
	}
}

func TestAFileWithNothingUsableIsRefused(t *testing.T) {
	// Distinct from skipping bad rows: a file with no ranges at all is not a file
	// with a typo in it, and loading it would replace a working dataset with an
	// empty one.
	if _, _, err := parseCSV(strings.NewReader("garbage\nmore garbage\n")); err == nil {
		t.Error("a file containing no ranges was accepted")
	}
}

// The tables are searched by their upper bound, so they have to be sorted by it
// whatever order the file arrived in - the sample above is deliberately jumbled.
func TestRangesAreSorted(t *testing.T) {
	v4, v6, err := parseCSV(strings.NewReader(sampleCSV))
	if err != nil {
		t.Fatal(err)
	}
	for i := 1; i < len(v4); i++ {
		if v4[i-1].hi > v4[i].hi {
			t.Fatalf("IPv4 ranges are not sorted at %d", i)
		}
	}
	for i := 1; i < len(v6); i++ {
		prev, cur := v6[i-1], v6[i]
		if prev.hiHi > cur.hiHi || (prev.hiHi == cur.hiHi && prev.hiLo > cur.hiLo) {
			t.Fatalf("IPv6 ranges are not sorted at %d", i)
		}
	}
}
