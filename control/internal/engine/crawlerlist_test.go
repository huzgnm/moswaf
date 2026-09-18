package engine

import (
	"fmt"
	"strings"
	"testing"
)

// These ranges decide who is exempt from the JS challenge, and they arrive over
// the network from a third party. This is the one place in MosWAF where an
// outside document grants a privilege, so the tests are written from the
// position that the document is hostile.

// The sharpest one, and it only exists because IPv4-mapped addresses are folded.
//
// "::ffff:0:0/96" reads as a /96. By any rule that counts bits that is narrow -
// narrower than the /32 floor for IPv6. It is also every IPv4 address there is.
// A guard that judged the text rather than the range would wave it through and
// hand a verified-crawler exemption to the entire internet.
func TestMappedPrefixIsJudgedAsTheIPv4RangeItIs(t *testing.T) {
	cases := []struct {
		name string
		in   string
	}{
		{"all of IPv4 written as a /96", "::ffff:0:0/96"},
		{"all of IPv4 written the long way", "0:0:0:0:0:ffff:0:0/96"},
		{"half of IPv4 as a /97", "::ffff:0:0/97"},
		{"a /104 is a /8 and far too broad", "::ffff:1.0.0.0/104"},
		{"a /116 is a /20 and fine, but /107 is a /11 and is not", "::ffff:1.0.0.0/107"},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if p, err := ValidatePrefix(c.in); err == nil {
				t.Fatalf("%s was accepted as %s - every address behind it would be "+
					"exempt from the challenge", c.in, p)
			}
		})
	}

	// The same folding must still let a legitimately narrow mapped range through,
	// or a list that happens to write IPv4 in mapped form is rejected wholesale.
	p, err := ValidatePrefix("::ffff:66.249.64.0/115")
	if err != nil {
		t.Fatalf("a narrow mapped range was refused: %v", err)
	}
	if got := p.String(); got != "66.249.64.0/19" {
		t.Errorf("mapped /115 normalised to %s, want 66.249.64.0/19", got)
	}
}

func TestOverBroadPrefixesAreRefused(t *testing.T) {
	for _, in := range []string{
		"0.0.0.0/0",
		"0.0.0.0/7",
		"10.0.0.0/7",
		"::/0",
		"2001:db8::/31",
		"::/16",
	} {
		if p, err := ValidatePrefix(in); err == nil {
			t.Errorf("%s was accepted as %s", in, p)
		}
	}
}

func TestOrdinaryCrawlerRangesAreAccepted(t *testing.T) {
	cases := map[string]string{
		"66.249.64.0/19":      "66.249.64.0/19",
		"1.2.3.4/32":          "1.2.3.4/32",
		"10.0.0.0/12":         "10.0.0.0/12", // exactly at the limit
		"2001:4860:4801::/48": "2001:4860:4801::/48",
		"2001:db8::/32":       "2001:db8::/32", // exactly at the limit
		// Host bits are masked off, so one range has one spelling.
		"66.249.64.5/19": "66.249.64.0/19",
	}
	for in, want := range cases {
		p, err := ValidatePrefix(in)
		if err != nil {
			t.Errorf("%s was refused: %v", in, err)
			continue
		}
		if p.String() != want {
			t.Errorf("%s normalised to %s, want %s", in, p, want)
		}
	}
}

func TestMalformedEntriesAreDroppedNotFatal(t *testing.T) {
	// One bad line in an otherwise good list must not cost every crawler its
	// exemption - that would turn a typo at Google into challenged crawlers here.
	good, rejected, err := ValidateRanges("test", []string{
		"66.249.64.0/19",
		"not an address",
		"1.2.3.4/99",
		"",
		"2001:4860:4801::/48",
		"66.249.64.0/19", // duplicate
	})
	if err != nil {
		t.Fatalf("the list was refused outright: %v", err)
	}
	if len(good) != 2 {
		t.Errorf("kept %v, want the two valid ranges once each", good)
	}
	if len(rejected) != 3 {
		t.Errorf("reported %d rejections, want 3: %v", len(rejected), rejected)
	}
}

// The per-prefix guard is not enough on its own. Forty separate /8 entries are
// each narrow enough to pass it, and together they are the entire internet.
func TestManyNarrowPrefixesCannotCoverEverything(t *testing.T) {
	// Each of these is a /12, comfortably inside the per-prefix guard. Together
	// they are eight million addresses.
	var all []string
	for i := 0; i < 8; i++ {
		all = append(all, fmt.Sprintf("%d.0.0.0/12", i*16))
	}
	if _, _, err := ValidateRanges("greedy", all); err == nil {
		t.Fatal("eight /12 ranges were accepted; each passes the width guard and " +
			"together they exempt eight million addresses")
	} else if !strings.Contains(err.Error(), "keeping the previous list") {
		t.Errorf("the error should say the previous list is kept, got: %v", err)
	}
}

func TestAnAbsurdNumberOfPrefixesIsRefused(t *testing.T) {
	all := make([]string, maxPrefixes+1)
	for i := range all {
		all[i] = "1.2.3.4/32"
	}
	if _, _, err := ValidateRanges("flood", all); err == nil {
		t.Fatal("a list past the entry ceiling was accepted")
	}
}

// Refusing has to leave the previous list in place, not replace it with nothing.
// An empty list exempts nobody, so every real crawler is challenged the moment
// the site is under attack - which is exactly when losing search engines hurts.
func TestAListWithNothingUsableIsRefusedRatherThanEmptied(t *testing.T) {
	_, _, err := ValidateRanges("broken", []string{"nonsense", "0.0.0.0/0"})
	if err == nil {
		t.Fatal("a list with nothing valid in it was accepted as an empty list")
	}
}

func TestEmptyInputIsRefused(t *testing.T) {
	if _, _, err := ValidateRanges("silent", nil); err == nil {
		t.Fatal("an empty list was accepted; it would exempt nobody")
	}
}
