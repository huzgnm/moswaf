package engine

import "testing"

func TestBundledSnapshotLoadsAndValidates(t *testing.T) {
	c := NewCrawlers()
	r := c.Ranges()
	if len(r) == 0 {
		t.Fatal("the bundled snapshot produced no ranges at all; every installation " +
			"without outbound internet would verify no crawler and challenge them all")
	}
	for name, prefixes := range r {
		if len(prefixes) == 0 {
			t.Errorf("%s has no usable ranges", name)
		}
		t.Logf("  %-16s %d ranges", name, len(prefixes))
	}
	for _, want := range []string{"googlebot", "bingbot"} {
		if len(r[want]) == 0 {
			t.Errorf("%s is missing from the bundled snapshot", want)
		}
	}
}
