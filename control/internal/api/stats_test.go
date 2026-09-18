package api

import (
	"math"
	"testing"
)

// rate feeds the percentages on the dashboard's tiles. Every one of them divides
// by a total that is zero on a quiet site, on a new install, and for any window
// that ended up empty - so the case that must not produce NaN is the ordinary
// one, not the edge one. JSON has no NaN: encoding/json fails the whole response
// rather than writing it, so a single division by zero here does not garble one
// tile, it blanks the entire overview.
func TestRateHandlesAnEmptyWindow(t *testing.T) {
	cases := []struct {
		name        string
		part, whole int64
		want        float64
	}{
		{"no traffic at all", 0, 0, 0},
		{"blocked nothing out of nothing", 0, 0, 0},
		{"a count with no total cannot be a percentage", 5, 0, 0},
		{"everything blocked", 100, 100, 100},
		{"nothing blocked", 0, 100, 0},
		{"a third", 1, 3, 33.3},
		{"two thirds", 2, 3, 66.7},
		{"rounds to one decimal", 1, 8, 12.5},
		{"a very small share is not rounded away to zero", 1, 1000, 0.1},
		{"smaller still does round to zero", 1, 100000, 0},
		{"a negative total is nonsense and yields zero", 5, -1, 0},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := rate(c.part, c.whole)
			if math.IsNaN(got) || math.IsInf(got, 0) {
				t.Fatalf("rate(%d, %d) = %v; JSON cannot encode that, so the whole "+
					"overview response would fail rather than one tile", c.part, c.whole, got)
			}
			if got != c.want {
				t.Errorf("rate(%d, %d) = %v, want %v", c.part, c.whole, got, c.want)
			}
		})
	}
}

// The tiles read as percentages, so a share can exceed 100 only if the inputs are
// inconsistent - and it is worth knowing that the function reports what it was
// given rather than quietly clamping, because a blocked count above the total
// means the counters disagree and that is the thing to investigate.
func TestRateDoesNotHideInconsistentCounters(t *testing.T) {
	if got := rate(150, 100); got != 150 {
		t.Errorf("rate(150, 100) = %v, want 150 - clamping would hide that the "+
			"blocked count exceeds the total", got)
	}
}
