package api

import (
	"encoding/json"
	"io"
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

// The overview's qps is the field that was not guarded, and its failure mode is
// worse than a wrong number: JSON cannot represent Inf or NaN, so the encoder
// rejects the whole document. writeJSON has already sent 200 and the headers by
// then, so the caller receives a successful response with an empty body and the
// dashboard shows nothing at all - not one blank tile, the whole page.
//
// Reproduced through the encoder rather than by comparing floats, because the
// encoder is what actually breaks.
func TestQPSNeverProducesAValueJSONCannotEncode(t *testing.T) {
	cases := []struct {
		name    string
		count   int64
		seconds int
	}{
		{"no window at all, busy site", 100000, 0},   // was +Inf
		{"no window at all, quiet site", 0, 0},       // was NaN
		{"a negative window", 500, -3600},
		{"an ordinary day", 86400, 86400},
		{"a quiet day", 0, 86400},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := perSecond(c.count, c.seconds)
			if math.IsNaN(got) || math.IsInf(got, 0) {
				t.Fatalf("perSecond(%d, %d) = %v", c.count, c.seconds, got)
			}
			// The real check: does the response still encode?
			if err := json.NewEncoder(io.Discard).Encode(map[string]any{"qps": got}); err != nil {
				t.Fatalf("perSecond(%d, %d) = %v, which fails to encode (%v) - the "+
					"whole overview response would arrive empty behind a 200",
					c.count, c.seconds, got, err)
			}
		})
	}

	if got := perSecond(86400, 86400); got != 1 {
		t.Errorf("perSecond(86400, 86400) = %v, want 1", got)
	}
}

// hours arrives from a query string, so it is whatever the caller typed. Zero is
// the division by zero above; a very large value makes uniqueCounts allocate one
// Redis key per hour and ask for the union of all of them, and overflows
// time.Duration(hours)*time.Hour past about 2.5 million hours - after which the
// window start is garbage and the totals are quietly wrong rather than obviously
// so. Clamping is what keeps both impossible.
func TestClampHoursKeepsTheWindowUsable(t *testing.T) {
	cases := []struct{ in, want int }{
		{0, minHours},
		{-1, minHours},
		{-2000000, minHours},
		{1, 1},
		{24, 24},
		{168, 168},
		{169, maxHours},
		{3000000, maxHours},
		{1 << 40, maxHours},
	}
	for _, c := range cases {
		if got := clampHours(c.in); got != c.want {
			t.Errorf("clampHours(%d) = %d, want %d", c.in, got, c.want)
		}
	}

	// The property that matters downstream: whatever came in, the window is a
	// positive number of hours that cannot overflow a time.Duration.
	for _, in := range []int{0, -5, 1 << 40, -(1 << 40)} {
		h := clampHours(in)
		if h < minHours || h > maxHours {
			t.Fatalf("clampHours(%d) = %d, outside [%d, %d]", in, h, minHours, maxHours)
		}
		if perSecond(1, h*3600) == 0 && h > 0 {
			continue // fine: a single request over hours rounds to 0.00
		}
	}
}
