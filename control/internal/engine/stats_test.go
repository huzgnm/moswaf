package engine

import "testing"

// The per-minute counters are shipped as absolute values under one key per data
// plane host, and the control plane adds them up. Before that they shared a
// single key per minute, so two hosts writing the same minute overwrote each
// other: the last writer won, and the database recorded whichever host happened
// to finish last rather than the traffic both of them served. A two-host
// deployment under-reported roughly by half, quietly and permanently - the
// graph simply looked like a smaller site.
//
// statMinute is what makes the sum possible, so it has to read both shapes: the
// keys a current data plane writes, and the keys an older one wrote, which
// survive for two hours after an upgrade. Dropping the old shape would put a
// two hour hole in the graph of every installation the moment it updates.
func TestStatMinuteReadsBothKeyShapes(t *testing.T) {
	cases := []struct {
		name string
		key  string
		want int64
		ok   bool
	}{
		{"with a host, as written now", "moswaf:stat:1789729140:proxy-01", 1789729140, true},
		{"a second host, same minute", "moswaf:stat:1789729140:proxy-02", 1789729140, true},
		{"without a host, written before the upgrade", "moswaf:stat:1789729140", 1789729140, true},
		{"a hostname with dots and dashes", "moswaf:stat:1789729140:edge-3.ams.example", 1789729140, true},

		{"not a minute at all", "moswaf:stat:notanumber", 0, false},
		{"empty minute", "moswaf:stat:", 0, false},
		{"empty minute with a host", "moswaf:stat::proxy-01", 0, false},
		{"a different key that shares the prefix", "moswaf:stats-something", 0, false},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, ok := statMinute(c.key)
			if ok != c.ok {
				t.Fatalf("statMinute(%q) ok = %v, want %v", c.key, ok, c.ok)
			}
			if ok && got != c.want {
				t.Errorf("statMinute(%q) = %d, want %d", c.key, got, c.want)
			}
		})
	}
}

// Two hosts serving the same minute have to land on the same bucket, or the sum
// never happens no matter how carefully absorbStat adds.
func TestKeysFromDifferentHostsShareOneMinute(t *testing.T) {
	a, okA := statMinute("moswaf:stat:1789729140:proxy-01")
	b, okB := statMinute("moswaf:stat:1789729140:proxy-02")
	if !okA || !okB {
		t.Fatal("both keys should parse")
	}
	if a != b {
		t.Fatalf("two hosts in the same minute parsed to %d and %d; their counters "+
			"would be written as separate rows instead of being added together", a, b)
	}
}
