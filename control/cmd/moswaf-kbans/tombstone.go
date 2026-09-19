package main

// Remembering, briefly, that an address was just let go.
//
// The agent has two ways of learning things and they do not agree instantly. The
// feed is immediate: somebody presses unban, a release event arrives, the kernel
// entry goes. The reconcile is periodic and works from a snapshot of the ban list
// it fetched at the top of its cycle - and if that fetch happened a moment before
// the unban, the snapshot still contains the address. The add-pass then puts it
// straight back.
//
// The result is the exact state the whole release ordering exists to prevent,
// with a timer on it: the dashboard reports the ban lifted, the operator sees
// "unbanned", and the address still cannot reach the machine for up to a minute.
// Self-healing, but a minute is long enough for somebody to press the button
// again, see nothing change, and conclude the product does not work.
//
// So a release leaves a note, and the reconcile reads it before adding anything.
//
// Deliberately in memory and not in Redis. It is a statement about one cycle of
// one process, and the only thing that could lose it - this process restarting -
// also destroys the stale snapshot that made it necessary: a fresh agent fetches
// a fresh ban list, which no longer has the address in it.

import (
	"net/netip"
	"sync"
	"time"
)

type tombstones struct {
	mu   sync.Mutex
	upto map[netip.Addr]time.Time
}

func newTombstones() *tombstones {
	return &tombstones{upto: map[netip.Addr]time.Time{}}
}

// mark says: do not re-add this address before `d` has passed.
//
// Two reconcile intervals rather than one. A release arriving in the middle of a
// cycle has to outlive the rest of that cycle AND the snapshot it was working
// from, and one interval covers only the first.
func (t *tombstones) mark(addr netip.Addr, d time.Duration) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.upto[addr] = time.Now().Add(d)
}

// clear forgets the note, because the address was banned again.
//
// Without this a fresh ban inside the window would be refused enforcement by a
// note left over from the previous one - punishing the new decision with the old
// one. A drop event is the system saying "this address is a problem again", and
// that is newer information than the release.
func (t *tombstones) clear(addr netip.Addr) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.upto, addr)
}

// held reports whether this address is still inside its window.
func (t *tombstones) held(addr netip.Addr, now time.Time) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	until, ok := t.upto[addr]
	return ok && now.Before(until)
}

// prune drops expired notes so the map tracks recent releases rather than every
// release this process has ever seen.
func (t *tombstones) prune(now time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for addr, until := range t.upto {
		if !now.Before(until) {
			delete(t.upto, addr)
		}
	}
}

func (t *tombstones) len() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.upto)
}
