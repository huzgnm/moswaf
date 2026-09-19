package main

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
)

func mustAddr(t *testing.T, s string) netip.Addr {
	t.Helper()
	a, err := netip.ParseAddr(s)
	if err != nil {
		t.Fatalf("%q: %v", s, err)
	}
	return a
}

// The race this exists for, written out as the sequence it actually happens in.
//
//	t=0   a reconcile starts and fetches the ban list; 1.2.3.4 is on it
//	t=1   the operator presses unban; the release event removes it from the kernel
//	t=2   that same reconcile reaches its add-pass, still holding the t=0 list,
//	      and puts 1.2.3.4 straight back
//
// The operator's screen says unbanned. The address cannot reach the machine for
// up to a minute. Self-healing, but a minute is long enough to press the button
// again, see nothing change, and conclude the product is broken.
func TestAReleasedAddressIsNotReAddedFromAStaleList(t *testing.T) {
	ts := newTombstones()
	ip := mustAddr(t, "1.2.3.4")
	now := time.Now()

	if ts.held(ip, now) {
		t.Fatal("an address nobody released is being held back")
	}

	ts.mark(ip, time.Minute)
	if !ts.held(ip, now) {
		t.Fatal("a just-released address would be re-added by a reconcile " +
			"working from a ban list fetched before the release. That is the " +
			"whole bug: the dashboard says unbanned and the kernel goes on " +
			"dropping for up to a full resync interval")
	}
}

// The note has to expire, or the first unban of an address would make it
// permanently unbannable.
func TestTheHoldEndsOnItsOwn(t *testing.T) {
	ts := newTombstones()
	ip := mustAddr(t, "1.2.3.4")
	now := time.Now()

	ts.mark(ip, time.Minute)
	if ts.held(ip, now.Add(61*time.Second)) {
		t.Fatal("the hold outlived its window. An address released once would " +
			"never be enforceable again, which turns a temporary workaround " +
			"into a permanent hole somebody could unban their way into")
	}
}

// A fresh ban inside the window must win.
func TestABanAfterAReleaseIsNotRefusedByTheOldRelease(t *testing.T) {
	ts := newTombstones()
	ip := mustAddr(t, "1.2.3.4")
	now := time.Now()

	ts.mark(ip, time.Minute)
	ts.clear(ip) // a drop event arrived: this address is a problem again

	if ts.held(ip, now) {
		t.Fatal("a note from the previous ban is refusing enforcement to a " +
			"decision made now. The drop event is newer information than the " +
			"release, and an attacker who got themselves unbanned once would " +
			"otherwise have a free minute every time")
	}
}

// One address being released must not hold back another.
func TestTheHoldIsPerAddress(t *testing.T) {
	ts := newTombstones()
	now := time.Now()

	ts.mark(mustAddr(t, "1.2.3.4"), time.Minute)
	if ts.held(mustAddr(t, "5.6.7.8"), now) {
		t.Fatal("releasing one address held back a different one. Under a flood " +
			"that is enforcement switched off for everybody by one unban")
	}
}

// The map must not become a record of every release this process ever saw.
func TestExpiredNotesArePruned(t *testing.T) {
	ts := newTombstones()
	now := time.Now()

	for i := 1; i <= 50; i++ {
		ts.mark(netip.AddrFrom4([4]byte{10, 0, 0, byte(i)}), time.Minute)
	}
	ts.mark(mustAddr(t, "203.0.113.1"), time.Hour)

	ts.prune(now.Add(2 * time.Minute))
	if n := ts.len(); n != 1 {
		t.Fatalf("pruning left %d notes, expected only the one still inside its "+
			"window; during a sustained flood with unbans this map is the one "+
			"thing here that grows without bound", n)
	}
	if !ts.held(mustAddr(t, "203.0.113.1"), now.Add(2*time.Minute)) {
		t.Fatal("pruning removed a note that had not expired")
	}
}

// The window has to outlast the snapshot that caused the problem.
func TestTheHoldOutlastsTwoReconcileCycles(t *testing.T) {
	a := &agent{cfg: config{resyncEvery: 60 * time.Second}}
	if got := a.holdFor(); got < 2*a.cfg.resyncEvery {
		t.Fatalf("hold is %s for a %s resync. A release arriving in the middle "+
			"of a cycle has to outlive the rest of that cycle AND the ban-list "+
			"snapshot it was working from; one interval covers only the first",
			got, a.cfg.resyncEvery)
	}
}

// ----------------------------------------------------- the wiring itself
//
// Everything above tests the note. These test that the agent reads it - which is
// where the bug would actually live, and where a mutation of the reconcile loop
// slipped past the tests above without failing anything.

func testAgent(t *testing.T) *agent {
	t.Helper()
	nd, err := newNeverDrop([]string{"59.153.224.0/20"}, []string{"172.17.0.0/16"})
	if err != nil {
		t.Fatal(err)
	}
	return &agent{
		cfg:  config{resyncEvery: 60 * time.Second},
		nd:   nd,
		nft:  &nftables{dryRun: true},
		just: newTombstones(),
	}
}

func TestReconcileDoesNotWantAnAddressItJustReleased(t *testing.T) {
	a := testAgent(t)
	now := time.Now()
	bans := []banRow{{IP: "1.2.3.4", TTL: 600}, {IP: "5.6.7.8", TTL: 600}}

	want := a.desired(bans, now)
	if len(want) != 2 {
		t.Fatalf("expected both bans to be wanted, got %d", len(want))
	}

	// The operator presses unban. The list above is the snapshot this cycle is
	// still holding.
	a.just.mark(mustAddr(t, "1.2.3.4"), a.holdFor())

	want = a.desired(bans, now)
	if _, still := want[mustAddr(t, "1.2.3.4")]; still || len(want) != 1 {
		t.Fatalf("the reconcile still wants %d addresses. It is about to re-add "+
			"the one that was just unbanned, from a ban list it fetched before "+
			"the unban happened - and the dashboard will show it lifted while "+
			"the kernel goes on dropping for up to a full resync interval",
			len(want))
	}
	if _, ok := want[mustAddr(t, "5.6.7.8")]; !ok {
		t.Fatal("releasing one address stopped another from being enforced")
	}
}

func TestReconcileNeverWantsAProtectedAddress(t *testing.T) {
	a := testAgent(t)
	// A ban on the operator's own address does happen - it is what started this
	// whole line of work. It must never become a kernel rule.
	want := a.desired([]banRow{
		{IP: "59.153.228.62", TTL: 600},
		{IP: "127.0.0.1", TTL: 600},
		{IP: "172.17.0.5", TTL: 600},
	}, time.Now())
	if len(want) != 0 {
		t.Fatalf("the reconcile wants to drop %d protected address(es)", len(want))
	}
}

func TestReconcileIgnoresRubbishRatherThanFailing(t *testing.T) {
	a := testAgent(t)
	want := a.desired([]banRow{
		{IP: "not-an-address", TTL: 600},
		{IP: "1.2.3.4", TTL: 0},  // expired between the fetch and here
		{IP: "1.2.3.5", TTL: -1}, // nonsense
		{IP: "1.2.3.6", TTL: 600},
	}, time.Now())
	if len(want) != 1 {
		t.Fatalf("expected only the one good row, got %d", len(want))
	}
}

func TestDropClearsTheHoldSoAFreshBanTakesEffect(t *testing.T) {
	a := testAgent(t)
	// A client that is never dialled: the context below is already cancelled, so
	// go-redis returns that error without touching the network. Cheaper than a
	// fake and it exercises the same call the real agent makes.
	a.rdb = redis.NewClient(&redis.Options{Addr: "127.0.0.1:1"})
	ip := mustAddr(t, "203.0.113.50")
	a.just.mark(ip, a.holdFor())

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	a.drop(ctx, ip, 600)

	if a.just.held(ip, time.Now()) {
		t.Fatal("a new ban did not clear the note left by the previous release. " +
			"The reconcile will refuse to enforce a decision made just now " +
			"because of one that was undone a minute ago - so an attacker who " +
			"got themselves unbanned once gets a free minute every time")
	}
}
