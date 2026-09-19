package main

import (
	"net/netip"
	"strings"
	"testing"
)

// The test this whole agent exists to pass.
//
// Everything else here can fail and the worst case is that a hostile address
// keeps costing CPU - which is where it was before any of this was written.
// Getting this wrong means programming the kernel to discard the operator's own
// packets, on a machine they can then only reach by walking to it.
func TestTheManagementAddressCanNeverBeDropped(t *testing.T) {
	nd, err := newNeverDrop([]string{"59.153.224.0/20"}, []string{"172.18.0.0/16"})
	if err != nil {
		t.Fatalf("building the refusal list: %v", err)
	}

	mustRefuse := []string{
		"59.153.228.62",  // the address the operator actually signs in from
		"59.153.224.0",   // and either end of the range they gave
		"59.153.239.255", //
		"127.0.0.1", "::1", "0.0.0.0",
		"10.0.0.5", "172.16.4.2", "192.168.1.10",
		"100.64.0.1",  // carrier NAT: one address shared by many real people
		"169.254.1.1", // link local, which is what an address means when DHCP failed
		"224.0.0.1",   // multicast
		"fe80::1", "fd00::1",
		// Multicast. Nothing with a multicast source can be a visitor - no unicast
		// reply could reach it - and the IPv4 side already refused 224/4. Catching
		// one and not the other was an asymmetry rather than a decision.
		"ff02::1", "ff00::1",
		"172.18.0.4",           // the container network the WAF talks to its own database over
		"::ffff:59.153.228.62", // and the management address written as IPv6
	}
	for _, s := range mustRefuse {
		addr, err := netip.ParseAddr(s)
		if err != nil {
			t.Fatalf("bad test address %q: %v", s, err)
		}
		ok, why := nd.covers(addr)
		if !ok {
			t.Errorf("%s would have been dropped in the kernel. This is the failure "+
				"that has no symptom until somebody cannot reach the machine they "+
				"were about to fix it from", s)
			continue
		}
		if why == "" {
			t.Errorf("%s was refused but nothing says which entry refused it; the "+
				"operator needs to recognise their own range in that line", s)
		}
	}

	// And an ordinary attacker is still droppable - a refusal list that refuses
	// everything protects nothing.
	for _, s := range []string{
		"8.8.8.8", "203.0.113.5", "46.203.233.214",
		"59.153.223.255", "59.153.240.0", // either side of the management range
		"2606:4700::1",
	} {
		addr := netip.MustParseAddr(s)
		if ok, _ := nd.covers(addr); ok {
			t.Errorf("%s was treated as never-droppable; an address an attacker can "+
				"hold must stay droppable or the feature does nothing", s)
		}
	}
}

// Starting with no management address is not a permissive configuration, it is
// an unfinished one. The agent would run perfectly and drop everything it was
// told to - including, one day, the person who installed it.
func TestItRefusesToStartWithoutAManagementAddress(t *testing.T) {
	for _, empty := range [][]string{nil, {}, {""}, {"  "}} {
		_, err := newNeverDrop(empty, nil)
		if err == nil {
			t.Errorf("started with management addresses %q", empty)
			continue
		}
		if !strings.Contains(err.Error(), "MOSWAF_KBANS_ALLOW") {
			t.Errorf("the refusal does not say how to fix it: %v", err)
		}
	}

	if _, err := newNeverDrop([]string{"not an address"}, nil); err == nil {
		t.Error("an unparseable management address was accepted; it would have " +
			"protected nothing while looking configured")
	}
}

// A bare address is a /32, because somebody writing one address should not have
// to remember the suffix - and if that were silently misread the entry would
// protect nothing.
func TestABareAddressIsAcceptedAsItself(t *testing.T) {
	nd, err := newNeverDrop([]string{"59.153.228.62"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if ok, _ := nd.covers(netip.MustParseAddr("59.153.228.62")); !ok {
		t.Error("the single management address does not protect itself")
	}
	// ...and only itself.
	if ok, _ := nd.covers(netip.MustParseAddr("59.153.228.63")); ok {
		t.Error("a bare address protected its neighbour too; it should be one host")
	}
}
