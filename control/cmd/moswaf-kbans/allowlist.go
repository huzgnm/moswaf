package main

import (
	"fmt"
	"net/netip"
	"strings"
)

// The addresses this agent will never ask the kernel to drop, whatever it is
// told to drop.
//
// This is the part that must not be wrong. Everything else here can fail and the
// worst case is that a hostile address keeps costing CPU - which is where it was
// before any of this existed. Getting THIS wrong means programming the kernel to
// discard the operator's own packets, on a machine they can then only reach by
// walking to it.
//
// So the check lives in the agent, before the insert, and not only in the
// nftables ruleset. The ruleset has an accept rule for these addresses too, and
// that is real defence - but it defends against the kernel matching them, not
// against this process being handed a list that contains them. A ban feed that
// somehow named the management address, through a bug here or a forged internal
// call, must not be able to program a drop for it. So it is refused twice, in two
// places, for two different reasons.

// neverDrop is what the agent refuses, built once at start.
type neverDrop struct {
	prefixes []netip.Prefix
	// The management ranges as the operator wrote them, for the log line that
	// says why something was refused. The operator needs to recognise their own
	// entry in it.
	management []string
}

// Ranges nobody on the internet can be arriving from, so nothing here is ever a
// visitor worth dropping - and several of them are how a machine talks to itself.
var infrastructure = []string{
	"0.0.0.0/8",      // "this network"
	"10.0.0.0/8",     // private
	"100.64.0.0/10",  // carrier NAT - shared by many real people
	"127.0.0.0/8",    // loopback
	"169.254.0.0/16", // link local, which is what an address means when DHCP failed
	"172.16.0.0/12",  // private
	"192.168.0.0/16", // private
	"224.0.0.0/4",    // multicast
	"240.0.0.0/4",    // reserved
	"ff00::/8",       // multicast - the IPv6 side of 224/4 above
	"::1/128",        // loopback
	"::/128",         // unspecified
	"fc00::/7",       // unique local
	"fe80::/10",      // link local
}

// newNeverDrop builds the refusal list, and refuses to build at all without at
// least one management range.
//
// Starting without one is the failure that has no symptom until it is too late:
// the agent would run perfectly, drop everything it was told to, and one day the
// thing it was told to drop would be the person who installed it. An empty list
// is not a permissive configuration, it is an unfinished one, and it is better to
// fail at install - loudly, while somebody is watching - than at three in the
// morning during the flood this was built for.
func newNeverDrop(managementCIDRs []string, dockerSubnets []string) (*neverDrop, error) {
	nd := &neverDrop{}

	for _, raw := range managementCIDRs {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		p, err := parsePrefix(raw)
		if err != nil {
			return nil, fmt.Errorf("management address %q: %w", raw, err)
		}
		nd.prefixes = append(nd.prefixes, p)
		nd.management = append(nd.management, p.String())
	}

	if len(nd.management) == 0 {
		return nil, fmt.Errorf(
			"no management address configured. This agent programs the kernel to " +
				"discard packets; without knowing which addresses administer this " +
				"machine it could be asked to discard yours, and you would find out " +
				"by losing the connection you were about to fix it over. Set " +
				"MOSWAF_KBANS_ALLOW to the address or range you reach this server from")
	}

	for _, raw := range infrastructure {
		p, err := parsePrefix(raw)
		if err != nil {
			return nil, err // a constant in this file is wrong; that is a build error
		}
		nd.prefixes = append(nd.prefixes, p)
	}

	// Whatever the containers talk to each other over. Dropping one of these
	// would cut the WAF off from its own database rather than cut off an attacker.
	for _, raw := range dockerSubnets {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		p, err := parsePrefix(raw)
		if err != nil {
			return nil, fmt.Errorf("container subnet %q: %w", raw, err)
		}
		nd.prefixes = append(nd.prefixes, p)
	}

	return nd, nil
}

// covers reports whether an address must never be dropped, and why.
//
// The reason is returned so the log can say which entry refused it. "Refused to
// drop 59.153.228.62" is a line somebody has to go and investigate; "refused to
// drop 59.153.228.62, it is in your management range 59.153.224.0/20" is a line
// that explains itself.
func (n *neverDrop) covers(addr netip.Addr) (bool, string) {
	addr = addr.Unmap()
	for _, p := range n.prefixes {
		// An address and a prefix of different families never match, and asking
		// avoids netip's answer of "false" being mistaken for a real comparison.
		if p.Addr().Is4() != addr.Is4() {
			continue
		}
		if p.Contains(addr) {
			return true, p.String()
		}
	}
	return false, ""
}

// parsePrefix accepts a bare address as well as a CIDR, because an operator
// writing one address should not have to remember to append /32.
func parsePrefix(raw string) (netip.Prefix, error) {
	if strings.Contains(raw, "/") {
		p, err := netip.ParsePrefix(raw)
		if err != nil {
			return netip.Prefix{}, err
		}
		return p.Masked(), nil
	}
	a, err := netip.ParseAddr(raw)
	if err != nil {
		return netip.Prefix{}, err
	}
	return netip.PrefixFrom(a.Unmap(), a.Unmap().BitLen()), nil
}
