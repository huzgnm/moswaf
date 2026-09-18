package engine

import (
	"fmt"
	"math"
	"net/netip"
	"sort"
	"strings"
)

// Validation for the published crawler address ranges.
//
// These ranges decide who is exempt from the JS challenge, so whatever ends up
// in them is trusted by the engine without any further question being asked.
// The list arrives over the network from a third party, which makes this the one
// place in MosWAF where an outside document grants a privilege - and the only
// defence against a compromised or intercepted source is refusing to believe
// what it says.
//
// The same checks run on the bundled snapshot. It ships inside the repository,
// which is a reason to trust the pipeline, not a reason to skip the validation:
// a fork, a bad merge or a tampered release would all arrive by that path.

const (
	// A prefix broader than this is refused outright.
	//
	// Real crawler ranges are small: Google's largest published block is a /19,
	// eight thousand addresses. A /12 is a million - two hundred and fifty times
	// the largest real one - so it is far past anything legitimate while leaving
	// no room to argue that a genuine operator was refused.
	//
	// It is also deliberately no broader than the whole-list ceiling below. A
	// per-prefix limit that permits what the total forbids is a rule that
	// contradicts itself, and the looser half is the one an attacker reads.
	minIPv4Bits = 12
	minIPv6Bits = 32

	// And a ceiling on the whole list, because the guard above is per prefix:
	// separate entries can each be narrow enough and together cover the internet.
	// Four million addresses is far above everything every crawler operator
	// publishes put together, and far below a number worth having.
	maxIPv4Addresses = 1 << 22

	// A list is a few hundred entries. This is not a tuning parameter; it is the
	// point past which the document is not a crawler list any more.
	maxPrefixes = 4096
)

// CrawlerRanges is one operator's published address space.
type CrawlerRanges struct {
	Name     string   `json:"name"`
	Prefixes []string `json:"prefixes"`
}

// normalisePrefix returns the prefix as it will actually be matched.
//
// An IPv4-mapped IPv6 prefix is an IPv4 prefix, and it has to be judged as one.
// "::ffff:0:0/96" reads as a /96 - narrow, by any rule that counts bits - and
// covers every IPv4 address there is. A guard that looked at the text would wave
// it through and hand a verified-crawler exemption to the entire internet.
func normalisePrefix(p netip.Prefix) netip.Prefix {
	if p.Addr().Is4In6() && p.Bits() >= 96 {
		return netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-96)
	}
	// A mapped address with fewer than 96 bits does not describe an IPv4 range at
	// all - it spans the boundary of the mapped block - so it is left as IPv6 and
	// the IPv6 width guard will refuse it.
	return p
}

// ValidatePrefix accepts one entry, or explains why it cannot be trusted.
func ValidatePrefix(raw string) (netip.Prefix, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return netip.Prefix{}, fmt.Errorf("empty prefix")
	}

	p, err := netip.ParsePrefix(s)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("%q is not an address range: %w", s, err)
	}

	// Masked: 1.2.3.4/24 names the range 1.2.3.0/24, and keeping the host bits
	// would make two spellings of one range look like two ranges.
	p = normalisePrefix(p.Masked())

	if p.Addr().Is4() {
		if p.Bits() < minIPv4Bits {
			return netip.Prefix{}, fmt.Errorf(
				"%q covers %s, which is broader than the /%d limit - no crawler operator "+
					"owns that much of the internet", s, p, minIPv4Bits)
		}
	} else if p.Bits() < minIPv6Bits {
		return netip.Prefix{}, fmt.Errorf(
			"%q covers %s, which is broader than the /%d limit", s, p, minIPv6Bits)
	}

	return p, nil
}

// ipv4Size is how many addresses a prefix covers, for the total ceiling.
func ipv4Size(p netip.Prefix) float64 {
	if !p.Addr().Is4() {
		return 0
	}
	return math.Pow(2, float64(32-p.Bits()))
}

// ValidateRanges filters a published list down to what may be trusted.
//
// Entries are dropped individually rather than failing the whole document: one
// malformed line in an otherwise good list should not cost every crawler its
// exemption. The ceilings are different - a list that trips one of those is not
// a list with a bad line in it, it is a list that is trying to cover everything,
// and the right answer is to keep the one already in use.
func ValidateRanges(name string, raw []string) ([]string, []string, error) {
	if len(raw) > maxPrefixes {
		return nil, nil, fmt.Errorf(
			"%s published %d ranges, past the %d limit; keeping the previous list",
			name, len(raw), maxPrefixes)
	}

	var (
		out      []string
		rejected []string
		total    float64
		seen     = map[string]bool{}
	)

	for _, r := range raw {
		p, err := ValidatePrefix(r)
		if err != nil {
			rejected = append(rejected, err.Error())
			continue
		}
		s := p.String()
		if seen[s] {
			continue
		}
		seen[s] = true
		total += ipv4Size(p)
		out = append(out, s)
	}

	if total > maxIPv4Addresses {
		return nil, rejected, fmt.Errorf(
			"%s published ranges covering %.0f IPv4 addresses, past the %d limit; "+
				"keeping the previous list", name, total, maxIPv4Addresses)
	}
	if len(out) == 0 {
		// An empty list is not a safe default in either direction: it would exempt
		// nobody, so every real crawler gets challenged the moment the site is under
		// attack. Refusing leaves the previous list in place, which is the better of
		// the two.
		return nil, rejected, fmt.Errorf("%s published nothing usable", name)
	}

	sort.Strings(out)
	return out, rejected, nil
}
