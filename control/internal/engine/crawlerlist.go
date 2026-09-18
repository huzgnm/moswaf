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

	// Every IPv6 range the four operators actually publish is a /64 - all 283 of
	// them in the bundled snapshot. A /48 is sixteen bits of headroom on that and
	// still narrow enough to mean something; the /32 this started at was sixty
	// five thousand times wider than any real one, which made the IPv6 half of
	// this validator decorative.
	minIPv6Bits = 48

	// And ceilings on the whole list, because the guards above are per prefix:
	// separate entries can each be narrow enough and together cover everything.
	//
	// Two ceilings, because one number cannot hold both families. Counting IPv6 in
	// addresses would drown IPv4 entirely - a single /64 is four billion times an
	// entire IPv4 internet - so IPv6 is counted in /64s, the unit it is actually
	// handed out in. Leaving IPv6 out of the total, which is what the first
	// version did, meant there was no aggregate limit on it at all.
	maxIPv4Addresses = 1 << 22 // four million addresses
	maxIPv6Subnets   = 1 << 20 // a million /64s, against 283 in the real lists

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
// mapped says whether the prefix was written in IPv4-mapped form, and it has to
// be asked BEFORE the prefix is masked. Masking ::ffff:0:0/95 clears the last bit
// of the ffff marker, giving ::fffe:0:0/95 - which is no longer recognisable as
// mapped at all, so a check made after masking sees an ordinary IPv6 range and
// waves it through. The same happens to every mapped prefix shorter than /96.
func normalisePrefix(p netip.Prefix, mapped bool) (netip.Prefix, error) {
	if !mapped {
		return p, nil
	}
	if p.Bits() >= 96 {
		return netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-96), nil
	}
	// A mapped address with fewer than 96 bits does not describe an IPv4 range:
	// it reaches outside the mapped block into space that is not IPv4 at all.
	// ::ffff:0:0/95 masks to ::fffe:0:0/95, ::ffff:0:0/40 masks to ::/40 - both
	// wide, neither meaningful, and the earlier comment here claimed the IPv6
	// width guard would refuse them, which it did not: they sat above the floor.
	// There is no reading of such an entry that a crawler operator meant, so it
	// is refused rather than interpreted.
	return netip.Prefix{}, fmt.Errorf(
		"%s is an IPv4-mapped prefix shorter than /96, which describes no IPv4 range", p)
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
	mapped := p.Addr().Is4In6()
	p, err = normalisePrefix(p.Masked(), mapped)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("%q: %w", s, err)
	}

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

// ipv4Size is how many addresses a prefix covers, for the IPv4 ceiling.
func ipv4Size(p netip.Prefix) float64 {
	if !p.Addr().Is4() {
		return 0
	}
	return math.Pow(2, float64(32-p.Bits()))
}

// ipv6Subnets is how many /64s a prefix covers, for the IPv6 ceiling.
//
// /64 is the unit IPv6 is handed out in, and it keeps the number in a range that
// means something: counting addresses instead would put a single /64 at
// eighteen quintillion and make every comparison meaningless.
func ipv6Subnets(p netip.Prefix) float64 {
	if p.Addr().Is4() || p.Bits() > 64 {
		return 0
	}
	return math.Pow(2, float64(64-p.Bits()))
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
		totalV6  float64
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
		totalV6 += ipv6Subnets(p)
		out = append(out, s)
	}

	if total > maxIPv4Addresses {
		return nil, rejected, fmt.Errorf(
			"%s published ranges covering %.0f IPv4 addresses, past the %d limit; "+
				"keeping the previous list", name, total, maxIPv4Addresses)
	}
	if totalV6 > maxIPv6Subnets {
		return nil, rejected, fmt.Errorf(
			"%s published ranges covering %.0f IPv6 /64 subnets, past the %d limit; "+
				"keeping the previous list", name, totalV6, maxIPv6Subnets)
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
