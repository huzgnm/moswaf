package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"os/exec"
	"strings"
	"time"
)

// Talking to nftables, through the nft command rather than the netlink socket.
//
// The socket would be faster and would not need a binary on the host. It would
// also mean this program building netlink messages by hand, for a subsystem where
// a malformed message is not an error message but a ruleset that does something
// other than what was meant. The volume here is a few hundred elements a minute;
// there is nothing to buy with the speed, and quite a lot to lose.

const (
	tableFamily = "inet"
	tableName   = "moswaf"
	set4        = "ban4"
	set6        = "ban6"
)

type nftables struct {
	dryRun      bool
	maxElements int
}

func (n *nftables) run(args ...string) (string, error) {
	if n.dryRun {
		return "", nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "nft", args...)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		return out.String(), fmt.Errorf("nft %s: %w: %s",
			strings.Join(args, " "), err, strings.TrimSpace(errb.String()))
	}
	return out.String(), nil
}

// The ruleset, written as one atomic definition.
//
// Three properties are deliberate and none of them is cosmetic:
//
//   policy accept - this chain can only ever drop somebody it was told to drop.
//   It never becomes a default-deny, so no mistake in this program, and no
//   failure to run it, can black-hole the machine.
//
//   ct state established,related accept, first - an administrator's session that
//   is already open is never cut, even if their address somehow enters a ban set
//   while they are working. Losing a connection mid-repair is how a fixable
//   problem becomes a trip to the datacentre.
//
//   its own table - created and modified here, and nothing else on the machine is
//   read or flushed. Somebody else's firewall is somebody else's.
const ruleset = `
table inet moswaf {
	set ban4 { type ipv4_addr; flags timeout; }
	set ban6 { type ipv6_addr; flags timeout; }
	chain input {
		type filter hook input priority -150; policy accept;
		ct state established,related accept
		ip saddr @ban4 drop
		ip6 saddr @ban6 drop
	}
}
`

// ensureTable makes the table exist, and is safe to run twice.
func (n *nftables) ensureTable() error {
	if n.dryRun {
		return nil
	}
	// "add" rather than "create" throughout: add is idempotent, create fails if
	// the object exists. Installing twice must be a no-op, not an error somebody
	// has to interpret.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "nft", "-f", "-")
	cmd.Stdin = strings.NewReader(ruleset)
	var errb bytes.Buffer
	cmd.Stderr = &errb
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%w: %s", err, strings.TrimSpace(errb.String()))
	}
	return nil
}

func setFor(addr netip.Addr) string {
	if addr.Is4() {
		return set4
	}
	return set6
}

// add programs one address, with the kernel holding its own expiry.
//
// The timeout is what makes a dead agent survivable: if this process never runs
// again, every element it left drains away by itself. Without it, a crash would
// leave permanent drops that only somebody with a shell could remove - and the
// address they would need the shell from might be one of them.
func (n *nftables) add(addr netip.Addr, ttlSeconds int) error {
	if ttlSeconds <= 0 {
		return nil
	}
	if n.dryRun {
		return nil
	}
	elem := fmt.Sprintf("{ %s timeout %ds }", addr.String(), ttlSeconds)
	_, err := n.run("add", "element", tableFamily, tableName, setFor(addr), elem)
	return err
}

func (n *nftables) remove(addr netip.Addr) error {
	if n.dryRun {
		return nil
	}
	elem := fmt.Sprintf("{ %s }", addr.String())
	out, err := n.run("delete", "element", tableFamily, tableName, setFor(addr), elem)
	if err != nil {
		// Removing something that is not there is the goal, not a failure. It
		// happens whenever a ban expired in the kernel before the release arrived,
		// which is ordinary.
		if strings.Contains(strings.ToLower(err.Error()+out), "no such file") {
			return nil
		}
		return err
	}
	return nil
}

// list reads what the kernel currently holds, for the reconcile.
func (n *nftables) list() (map[netip.Addr]struct{}, error) {
	out := map[netip.Addr]struct{}{}
	if n.dryRun {
		return out, nil
	}
	for _, s := range []string{set4, set6} {
		raw, err := n.run("-j", "list", "set", tableFamily, tableName, s)
		if err != nil {
			return nil, err
		}
		if err := parseSet(raw, out); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// parseSet reads nft's JSON output.
//
// The JSON form rather than the human one: the text output is meant for people
// and changes shape between versions, and a parser that silently reads nothing
// would have the reconcile believe the kernel is empty - and then add everything
// back, every minute, forever.
func parseSet(raw string, into map[netip.Addr]struct{}) error {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	var doc struct {
		Nftables []map[string]json.RawMessage `json:"nftables"`
	}
	if err := json.Unmarshal([]byte(raw), &doc); err != nil {
		return fmt.Errorf("reading the kernel set: %w", err)
	}
	for _, node := range doc.Nftables {
		rawSet, ok := node["set"]
		if !ok {
			continue
		}
		var s struct {
			Elem []json.RawMessage `json:"elem"`
		}
		if err := json.Unmarshal(rawSet, &s); err != nil {
			continue
		}
		for _, e := range s.Elem {
			// An element is either a bare address or {"elem":{"val":...,"timeout":n}}
			var plain string
			if err := json.Unmarshal(e, &plain); err == nil {
				if a, err := netip.ParseAddr(plain); err == nil {
					into[a.Unmap()] = struct{}{}
				}
				continue
			}
			var wrapped struct {
				Elem struct {
					Val string `json:"val"`
				} `json:"elem"`
			}
			if err := json.Unmarshal(e, &wrapped); err == nil && wrapped.Elem.Val != "" {
				if a, err := netip.ParseAddr(wrapped.Elem.Val); err == nil {
					into[a.Unmap()] = struct{}{}
				}
			}
		}
	}
	return nil
}

// ------------------------------------------------------------- the ban list

type banRow struct {
	IP     string `json:"ip"`
	Reason string `json:"reason"`
	TTL    int    `json:"ttl"`
}

func fetchBans(ctx context.Context, url, token string) ([]banRow, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	if token != "" {
		req.Header.Set("X-MosWAF-Token", token)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("the ban list answered %d", res.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(res.Body, 32<<20))
	if err != nil {
		return nil, err
	}
	var doc struct {
		Items    []banRow `json:"items"`
		Complete bool     `json:"complete"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, err
	}
	// A truncated list would have the reconcile believe bans it cannot see are no
	// longer bans, and release them from the kernel - at exactly the moment there
	// are enough of them to truncate, which is a flood.
	if !doc.Complete {
		return nil, fmt.Errorf("the ban list came back truncated; refusing to " +
			"reconcile against a partial view")
	}
	return doc.Items, nil
}
