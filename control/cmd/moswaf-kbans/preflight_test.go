package main

import "testing"

// The installer decides whether to enable this service by the exit code of
// -check. So every way preflight can be wrong is a way somebody gets locked out
// of their own server, and the direction of the mistake is what matters: saying
// "not protected" when it is costs a second look, saying "protected" when it is
// not costs the machine.
//
// Everything below is about refusing to say yes on anything less than proof.

func run(t *testing.T, allow []string, from string) int {
	t.Helper()
	return preflight(config{
		management: allow,
		docker:     []string{"172.17.0.0/16"},
	}, from)
}

func TestPreflightPassesOnlyWithProof(t *testing.T) {
	const operator = "59.153.228.62"

	if code := run(t, []string{"59.153.224.0/20"}, operator); code != 0 {
		t.Fatalf("an address inside the management range must pass, got exit %d", code)
	}
	if code := run(t, []string{operator}, operator); code != 0 {
		t.Fatalf("a bare address given as the management entry must pass, got exit %d", code)
	}
}

func TestPreflightRefusesAnAddressItDoesNotCover(t *testing.T) {
	// A plausible near-miss: the operator typed the range their office used to
	// have. Everything looks configured; nothing protects them.
	if code := run(t, []string{"203.0.113.0/24"}, "59.153.228.62"); code == 0 {
		t.Fatal("preflight passed an address outside every configured range. " +
			"The installer would enable the service, the agent would run " +
			"correctly, and the first time this address was banned the operator " +
			"would lose the connection they need to undo it")
	}
}

func TestPreflightRefusesWithNothingToCheckAgainst(t *testing.T) {
	// The interesting one. "I was not told which address to verify" must not be
	// reported the same way as "I verified it". An installer that reads exit 0
	// here would enable the service having checked nothing at all - and this is
	// the likely case, because SSH_CLIENT is empty on a console login or under
	// sudo that scrubs the environment.
	if code := run(t, []string{"59.153.224.0/20"}, ""); code == 0 {
		t.Fatal("preflight passed with no address to check. Not knowing is not " +
			"the same as being safe, and an empty check is the one an installer " +
			"is most likely to run by accident")
	}
	if code := run(t, []string{"59.153.224.0/20"}, "not-an-address"); code == 0 {
		t.Fatal("preflight passed something that is not an address")
	}
}

func TestPreflightRefusesAnUnfinishedConfiguration(t *testing.T) {
	// No management range at all. The agent itself refuses to start in this
	// state; preflight has to agree, or the installer would enable a service that
	// then dies on every boot.
	if code := run(t, nil, "59.153.228.62"); code == 0 {
		t.Fatal("preflight passed with no management range configured")
	}
	if code := run(t, []string{"", "  "}, "59.153.228.62"); code == 0 {
		t.Fatal("preflight passed with a management range of blanks, which is " +
			"what an unset environment variable split on commas looks like")
	}
}

func TestPreflightRefusesTheAddressesThatAreNotVisitors(t *testing.T) {
	// These are covered by the infrastructure list rather than by anything the
	// operator typed, so they pass - and they should, because dropping them cuts
	// the machine off from itself rather than from an attacker.
	for _, ip := range []string{"127.0.0.1", "::1", "172.17.0.9"} {
		if code := run(t, []string{"59.153.224.0/20"}, ip); code != 0 {
			t.Fatalf("%s should be protected without the operator listing it, got exit %d", ip, code)
		}
	}
}
