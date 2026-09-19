package main

// The unit file is the part of this program that nothing compiles and nothing
// runs in CI, and systemd's response to a directive in the wrong section is a
// warning in a journal nobody reads. So it fails the way configuration always
// fails: the protection is written down, it reads as present, and it is not
// there - which is worse than never having written it, because the first is a
// thing somebody trusts.
//
// That already happened once here. StartLimitIntervalSec and StartLimitBurst
// were in [Service]; systemd moved them to [Unit] in v230 and ignores them where
// they were. The default ten-second window stayed in force, and with
// RestartSec=5s a misconfigured agent restarts twice per window, never reaches
// the burst limit, and loops forever filling the disk - which is the exact
// outcome the comment above those two lines said they prevented.
//
// These tests read the file as systemd would.

import (
	"bufio"
	"os"
	"strings"
	"testing"
)

// unitSections parses the file into section -> directive -> value.
func unitSections(t *testing.T) map[string]map[string]string {
	t.Helper()
	f, err := os.Open("../../../scripts/moswaf-kbans.service")
	if err != nil {
		t.Fatalf("the unit file is missing: %v", err)
	}
	defer f.Close()

	out := map[string]map[string]string{}
	section := ""
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.Trim(line, "[]")
			if out[section] == nil {
				out[section] = map[string]string{}
			}
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok || section == "" {
			t.Fatalf("unit file line outside any section, or with no '=': %q", line)
		}
		out[section][strings.TrimSpace(k)] = strings.TrimSpace(v)
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestTheRestartLimitIsInTheSectionSystemdReadsItFrom(t *testing.T) {
	s := unitSections(t)

	for _, key := range []string{"StartLimitIntervalSec", "StartLimitBurst"} {
		if _, wrong := s["Service"][key]; wrong {
			t.Errorf("%s is in [Service]. systemd moved it to [Unit] in v230 and "+
				"ignores it here - the default 10s window stays in force, and with "+
				"RestartSec=5s a broken agent restarts twice per window, never "+
				"reaches the burst limit, and loops forever filling the journal. "+
				"The crash-loop protection reads as present and is not there", key)
		}
		if _, ok := s["Unit"][key]; !ok {
			t.Errorf("%s is missing from [Unit]", key)
		}
	}
}

func TestTheServiceKeepsExactlyThePrivilegeItNeeds(t *testing.T) {
	svc := s3(t)

	// The one it cannot do its job without.
	if got := svc["AmbientCapabilities"]; got != "CAP_NET_ADMIN" {
		t.Errorf("AmbientCapabilities is %q; the agent programs nftables and "+
			"needs CAP_NET_ADMIN, and granting anything wider hands the broadest "+
			"privilege in the product to the component that already has the most "+
			"dangerous job", got)
	}
	// And the bound that stops it acquiring any other.
	if got := svc["CapabilityBoundingSet"]; got != "CAP_NET_ADMIN" {
		t.Errorf("CapabilityBoundingSet is %q, so the process could gain "+
			"capabilities beyond the one it was given", got)
	}
	if svc["NoNewPrivileges"] != "yes" {
		t.Error("NoNewPrivileges is not yes")
	}
}

func TestTheSandboxDirectivesAreAllStillThere(t *testing.T) {
	svc := s3(t)

	// Each of these was chosen; none is decorative. Listed by name so that
	// removing one is a decision somebody has to make in this file rather than a
	// line that quietly went missing in a merge.
	want := map[string]string{
		"ProtectSystem":          "strict",
		"ProtectHome":            "yes",
		"ProtectKernelTunables":  "yes",
		"ProtectKernelModules":   "yes",
		"RestrictNamespaces":     "yes",
		"RestrictSUIDSGID":       "yes",
		"MemoryDenyWriteExecute": "yes",
		"SystemCallFilter":       "@system-service",
	}
	for k, v := range want {
		if got := svc[k]; got != v {
			t.Errorf("%s = %q, expected %q", k, got, v)
		}
	}
}

func TestTheServiceDoesNotHardDependOnDocker(t *testing.T) {
	s := unitSections(t)
	if req := s["Unit"]["Requires"]; strings.Contains(req, "docker") {
		t.Error("the unit Requires docker. The agent is an optimisation, not a " +
			"dependency: if Docker is down there are no bans to program, and a " +
			"hard dependency only adds a second thing to fix while somebody is " +
			"already fixing the first")
	}
}

func s3(t *testing.T) map[string]string {
	t.Helper()
	svc := unitSections(t)["Service"]
	if svc == nil {
		t.Fatal("the unit file has no [Service] section")
	}
	return svc
}
