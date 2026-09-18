package store

import (
	"strings"
	"testing"
)

func ruleWith(action string, conds ...RuleCondition) *AccessRule {
	return &AccessRule{Name: "test", Action: action, Enabled: true, Conditions: conds}
}

func cond(field, op string, values ...string) RuleCondition {
	return RuleCondition{Field: field, Op: op, Values: values}
}

// The check the whole feature rests on.
//
// "Allow" means stop checking this request, so whoever controls the condition
// that fires it controls whether the firewall runs. A path, a host, a method and
// a user agent are all part of the request - the attacker writes them. "Allow if
// the user agent contains Mozilla" is not a broad rule, it is a back door opened
// by sending a header, and every visitor can open it.
func TestAllowMayOnlyBeTriggeredByThingsTheRequestCannotClaim(t *testing.T) {
	for _, c := range []RuleCondition{
		cond("ua", "contains", "Mozilla"),
		cond("path", "prefix", "/api"),
		cond("host", "equals", "example.com"),
		cond("method", "in", "GET"),
		cond("country", "in", "VN"),
	} {
		if err := ValidateAccessRule(ruleWith("allow", c)); err == nil {
			t.Errorf("an allow rule on %q was accepted. That field is part of the "+
				"request, so anybody could send it and switch the firewall off for "+
				"themselves", c.Field)
		}
	}

	// And the two that are established by us rather than claimed.
	if err := ValidateAccessRule(ruleWith("allow", cond("ip", "in_cidr", "203.0.113.0/24"))); err != nil {
		t.Errorf("an allow rule on an address was refused: %v", err)
	}
	if err := ValidateAccessRule(ruleWith("allow", cond("crawler", "is", "true"))); err != nil {
		t.Errorf("an allow rule on a verified crawler was refused: %v", err)
	}

	// The same fields are fine for the actions that catch a request rather than
	// wave it through.
	for _, action := range []string{"deny", "challenge", "log"} {
		if err := ValidateAccessRule(ruleWith(action, cond("ua", "contains", "sqlmap"))); err != nil {
			t.Errorf("a %s rule on the user agent was refused: %v - matching an "+
				"attacker's own request is how you catch it", action, err)
		}
	}
}

// An allow rule covering every address is the firewall switched off, however it
// is spelled. The spelling matters because one of them hides: "/00" is read as a
// prefix length of zero by a lenient parser, and a lenient parser is what the
// data plane used to have.
func TestAnAllowRuleCannotCoverEveryAddress(t *testing.T) {
	for _, v := range []string{"0.0.0.0/0", "::/0", "1.2.3.4/0"} {
		err := ValidateAccessRule(ruleWith("allow", cond("ip", "in_cidr", v)))
		if err == nil {
			t.Errorf("an allow rule on %q was accepted; it covers every address", v)
		} else if !strings.Contains(err.Error(), "every address") {
			t.Errorf("%q was refused but the message does not say why: %v", v, err)
		}
	}

	// "allow anybody who is not a verified crawler" is very nearly everybody.
	if err := ValidateAccessRule(ruleWith("allow", cond("crawler", "is", "false"))); err == nil {
		t.Error("an allow rule on \"not a crawler\" was accepted; that is almost " +
			"every visitor")
	}
}

// A rule with nothing to match on fires on everything, which is the firewall off
// or the site off depending only on the action.
func TestARuleNeedsSomethingToMatchOn(t *testing.T) {
	for _, action := range []string{"allow", "deny", "challenge", "log"} {
		if err := ValidateAccessRule(ruleWith(action)); err == nil {
			t.Errorf("a %s rule with no conditions was accepted", action)
		}
	}
	if err := ValidateAccessRule(ruleWith("deny", cond("path", "prefix"))); err == nil {
		t.Error("a condition with no values was accepted; it would hold vacuously")
	}
}

// Loose CIDR spellings are the ones that hide their meaning. "1.2.3.4/00" read as
// a prefix length of zero is every address on the internet, and behind an allow
// rule that is the firewall switched off, entered as a typo.
func TestCIDRValuesAreStrictAndStoredCanonically(t *testing.T) {
	for _, bad := range []string{
		"1.2.3.4/00", "01.2.3.4/24", "192.168.001.001/24", "1.2.3.4/024",
		"1.2.3.4/33", "not an address", "1.2.3.4/", "",
	} {
		if err := ValidateAccessRule(ruleWith("deny", cond("ip", "in_cidr", bad))); err == nil {
			t.Errorf("%q was accepted as an address range", bad)
		}
	}

	// What is stored is the canonical form, so the data plane never has to be the
	// strict one - and an operator reading the rule back sees what it really covers.
	r := ruleWith("deny", cond("ip", "in_cidr", "203.0.113.5/24", "198.51.100.7"))
	if err := ValidateAccessRule(r); err != nil {
		t.Fatalf("a valid rule was refused: %v", err)
	}
	got := strings.Join(r.Conditions[0].Values, " ")
	if got != "203.0.113.0/24 198.51.100.7/32" {
		t.Errorf("stored %q; the host bits should be masked off and a bare address "+
			"written as a full-length prefix, so what is stored is what is matched", got)
	}
}

func TestOnlyKnownFieldsAndOperators(t *testing.T) {
	for _, c := range []RuleCondition{
		cond("referer", "contains", "x"),
		cond("body", "contains", "x"),
		cond("path", "regex", ".*"), // deliberately not supported: it runs per request
		cond("ip", "equals", "1.2.3.4"),
		cond("country", "prefix", "V"),
	} {
		if err := ValidateAccessRule(ruleWith("deny", c)); err == nil {
			t.Errorf("%q with %q was accepted", c.Field, c.Op)
		}
	}
}

func TestCountriesAreCollectedFromRulesSoTheyHaveDataToTestAgainst(t *testing.T) {
	rules := []*AccessRule{
		{Enabled: true, Conditions: []RuleCondition{cond("country", "in", "VN", "CN")}},
		{Enabled: true, Conditions: []RuleCondition{cond("country", "in", "VN")}},
		{Enabled: false, Conditions: []RuleCondition{cond("country", "in", "RU")}},
		{Enabled: true, Conditions: []RuleCondition{cond("path", "prefix", "/x")}},
	}
	got := strings.Join(RuleCountries(rules), ",")
	if got != "VN,CN" {
		t.Errorf("RuleCountries = %q, want \"VN,CN\" - every country a live rule "+
			"names needs its ranges published, or the condition has nothing to test "+
			"against and the rule silently never fires", got)
	}
}
