package api

import (
	"encoding/json"
	"testing"
)

// "The caller did not mention it" and "the caller said false" are different
// things, and a plain bool cannot tell them apart.
//
// It matters most for a deny rule. Somebody writes "block TRACE", the API answers
// 201, and the rule is off - so nothing about TRACE is being blocked while the
// dashboard shows a rule that says it is. Protection that was never switched on
// is worse than no protection, because nobody is looking for it.
func TestOmittingEnabledIsNotTheSameAsSayingFalse(t *testing.T) {
	cases := []struct {
		body string
		want *bool
		why  string
	}{
		{`{"name":"x","action":"deny"}`, nil,
			"the field was not mentioned"},
		{`{"name":"x","action":"deny","enabled":false}`, boolPtr(false),
			"the caller explicitly switched it off"},
		{`{"name":"x","action":"deny","enabled":true}`, boolPtr(true),
			"the caller explicitly switched it on"},
	}

	for _, c := range cases {
		var got ruleBody
		if err := json.Unmarshal([]byte(c.body), &got); err != nil {
			t.Fatalf("decoding %s: %v", c.body, err)
		}
		if (got.Enabled == nil) != (c.want == nil) {
			t.Errorf("%s: Enabled nil = %v, want nil = %v (%s)",
				c.body, got.Enabled == nil, c.want == nil, c.why)
			continue
		}
		if c.want != nil && *got.Enabled != *c.want {
			t.Errorf("%s: Enabled = %v, want %v", c.body, *got.Enabled, *c.want)
		}
	}
}

// The rule the create handler applies: a rule somebody just wrote is meant to be
// in force, and only an explicit false turns it off.
func TestANewRuleIsOnUnlessItSaysOtherwise(t *testing.T) {
	for _, c := range []struct {
		body string
		want bool
	}{
		{`{"name":"x","action":"deny"}`, true},
		{`{"name":"x","action":"deny","enabled":true}`, true},
		{`{"name":"x","action":"deny","enabled":false}`, false},
	} {
		var body ruleBody
		if err := json.Unmarshal([]byte(c.body), &body); err != nil {
			t.Fatal(err)
		}
		got := body.Enabled == nil || *body.Enabled
		if got != c.want {
			t.Errorf("%s created enabled=%v, want %v", c.body, got, c.want)
		}
	}
}

func boolPtr(b bool) *bool { return &b }
