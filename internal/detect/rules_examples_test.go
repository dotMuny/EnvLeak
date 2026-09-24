package detect_test

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/dotMuny/EnvLeak/internal/detect"
	"github.com/dotMuny/EnvLeak/internal/rules"
)

// newDetector builds a detector over the embedded catalogue with the shipped
// defaults — the same configuration a user gets out of the box.
func newDetector(t *testing.T) *detect.Detector {
	t.Helper()
	cat, err := rules.Default()
	require.NoError(t, err)
	d, err := detect.New(cat, detect.DefaultOptions())
	require.NoError(t, err)
	return d
}

// TestRuleExamples is the contract every rule in rules.yaml has to satisfy:
// each positive example produces a finding for that rule, each negative
// example does not. The examples are the same ones rendered into
// docs/rules.md, so the documentation cannot drift from the behaviour.
func TestRuleExamples(t *testing.T) {
	cat, err := rules.Default()
	require.NoError(t, err)
	d := newDetector(t)

	ctx := detect.Context{Path: "src/config.go"}

	for _, r := range cat.Rules {
		t.Run(r.ID, func(t *testing.T) {
			require.NotEmpty(t, r.Examples.Positive, "rule needs a positive example")
			require.NotEmpty(t, r.Examples.Negative, "rule needs a negative example")

			for i, pos := range r.Examples.Positive {
				findings := d.ScanString(pos, ctx)
				require.Truef(t, hasRule(findings, r.ID),
					"positive example #%d did not fire %s\n  input:    %s\n  findings: %s",
					i, r.ID, pos, describe(findings))
			}
			for i, neg := range r.Examples.Negative {
				findings := d.ScanString(neg, ctx)
				require.Falsef(t, hasRule(findings, r.ID),
					"negative example #%d wrongly fired %s\n  input:    %s\n  findings: %s",
					i, r.ID, neg, describe(findings))
			}
		})
	}
}

func hasRule(fs []detect.Finding, id string) bool {
	for _, f := range fs {
		if f.RuleID == id {
			return true
		}
	}
	return false
}

func describe(fs []detect.Finding) string {
	if len(fs) == 0 {
		return "(none)"
	}
	out := ""
	for _, f := range fs {
		out += fmt.Sprintf("\n    - %s [%s/%s] %q", f.RuleID, f.Severity, f.Confidence, f.Redacted)
	}
	return out
}
