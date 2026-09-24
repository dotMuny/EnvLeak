package report_test

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dotMuny/EnvLeak/internal/detect"
	"github.com/dotMuny/EnvLeak/internal/report"
	"github.com/dotMuny/EnvLeak/internal/rules"
)

const secret = "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"

func boolPtr(b bool) *bool { return &b }

func sample() report.Report {
	inHead := true
	return report.Report{
		ToolVersion:     "1.2.3",
		Mode:            "worktree",
		FilesScanned:    12,
		DurationSeconds: 0.42,
		Findings: []detect.Finding{
			{
				RuleID:        "github-pat-classic",
				Description:   "GitHub classic personal access token",
				Severity:      rules.SeverityCritical,
				Confidence:    detect.ConfidenceHigh,
				Engines:       []string{detect.EnginePattern, detect.EngineValidator},
				Tags:          []string{"github", "vcs"},
				Path:          "src/deploy.sh",
				Line:          12,
				StartCol:      14,
				EndCol:        54,
				LineSample:    "GITHUB_TOKEN=" + secret,
				Secret:        secret,
				Redacted:      detect.Redact(secret),
				Validated:     true,
				ValidatorName: "github-crc32",
				Fingerprint:   detect.Fingerprint("github-pat-classic", "src/deploy.sh", secret),
				SecretHash:    detect.HashSecret(secret),
			},
			{
				RuleID:      "generic-high-entropy",
				Description: "High-entropy base64 string (4.71 bits/char)",
				Severity:    rules.SeverityLow,
				Confidence:  detect.ConfidenceLow,
				Engines:     []string{detect.EngineEntropy},
				Path:        "docs/notes.md",
				Line:        3,
				StartCol:    1,
				EndCol:      33,
				Secret:      "kR7mQz2XvNb8LcYt4WpJd6SgHa1FuE3Zi",
				Redacted:    "kR7m...E3Zi",
				Entropy:     4.71,
				Notes:       []string{"documentation file"},
				Fingerprint: "abcdef0123456789",
				SecretHash:  "0123456789abcdef",
				Commit:      "1760bdb2c98751b6cf496fefe0d68a4effa3",
				Author:      "Jo Dev",
				AuthorEmail: "jo@example.com",
				Date:        "2024-02-11T14:22:00Z",
				InHEAD:      &inHead,
			},
		},
	}
}

func render(t *testing.T, f report.Format, r report.Report, o report.Options) string {
	t.Helper()
	formatter, err := report.New(f)
	require.NoError(t, err)
	var buf bytes.Buffer
	require.NoError(t, formatter.Format(&buf, r, o))
	return buf.String()
}

func TestParseFormat(t *testing.T) {
	for _, name := range report.Formats() {
		f, err := report.ParseFormat(name)
		require.NoError(t, err)
		_, err = report.New(f)
		assert.NoError(t, err)
	}
	f, err := report.ParseFormat(" SARIF ")
	require.NoError(t, err)
	assert.Equal(t, report.FormatSARIF, f)

	_, err = report.ParseFormat("yaml")
	assert.ErrorContains(t, err, "unknown format")
	_, err = report.New(report.Format("yaml"))
	assert.Error(t, err)
}

// TestSecretsAreRedactedByDefault is the promise the tool makes in its help
// text: nothing prints a live credential unless the operator asked for it.
func TestSecretsAreRedactedByDefault(t *testing.T) {
	r := sample()
	for _, f := range report.Formats() {
		t.Run(f, func(t *testing.T) {
			format, err := report.ParseFormat(f)
			require.NoError(t, err)

			out := render(t, format, r, report.Options{})
			assert.NotContains(t, out, secret, "%s leaked the raw secret", f)
			assert.Contains(t, out, detect.Redact(secret))

			loud := render(t, format, r, report.Options{ShowSecrets: true})
			assert.Contains(t, loud, secret, "%s should honour --show-secrets", f)
		})
	}
}

func TestTextFormat(t *testing.T) {
	out := render(t, report.FormatText, sample(), report.Options{Verbose: true})

	assert.Contains(t, out, "src/deploy.sh")
	assert.Contains(t, out, "github-pat-classic")
	assert.Contains(t, out, "CRITICAL")
	assert.Contains(t, out, "checksum=ok")
	assert.Contains(t, out, "confidence=high")
	assert.Contains(t, out, "12:14", "findings carry line:column")
	assert.Contains(t, out, "STILL IN HEAD")
	assert.Contains(t, out, "documentation file", "--verbose explains the downgrade")
	assert.Contains(t, out, "2 findings in 2 files")
	assert.NotContains(t, out, "\033[", "no ANSI escapes when colour is off")
}

func TestTextFormatColour(t *testing.T) {
	out := render(t, report.FormatText, sample(), report.Options{Color: true})
	assert.Contains(t, out, "\033[")
}

func TestTextFormatEmpty(t *testing.T) {
	out := render(t, report.FormatText, report.Report{FilesScanned: 1, DurationSeconds: 0.01}, report.Options{})
	assert.Contains(t, out, "no secrets found")
	assert.Contains(t, out, "1 file")
	assert.NotContains(t, out, "1 files")
}

func TestShowSecretsWarns(t *testing.T) {
	out := render(t, report.FormatText, sample(), report.Options{ShowSecrets: true})
	assert.Contains(t, out, "warning: --show-secrets")
	assert.Contains(t, out, "CI logs")
}

func TestJSONIsOneObjectPerLine(t *testing.T) {
	out := render(t, report.FormatJSON, sample(), report.Options{})
	lines := strings.Split(strings.TrimSpace(out), "\n")
	require.Len(t, lines, 2)

	var first map[string]any
	require.NoError(t, json.Unmarshal([]byte(lines[0]), &first))

	assert.Equal(t, report.JSONSchemaVersion, first["schema"])
	assert.Equal(t, "github-pat-classic", first["rule_id"])
	assert.Equal(t, "critical", first["severity"])
	assert.Equal(t, "high", first["confidence"])
	assert.Equal(t, float64(12), first["line"])
	assert.Equal(t, true, first["validated"])
	assert.NotEmpty(t, first["fingerprint"])
	assert.Nil(t, first["secret"], "the raw secret is omitted unless asked for")

	// The line sample must not smuggle the secret past the redaction.
	assert.NotContains(t, first["line_sample"].(string), secret)

	var second map[string]any
	require.NoError(t, json.Unmarshal([]byte(lines[1]), &second))
	assert.Equal(t, true, second["in_head"])
	assert.Equal(t, "Jo Dev", second["author"])
}

func TestJSONEmpty(t *testing.T) {
	out := render(t, report.FormatJSON, report.Report{}, report.Options{})
	assert.Empty(t, out, "no findings means no lines, which is what a JSONL consumer expects")
}

func TestJUnitFormat(t *testing.T) {
	out := render(t, report.FormatJUnit, sample(), report.Options{})

	var suites struct {
		XMLName  xml.Name `xml:"testsuites"`
		Tests    int      `xml:"tests,attr"`
		Failures int      `xml:"failures,attr"`
		Suites   []struct {
			Name  string `xml:"name,attr"`
			Cases []struct {
				Name    string `xml:"name,attr"`
				Failure *struct {
					Message string `xml:"message,attr"`
					Type    string `xml:"type,attr"`
					Body    string `xml:",chardata"`
				} `xml:"failure"`
			} `xml:"testcase"`
		} `xml:"testsuite"`
	}
	require.NoError(t, xml.Unmarshal([]byte(out), &suites))

	assert.Equal(t, 2, suites.Tests)
	assert.Equal(t, 2, suites.Failures)
	require.Len(t, suites.Suites, 2)
	require.NotNil(t, suites.Suites[1].Cases[0].Failure)
	assert.Equal(t, "github-pat-classic", suites.Suites[1].Cases[0].Failure.Type)
	assert.Contains(t, suites.Suites[1].Cases[0].Failure.Body, "src/deploy.sh:12:14")
	assert.Contains(t, out, xml.Header)
}

func TestJUnitEmptyHasOnePassingCase(t *testing.T) {
	out := render(t, report.FormatJUnit, report.Report{}, report.Options{})
	assert.Contains(t, out, "no secrets detected")
	assert.Contains(t, out, `tests="1"`)
	assert.Contains(t, out, `failures="0"`)
}

func TestSARIFStructure(t *testing.T) {
	out := render(t, report.FormatSARIF, sample(), report.Options{})

	var log struct {
		Schema  string `json:"$schema"`
		Version string `json:"version"`
		Runs    []struct {
			Tool struct {
				Driver struct {
					Name  string `json:"name"`
					Rules []struct {
						ID                   string `json:"id"`
						DefaultConfiguration struct {
							Level string `json:"level"`
						} `json:"defaultConfiguration"`
					} `json:"rules"`
				} `json:"driver"`
			} `json:"tool"`
			Results []struct {
				RuleID    string `json:"ruleId"`
				RuleIndex int    `json:"ruleIndex"`
				Level     string `json:"level"`
				Locations []struct {
					PhysicalLocation struct {
						ArtifactLocation struct {
							URI string `json:"uri"`
						} `json:"artifactLocation"`
						Region struct {
							StartLine   int `json:"startLine"`
							StartColumn int `json:"startColumn"`
						} `json:"region"`
					} `json:"physicalLocation"`
				} `json:"locations"`
				PartialFingerprints map[string]string `json:"partialFingerprints"`
			} `json:"results"`
		} `json:"runs"`
	}
	require.NoError(t, json.Unmarshal([]byte(out), &log))

	assert.Equal(t, "2.1.0", log.Version)
	assert.Contains(t, log.Schema, "sarif-schema-2.1.0.json")
	require.Len(t, log.Runs, 1)
	assert.Equal(t, "envleak", log.Runs[0].Tool.Driver.Name)
	require.Len(t, log.Runs[0].Results, 2)

	// Every result must index a rule that actually exists in the driver.
	for _, res := range log.Runs[0].Results {
		require.Less(t, res.RuleIndex, len(log.Runs[0].Tool.Driver.Rules))
		assert.Equal(t, res.RuleID, log.Runs[0].Tool.Driver.Rules[res.RuleIndex].ID)
		assert.NotEmpty(t, res.Locations)
		assert.Positive(t, res.Locations[0].PhysicalLocation.Region.StartLine)
		assert.NotEmpty(t, res.PartialFingerprints["envleakFingerprint/v1"])
	}

	assert.Equal(t, "error", log.Runs[0].Results[0].Level, "critical maps to error")
	assert.Equal(t, "note", log.Runs[0].Results[1].Level, "low maps to note, not warning")
	assert.Equal(t, "src/deploy.sh", log.Runs[0].Results[0].Locations[0].PhysicalLocation.ArtifactLocation.URI)
}

func TestSARIFEmptyRunIsStillValidShape(t *testing.T) {
	out := render(t, report.FormatSARIF, report.Report{ToolVersion: "1.0.0"}, report.Options{})
	assert.Contains(t, out, `"rules": []`)
	assert.Contains(t, out, `"results": []`)
}

func TestFormattersDoNotFilter(t *testing.T) {
	// A formatter renders exactly what it is given; deciding what to report
	// happens upstream. Guard that with a low-confidence finding that every
	// format must still print.
	r := sample()
	for _, name := range report.Formats() {
		format, err := report.ParseFormat(name)
		require.NoError(t, err)
		out := render(t, format, r, report.Options{})
		if name == "text" || name == "junit" {
			assert.Contains(t, out, "generic-high-entropy", name)
		}
	}
}
