package report_test

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"github.com/stretchr/testify/require"

	"github.com/dotMuny/EnvLeak/internal/detect"
	"github.com/dotMuny/EnvLeak/internal/report"
	"github.com/dotMuny/EnvLeak/internal/rules"
)

// schemaPath is the official OASIS SARIF 2.1.0 schema, vendored into testdata
// so the test does not need the network.
var schemaPath = filepath.Join("..", "..", "testdata", "schema", "sarif-2.1.0.json")

func loadSARIFSchema(t *testing.T) *jsonschema.Schema {
	t.Helper()

	f, err := os.Open(schemaPath)
	require.NoError(t, err, "vendored SARIF schema is missing")
	defer func() { _ = f.Close() }()

	doc, err := jsonschema.UnmarshalJSON(f)
	require.NoError(t, err)

	c := jsonschema.NewCompiler()
	const url = "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json"
	require.NoError(t, c.AddResource(url, doc))

	schema, err := c.Compile(url)
	require.NoError(t, err)
	return schema
}

func validateSARIF(t *testing.T, schema *jsonschema.Schema, raw []byte) {
	t.Helper()

	inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	require.NoError(t, err)

	if err := schema.Validate(inst); err != nil {
		var detail *jsonschema.ValidationError
		if ok := asValidationError(err, &detail); ok {
			t.Fatalf("SARIF output does not validate against the 2.1.0 schema:\n%v\n\noutput:\n%s",
				detail, raw)
		}
		t.Fatalf("SARIF validation failed: %v\n\noutput:\n%s", err, raw)
	}
}

func asValidationError(err error, target **jsonschema.ValidationError) bool {
	v, ok := err.(*jsonschema.ValidationError)
	if ok {
		*target = v
	}
	return ok
}

// TestSARIFValidatesAgainstSchema is acceptance criterion 3: the SARIF we hand
// to GitHub Code Scanning is valid SARIF 2.1.0, checked against the official
// schema rather than against our own idea of it.
func TestSARIFValidatesAgainstSchema(t *testing.T) {
	schema := loadSARIFSchema(t)

	cases := map[string]report.Report{
		"typical findings": sample(),
		"no findings":      {ToolVersion: "1.0.0"},
		"history findings": historyReport(),
		"awkward paths": {
			ToolVersion: "1.0.0",
			Findings: []detect.Finding{{
				RuleID:      "private-key-rsa",
				Description: "RSA private key in PEM format",
				Severity:    rules.SeverityCritical,
				Confidence:  detect.ConfidenceHigh,
				Engines:     []string{detect.EnginePattern},
				Path:        "some dir/with spaces/ünïcode.pem",
				Line:        1,
				StartCol:    1,
				EndCol:      31,
				Secret:      "-----BEGIN RSA PRIVATE KEY-----",
				Redacted:    "-----BEGIN RSA PRIVATE KEY-----",
				Fingerprint: "aaaaaaaaaaaaaaaa",
				SecretHash:  "bbbbbbbbbbbbbbbb",
			}},
		},
		"zero line and column": {
			ToolVersion: "1.0.0",
			Findings: []detect.Finding{{
				RuleID:      "generic-high-entropy",
				Description: "High-entropy string",
				Severity:    rules.SeverityLow,
				Confidence:  detect.ConfidenceLow,
				Engines:     []string{detect.EngineEntropy},
				Path:        "a.txt",
				Redacted:    "abcd...wxyz",
				Fingerprint: "cccccccccccccccc",
				SecretHash:  "dddddddddddddddd",
			}},
		},
	}

	for name, r := range cases {
		t.Run(name, func(t *testing.T) {
			for _, opts := range []report.Options{{}, {ShowSecrets: true}} {
				out := render(t, report.FormatSARIF, r, opts)
				validateSARIF(t, schema, []byte(out))
			}
		})
	}
}

// TestSARIFFromEveryRuleValidates renders one finding per catalogue rule, so a
// new rule with an awkward description or tag cannot break Code Scanning
// ingestion without a test noticing.
func TestSARIFFromEveryRuleValidates(t *testing.T) {
	schema := loadSARIFSchema(t)

	cat, err := rules.Default()
	require.NoError(t, err)

	r := report.Report{ToolVersion: "1.0.0"}
	for i, rule := range cat.Rules {
		r.Findings = append(r.Findings, detect.Finding{
			RuleID:      rule.ID,
			Description: rule.Description,
			Severity:    rule.Severity,
			Confidence:  detect.ConfidenceMedium,
			Engines:     []string{detect.EnginePattern},
			Tags:        rule.Tags,
			Path:        "src/file.go",
			Line:        i + 1,
			StartCol:    1,
			EndCol:      10,
			Secret:      "synthetic",
			Redacted:    "*********",
			Fingerprint: detect.Fingerprint(rule.ID, "src/file.go", "synthetic"),
			SecretHash:  detect.HashSecret("synthetic"),
		})
	}

	out := render(t, report.FormatSARIF, r, report.Options{})
	validateSARIF(t, schema, []byte(out))

	var log struct {
		Runs []struct {
			Tool struct {
				Driver struct {
					Rules []json.RawMessage `json:"rules"`
				} `json:"driver"`
			} `json:"tool"`
		} `json:"runs"`
	}
	require.NoError(t, json.Unmarshal([]byte(out), &log))
	require.Len(t, log.Runs[0].Tool.Driver.Rules, cat.Len(),
		"every rule that produced a result must be described in the driver")
}

func historyReport() report.Report {
	r := sample()
	for i := range r.Findings {
		r.Findings[i].Commit = "1760bdb2c98751b6cf496fefe0d68a4effa3c98d"
		r.Findings[i].Author = "Jo Dev"
		r.Findings[i].Date = "2024-02-11T14:22:00Z"
		r.Findings[i].InHEAD = boolPtr(i%2 == 0)
	}
	r.Mode = "history"
	r.CommitsScanned = 7
	return r
}
