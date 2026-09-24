package report

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/dotMuny/EnvLeak/internal/detect"
)

// jsonFormatter emits JSON Lines: one self-contained JSON object per finding,
// newline separated. JSONL rather than one big array so the output can be
// piped into jq, split, or streamed by a consumer that does not want to buffer
// a whole scan.
//
// The schema is documented in docs/json.md and is considered stable: fields
// may be added, never removed or retyped.
type jsonFormatter struct{}

// jsonFinding is the wire shape. It is a separate type from detect.Finding so
// that refactoring the internal model cannot silently change the contract.
type jsonFinding struct {
	Schema      string   `json:"schema"`
	Tool        string   `json:"tool"`
	RuleID      string   `json:"rule_id"`
	Description string   `json:"description"`
	Severity    string   `json:"severity"`
	Confidence  string   `json:"confidence"`
	Engines     []string `json:"engines"`
	Tags        []string `json:"tags,omitempty"`

	Path        string `json:"path"`
	Line        int    `json:"line"`
	StartColumn int    `json:"start_column"`
	EndColumn   int    `json:"end_column"`
	LineSample  string `json:"line_sample,omitempty"`

	// Secret is populated only under --show-secrets; the default path
	// leaves it empty, which is why it carries omitempty.
	Secret   string `json:"secret,omitempty"` //nolint:gosec // G117: emitting the secret is the documented, opt-in purpose of --show-secrets
	Redacted string `json:"redacted"`

	Entropy   float64 `json:"entropy,omitempty"`
	Validator string  `json:"validator,omitempty"`
	Validated bool    `json:"validated"`

	Fingerprint string `json:"fingerprint"`
	SecretHash  string `json:"secret_hash"`

	Commit      string `json:"commit,omitempty"`
	Author      string `json:"author,omitempty"`
	AuthorEmail string `json:"author_email,omitempty"`
	Date        string `json:"date,omitempty"`
	InHEAD      *bool  `json:"in_head,omitempty"`

	Notes []string `json:"notes,omitempty"`
}

// JSONSchemaVersion identifies the JSONL contract.
const JSONSchemaVersion = "envleak.finding/v1"

func (jsonFormatter) Format(w io.Writer, r Report, o Options) error {
	enc := json.NewEncoder(w)
	for _, f := range r.Findings {
		out := toJSON(f, r, o)
		//nolint:gosec // G117: the "secret" field is populated only under
		// --show-secrets, which the help text flags as dangerous. Emitting it
		// on request is the documented purpose of the flag.
		if err := enc.Encode(out); err != nil {
			return fmt.Errorf("encode finding %s: %w", f.Fingerprint, err)
		}
	}
	return nil
}

func toJSON(f detect.Finding, r Report, o Options) jsonFinding {
	j := jsonFinding{
		Schema:      JSONSchemaVersion,
		Tool:        "envleak " + r.ToolVersion,
		RuleID:      f.RuleID,
		Description: f.Description,
		Severity:    string(f.Severity),
		Confidence:  string(f.Confidence),
		Engines:     f.Engines,
		Tags:        f.Tags,
		Path:        f.Path,
		Line:        f.Line,
		StartColumn: f.StartCol,
		EndColumn:   f.EndCol,
		LineSample:  f.LineSample,
		Redacted:    f.Redacted,
		Entropy:     f.Entropy,
		Validator:   f.ValidatorName,
		Validated:   f.Validated,
		Fingerprint: f.Fingerprint,
		SecretHash:  f.SecretHash,
		Commit:      f.Commit,
		Author:      f.Author,
		AuthorEmail: f.AuthorEmail,
		Date:        f.Date,
		InHEAD:      f.InHEAD,
		Notes:       f.Notes,
	}
	if o.ShowSecrets {
		j.Secret = f.Secret
	} else {
		// The line sample can contain the secret itself; redact it there too,
		// otherwise --format json would leak what the text format protects.
		j.LineSample = redactIn(f.LineSample, f.Secret, f.Redacted)
	}
	return j
}

func redactIn(sample, secret, redacted string) string {
	if secret == "" || sample == "" {
		return sample
	}
	return strings.ReplaceAll(sample, secret, redacted)
}
