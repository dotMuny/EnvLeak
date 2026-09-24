// Package detect holds the three detection engines — pattern, entropy and
// checksum validators — and the logic that aggregates their verdicts into a
// single confidence level.
//
// The package knows nothing about files, Git or output formats: it is handed
// content plus a Context and hands back Findings. That is what makes it
// testable without touching disk.
package detect

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"

	"github.com/dotMuny/EnvLeak/internal/rules"
)

// Confidence expresses how sure we are that a finding is a real secret, as
// opposed to a sample, a placeholder or a random-looking identifier.
type Confidence string

// Confidence levels.
const (
	ConfidenceHigh   Confidence = "high"
	ConfidenceMedium Confidence = "medium"
	ConfidenceLow    Confidence = "low"
)

// Rank maps a confidence onto a comparable integer; higher means surer.
func (c Confidence) Rank() int {
	switch c {
	case ConfidenceHigh:
		return 3
	case ConfidenceMedium:
		return 2
	case ConfidenceLow:
		return 1
	default:
		return 0
	}
}

func confidenceFromRank(r int) Confidence {
	switch {
	case r >= 3:
		return ConfidenceHigh
	case r == 2:
		return ConfidenceMedium
	default:
		return ConfidenceLow
	}
}

// ParseConfidence converts a string into a Confidence.
func ParseConfidence(s string) (Confidence, bool) {
	switch Confidence(strings.ToLower(strings.TrimSpace(s))) {
	case ConfidenceHigh:
		return ConfidenceHigh, true
	case ConfidenceMedium:
		return ConfidenceMedium, true
	case ConfidenceLow:
		return ConfidenceLow, true
	default:
		return "", false
	}
}

// Engine names recorded on a Finding, so a report can say why we believe it.
const (
	EnginePattern   = "pattern"
	EngineEntropy   = "entropy"
	EngineValidator = "validator"
)

// Finding is one detected secret. It carries every field any formatter might
// want; it deliberately contains no presentation logic.
type Finding struct {
	RuleID      string         `json:"rule_id"`
	Description string         `json:"description"`
	Severity    rules.Severity `json:"severity"`
	Confidence  Confidence     `json:"confidence"`
	Engines     []string       `json:"engines"`
	Tags        []string       `json:"tags,omitempty"`

	Path       string `json:"path"`
	Line       int    `json:"line"`
	StartCol   int    `json:"start_column"`
	EndCol     int    `json:"end_column"`
	LineSample string `json:"line_sample"`

	// Secret is the raw matched value. It is never rendered by a formatter
	// unless --show-secrets was given; Redacted is what gets printed.
	Secret   string `json:"secret,omitempty"`
	Redacted string `json:"redacted"`

	Entropy       float64 `json:"entropy,omitempty"`
	ValidatorName string  `json:"validator,omitempty"`
	Validated     bool    `json:"validated,omitempty"`

	// Fingerprint is stable across line moves and is what the baseline and the
	// allowlist match on.
	Fingerprint string `json:"fingerprint"`
	// SecretHash identifies the secret value alone, independent of where it
	// was found. gitscan uses it to answer "is this still in HEAD?".
	SecretHash string `json:"secret_hash"`

	// Git provenance; empty for worktree scans.
	Commit      string `json:"commit,omitempty"`
	Author      string `json:"author,omitempty"`
	AuthorEmail string `json:"author_email,omitempty"`
	Date        string `json:"date,omitempty"`
	// InHEAD is nil for worktree scans; for history scans it says whether the
	// secret is still reachable from HEAD.
	InHEAD *bool `json:"in_head,omitempty"`

	// Notes records why confidence was adjusted, e.g. "documentation file".
	Notes []string `json:"notes,omitempty"`
}

// Redact keeps the first and last four characters of a secret and replaces the
// middle with a fixed-width ellipsis, so the reader can correlate a finding
// with a key in their password manager without the report itself becoming a
// secret.
func Redact(secret string) string {
	// A PEM banner is a marker, not key material: redacting it to "----...----"
	// throws away the only useful part of the message. The key bytes on the
	// following lines are never captured as the secret.
	if strings.Contains(secret, "-----BEGIN") {
		return strings.TrimSpace(secret)
	}
	r := []rune(secret)
	if len(r) <= 8 {
		return strings.Repeat("*", len(r))
	}
	return string(r[:4]) + "..." + string(r[len(r)-4:])
}

// Fingerprint derives the stable identity of a finding. The line number is
// deliberately excluded so that moving code around does not invalidate a
// baseline.
func Fingerprint(ruleID, path, secret string) string {
	sum := sha256.Sum256([]byte(ruleID + "\x00" + path + "\x00" + secret))
	return hex.EncodeToString(sum[:12])
}

// HashSecret returns a stable hash of a secret value alone.
func HashSecret(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:16])
}
