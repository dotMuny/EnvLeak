package allowlist

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"sort"
	"time"

	"github.com/dotMuny/EnvLeak/internal/detect"
)

// DefaultBaselineFile is where `envleak baseline` writes by default.
const DefaultBaselineFile = ".envleak-baseline.json"

// BaselineVersion is the schema version of the baseline file.
const BaselineVersion = 1

// Baseline records the findings a repository has decided to live with, so
// that later runs only report what is new. It stores fingerprints, never
// secrets: committing this file must not commit the leak a second time.
type Baseline struct {
	Version      int       `json:"version"`
	GeneratedAt  time.Time `json:"generated_at"`
	Tool         string    `json:"tool"`
	Fingerprints []string  `json:"fingerprints"`
	SecretHashes []string  `json:"secret_hashes,omitempty"`
	// Entries is human-readable context for review; it carries redacted
	// values only.
	Entries []BaselineEntry `json:"entries,omitempty"`
}

// BaselineEntry is the reviewable record behind one accepted fingerprint.
type BaselineEntry struct {
	Fingerprint string `json:"fingerprint"`
	RuleID      string `json:"rule_id"`
	Path        string `json:"path"`
	Line        int    `json:"line"`
	Redacted    string `json:"redacted"`
	Confidence  string `json:"confidence"`
}

// NewBaseline builds a baseline from a set of findings.
func NewBaseline(findings []detect.Finding, tool string) *Baseline {
	b := &Baseline{
		Version:     BaselineVersion,
		GeneratedAt: time.Now().UTC().Truncate(time.Second),
		Tool:        tool,
	}
	seen := make(map[string]bool, len(findings))
	for _, f := range findings {
		if seen[f.Fingerprint] {
			continue
		}
		seen[f.Fingerprint] = true
		b.Fingerprints = append(b.Fingerprints, f.Fingerprint)
		b.Entries = append(b.Entries, BaselineEntry{
			Fingerprint: f.Fingerprint,
			RuleID:      f.RuleID,
			Path:        f.Path,
			Line:        f.Line,
			Redacted:    f.Redacted,
			Confidence:  string(f.Confidence),
		})
	}
	sort.Strings(b.Fingerprints)
	sort.Slice(b.Entries, func(i, j int) bool {
		if b.Entries[i].Path != b.Entries[j].Path {
			return b.Entries[i].Path < b.Entries[j].Path
		}
		return b.Entries[i].Line < b.Entries[j].Line
	})
	return b
}

// WriteBaseline serialises a baseline as indented JSON.
func WriteBaseline(w io.Writer, b *Baseline) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(b); err != nil {
		return fmt.Errorf("write baseline: %w", err)
	}
	return nil
}

// LoadBaseline reads a baseline file. A missing file is not an error: it means
// "no baseline yet", which is the common first-run case.
func LoadBaseline(path string) (*Baseline, error) {
	data, err := os.ReadFile(path) //nolint:gosec // path comes from the user's own flag
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read baseline %s: %w", path, err)
	}
	var b Baseline
	if err := json.Unmarshal(data, &b); err != nil {
		return nil, fmt.Errorf("parse baseline %s: %w", path, err)
	}
	if b.Version > BaselineVersion {
		return nil, fmt.Errorf("baseline %s: unsupported version %d (this build understands %d)",
			path, b.Version, BaselineVersion)
	}
	return &b, nil
}
