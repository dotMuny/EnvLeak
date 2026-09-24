// Package report turns findings into output. Formatters decide how something
// is printed; they never decide what gets reported — that filtering has
// already happened by the time a Report reaches them.
package report

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/dotMuny/EnvLeak/internal/detect"
)

// Format is an output format name.
type Format string

// Supported output formats.
const (
	FormatText  Format = "text"
	FormatJSON  Format = "json"
	FormatSARIF Format = "sarif"
	FormatJUnit Format = "junit"
)

// Formats lists every supported format, for help text and validation.
func Formats() []string {
	return []string{string(FormatText), string(FormatJSON), string(FormatSARIF), string(FormatJUnit)}
}

// ParseFormat validates a format name.
func ParseFormat(s string) (Format, error) {
	switch Format(strings.ToLower(strings.TrimSpace(s))) {
	case FormatText:
		return FormatText, nil
	case FormatJSON:
		return FormatJSON, nil
	case FormatSARIF:
		return FormatSARIF, nil
	case FormatJUnit:
		return FormatJUnit, nil
	default:
		return "", fmt.Errorf("unknown format %q (want one of %s)", s, strings.Join(Formats(), ", "))
	}
}

// Report is everything a formatter is allowed to see.
type Report struct {
	Findings []detect.Finding
	// Root is the scanned path, used to make locations relative.
	Root string
	// Mode is "worktree", "history", "staged" or "stdin"; it lets the text
	// formatter word its summary correctly.
	Mode string
	// Duration of the scan, in seconds.
	DurationSeconds float64
	FilesScanned    int64
	CommitsScanned  int64
	// ToolVersion is stamped into machine-readable output.
	ToolVersion string
}

// Options tune rendering.
type Options struct {
	// ShowSecrets prints raw secret values instead of redacted ones.
	ShowSecrets bool
	// Color forces ANSI colour on or off in the text formatter.
	Color bool
	// Verbose adds the per-finding notes explaining confidence adjustments.
	Verbose bool
}

// Formatter renders a Report.
type Formatter interface {
	Format(w io.Writer, r Report, o Options) error
}

// New returns the formatter for a format.
func New(f Format) (Formatter, error) {
	switch f {
	case FormatText:
		return textFormatter{}, nil
	case FormatJSON:
		return jsonFormatter{}, nil
	case FormatSARIF:
		return sarifFormatter{}, nil
	case FormatJUnit:
		return junitFormatter{}, nil
	default:
		return nil, fmt.Errorf("no formatter for %q", f)
	}
}

// secretOf returns what a formatter is allowed to print for a finding.
func secretOf(f detect.Finding, o Options) string {
	if o.ShowSecrets {
		return f.Secret
	}
	return f.Redacted
}

// byFile groups findings by path, preserving a deterministic file order.
func byFile(findings []detect.Finding) ([]string, map[string][]detect.Finding) {
	groups := make(map[string][]detect.Finding)
	for _, f := range findings {
		groups[f.Path] = append(groups[f.Path], f)
	}
	paths := make([]string, 0, len(groups))
	for p := range groups {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	return paths, groups
}
