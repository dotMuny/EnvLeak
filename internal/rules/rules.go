// Package rules holds the declarative secret-detection catalogue: the embedded
// YAML file, its parser and the compiled form used by the detection engines.
//
// The package is deliberately ignorant of files, Git and output formats. It
// turns bytes of YAML into compiled regexes plus a keyword prefilter, nothing
// else.
package rules

import (
	_ "embed"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

//go:embed rules.yaml
var embedded []byte

// Severity ranks how bad a confirmed leak of this kind is.
type Severity string

// Severity levels, ordered from worst to least bad.
const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
)

// Rank maps a severity onto a comparable integer; higher means worse.
func (s Severity) Rank() int {
	switch s {
	case SeverityCritical:
		return 4
	case SeverityHigh:
		return 3
	case SeverityMedium:
		return 2
	case SeverityLow:
		return 1
	default:
		return 0
	}
}

// ParseSeverity converts a string into a Severity, rejecting unknown values.
func ParseSeverity(s string) (Severity, error) {
	switch Severity(strings.ToLower(strings.TrimSpace(s))) {
	case SeverityCritical:
		return SeverityCritical, nil
	case SeverityHigh:
		return SeverityHigh, nil
	case SeverityMedium:
		return SeverityMedium, nil
	case SeverityLow:
		return SeverityLow, nil
	default:
		return "", fmt.Errorf("unknown severity %q (want critical|high|medium|low)", s)
	}
}

// Examples are the documented sample values for a rule. They are the source of
// truth both for docs/rules.md and for the per-rule table test, so every rule
// is required to carry at least one positive and one negative example.
type Examples struct {
	Positive []string `yaml:"positive"`
	Negative []string `yaml:"negative"`
}

// Rule is one declarative detection pattern as written in rules.yaml.
type Rule struct {
	ID          string   `yaml:"id"`
	Description string   `yaml:"description"`
	Severity    Severity `yaml:"severity"`
	// Confidence is what a bare pattern match is worth before the entropy and
	// validator engines have their say. Prefix-anchored formats such as
	// "ghp_" earn "high"; context-dependent ones earn "medium" or "low".
	Confidence string `yaml:"confidence"`
	Regex      string `yaml:"regex"`
	// Keywords feed the Aho-Corasick prefilter. A rule only has its regex run
	// against a line when one of its keywords is present (case-insensitive).
	Keywords []string `yaml:"keywords"`
	// SecretGroup is the capture group holding the secret itself; 0 means the
	// whole match.
	SecretGroup int `yaml:"secret_group"`
	// EntropyThreshold, when > 0, asks the entropy engine to confirm the
	// captured secret before the finding is promoted to high confidence.
	EntropyThreshold float64 `yaml:"entropy_threshold"`
	Validator        string  `yaml:"validator"`
	// Continuation names a check applied to the line *after* the match. It
	// exists for banner-style rules: "-----BEGIN RSA PRIVATE KEY-----" in a
	// README is prose, the same banner followed by base64 is a leaked key.
	Continuation string   `yaml:"continuation"`
	Tags         []string `yaml:"tags"`
	Examples     Examples `yaml:"examples"`
}

// Compiled is a Rule with its regex compiled and its keywords normalised.
type Compiled struct {
	Rule
	Regex *regexp.Regexp
}

// Catalogue is a compiled, prefilter-ready set of rules.
type Catalogue struct {
	Rules []Compiled
	// prefilter maps keyword hits onto rule indices.
	prefilter *matcher
	// always holds indices of rules that declare no keywords and therefore run
	// against every line. Load rejects such rules, so this stays empty today;
	// it exists so relaxing that constraint is a one-line change.
	always []int
}

type file struct {
	Version int    `yaml:"version"`
	Rules   []Rule `yaml:"rules"`
}

// Default parses and compiles the catalogue embedded at build time.
func Default() (*Catalogue, error) {
	return Parse(embedded)
}

// Embedded returns the raw bytes of the built-in catalogue.
func Embedded() []byte { return embedded }

// Parse reads a YAML catalogue and compiles it. Every rule is validated: a
// malformed catalogue is a build-time bug, so we fail loudly rather than
// silently skipping rules.
func Parse(data []byte) (*Catalogue, error) {
	var f file
	if err := yaml.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("parse rule catalogue: %w", err)
	}
	if len(f.Rules) == 0 {
		return nil, fmt.Errorf("parse rule catalogue: no rules defined")
	}

	cat := &Catalogue{Rules: make([]Compiled, 0, len(f.Rules))}
	seen := make(map[string]struct{}, len(f.Rules))
	patterns := make([][]string, 0, len(f.Rules))

	for i, r := range f.Rules {
		if r.ID == "" {
			return nil, fmt.Errorf("rule #%d: missing id", i)
		}
		if _, dup := seen[r.ID]; dup {
			return nil, fmt.Errorf("rule %q: duplicate id", r.ID)
		}
		seen[r.ID] = struct{}{}

		if r.Description == "" {
			return nil, fmt.Errorf("rule %q: missing description", r.ID)
		}
		if _, err := ParseSeverity(string(r.Severity)); err != nil {
			return nil, fmt.Errorf("rule %q: %w", r.ID, err)
		}
		switch r.Confidence {
		case "", "high", "medium", "low":
			if r.Confidence == "" {
				r.Confidence = "medium"
			}
		default:
			return nil, fmt.Errorf("rule %q: unknown confidence %q", r.ID, r.Confidence)
		}
		// Validator names are resolved by internal/detect, which owns the
		// registry; this package only deals with catalogue syntax.
		if len(r.Keywords) == 0 {
			return nil, fmt.Errorf("rule %q: at least one keyword is required for the prefilter", r.ID)
		}
		if len(r.Examples.Positive) == 0 || len(r.Examples.Negative) == 0 {
			return nil, fmt.Errorf("rule %q: needs at least one positive and one negative example", r.ID)
		}

		re, err := regexp.Compile(r.Regex)
		if err != nil {
			return nil, fmt.Errorf("rule %q: compile regex: %w", r.ID, err)
		}
		if r.SecretGroup < 0 || r.SecretGroup > re.NumSubexp() {
			return nil, fmt.Errorf("rule %q: secret_group %d out of range (regex has %d groups)",
				r.ID, r.SecretGroup, re.NumSubexp())
		}

		kws := make([]string, 0, len(r.Keywords))
		for _, k := range r.Keywords {
			k = strings.ToLower(strings.TrimSpace(k))
			if k == "" {
				return nil, fmt.Errorf("rule %q: empty keyword", r.ID)
			}
			kws = append(kws, k)
		}
		r.Keywords = kws

		cat.Rules = append(cat.Rules, Compiled{Rule: r, Regex: re})
		patterns = append(patterns, kws)
	}

	sort.SliceStable(cat.Rules, func(i, j int) bool { return cat.Rules[i].ID < cat.Rules[j].ID })
	// Rebuild the keyword lists in the sorted order.
	patterns = patterns[:0]
	for _, r := range cat.Rules {
		patterns = append(patterns, r.Keywords)
	}
	cat.prefilter = newMatcher(patterns)
	return cat, nil
}

// Candidates returns the indices of rules whose keyword prefilter matches the
// given line. The line is expected to be lowercased by the caller — hoisting
// the lowercasing out of the hot loop is what makes the prefilter cheap.
func (c *Catalogue) Candidates(lowerLine []byte, dst []int) []int {
	dst = c.prefilter.match(lowerLine, dst)
	return append(dst, c.always...)
}

// Len reports how many rules the catalogue holds.
func (c *Catalogue) Len() int { return len(c.Rules) }

// Get returns a rule by id.
func (c *Catalogue) Get(id string) (Compiled, bool) {
	for _, r := range c.Rules {
		if r.ID == id {
			return r, true
		}
	}
	return Compiled{}, false
}

// Filter returns a copy of the catalogue keeping only rules accepted by keep.
// It is used by --rule/--exclude-rule and by the config file's disabled list.
func (c *Catalogue) Filter(keep func(Compiled) bool) *Catalogue {
	out := &Catalogue{}
	patterns := make([][]string, 0, len(c.Rules))
	for _, r := range c.Rules {
		if keep(r) {
			out.Rules = append(out.Rules, r)
			patterns = append(patterns, r.Keywords)
		}
	}
	out.prefilter = newMatcher(patterns)
	return out
}

// Merge combines catalogues, letting a later rule override an earlier one with
// the same id. That is how a repository adds its own rules through
// extra_rules without having to re-declare the built-in ones.
func Merge(cats ...*Catalogue) (*Catalogue, error) {
	out := &Catalogue{}
	index := map[string]int{}
	for _, c := range cats {
		if c == nil {
			continue
		}
		for _, r := range c.Rules {
			if i, ok := index[r.ID]; ok {
				out.Rules[i] = r
				continue
			}
			index[r.ID] = len(out.Rules)
			out.Rules = append(out.Rules, r)
		}
	}
	sort.SliceStable(out.Rules, func(i, j int) bool { return out.Rules[i].ID < out.Rules[j].ID })
	patterns := make([][]string, 0, len(out.Rules))
	for _, r := range out.Rules {
		patterns = append(patterns, r.Keywords)
	}
	out.prefilter = newMatcher(patterns)
	return out, nil
}
