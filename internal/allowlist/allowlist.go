// Package allowlist implements the three false-positive escape hatches:
// the .envleak.yml configuration file, inline // envleak:ignore comments, and
// the baseline of already-accepted findings.
//
// It decides what is reported, never how it is printed.
package allowlist

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/dotMuny/EnvLeak/internal/detect"
)

// Allowlist filters findings. The zero value allows everything through.
type Allowlist struct {
	paths       []string
	pathREs     []*regexp.Regexp
	rules       map[string]bool
	valueREs    []*regexp.Regexp
	fingerprint map[string]bool
	secretHash  map[string]bool
	directives  *Directives
}

// Config is the allowlist section of .envleak.yml, already parsed.
type Config struct {
	// Paths are gitignore-style globs matched against the repo-relative path.
	Paths []string
	// PathRegexes are full regexes matched against the same path.
	PathRegexes []string
	// Rules lists rule ids to disable entirely.
	Rules []string
	// Regexes match against the secret value; a hit is allowed through.
	Regexes []string
	// Fingerprints are accepted finding fingerprints (an inline baseline).
	Fingerprints []string
}

// New compiles a Config into an Allowlist.
func New(cfg Config) (*Allowlist, error) {
	a := &Allowlist{
		rules:       make(map[string]bool, len(cfg.Rules)),
		fingerprint: make(map[string]bool, len(cfg.Fingerprints)),
		secretHash:  make(map[string]bool),
		directives:  DefaultDirectives(),
	}
	for _, p := range cfg.Paths {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		// Validate the glob up front rather than swallowing ErrBadPattern on
		// every file later.
		if _, err := filepath.Match(strings.TrimSuffix(p, "/**"), "x"); err != nil {
			return nil, fmt.Errorf("allowlist: bad path glob %q: %w", p, err)
		}
		a.paths = append(a.paths, p)
	}
	for _, r := range cfg.PathRegexes {
		re, err := regexp.Compile(r)
		if err != nil {
			return nil, fmt.Errorf("allowlist: bad path regex %q: %w", r, err)
		}
		a.pathREs = append(a.pathREs, re)
	}
	for _, r := range cfg.Rules {
		a.rules[strings.TrimSpace(r)] = true
	}
	for _, r := range cfg.Regexes {
		re, err := regexp.Compile(r)
		if err != nil {
			return nil, fmt.Errorf("allowlist: bad value regex %q: %w", r, err)
		}
		a.valueREs = append(a.valueREs, re)
	}
	for _, f := range cfg.Fingerprints {
		a.fingerprint[strings.TrimSpace(f)] = true
	}
	return a, nil
}

// AddBaseline marks every fingerprint in b as already accepted.
func (a *Allowlist) AddBaseline(b *Baseline) {
	if b == nil {
		return
	}
	for _, f := range b.Fingerprints {
		a.fingerprint[f] = true
	}
	for _, h := range b.SecretHashes {
		a.secretHash[h] = true
	}
}

// SkipPath reports whether a whole file can be skipped before it is even read.
// Hoisting the path check out of the per-finding filter is what makes
// "allowlist: vendor/**" cheap rather than merely correct.
func (a *Allowlist) SkipPath(path string) bool {
	if a == nil {
		return false
	}
	p := filepath.ToSlash(path)
	for _, glob := range a.paths {
		if matchGlob(glob, p) {
			return true
		}
	}
	for _, re := range a.pathREs {
		if re.MatchString(p) {
			return true
		}
	}
	return false
}

// RuleDisabled reports whether a rule id is switched off by configuration.
func (a *Allowlist) RuleDisabled(id string) bool {
	if a == nil {
		return false
	}
	return a.rules[id]
}

// Allowed reports whether a finding should be dropped.
func (a *Allowlist) Allowed(f detect.Finding) bool {
	if a == nil {
		return false
	}
	if a.rules[f.RuleID] {
		return true
	}
	if a.fingerprint[f.Fingerprint] || a.secretHash[f.SecretHash] {
		return true
	}
	if a.SkipPath(f.Path) {
		return true
	}
	for _, re := range a.valueREs {
		if re.MatchString(f.Secret) {
			return true
		}
	}
	return false
}

// Filter returns the findings that survive the allowlist.
func (a *Allowlist) Filter(in []detect.Finding) []detect.Finding {
	if a == nil {
		return in
	}
	out := in[:0:0]
	for _, f := range in {
		if a.Allowed(f) {
			continue
		}
		out = append(out, f)
	}
	return out
}

// Suppressed implements detect.Suppressor by delegating to the inline
// directive parser.
func (a *Allowlist) Suppressed(ruleID, line, prevLine string) bool {
	if a == nil || a.directives == nil {
		return false
	}
	return a.directives.Suppressed(ruleID, line, prevLine)
}

// matchGlob supports the subset of gitignore syntax that is actually useful in
// an allowlist: a leading or trailing "**" and standard filepath.Match
// wildcards on each segment.
func matchGlob(glob, path string) bool {
	glob = filepath.ToSlash(glob)
	switch {
	case glob == path:
		return true
	case strings.HasSuffix(glob, "/**"):
		prefix := strings.TrimSuffix(glob, "/**")
		if path == prefix || strings.HasPrefix(path, prefix+"/") {
			return true
		}
		// Still allow the prefix itself to contain wildcards.
		if ok, _ := filepath.Match(prefix, path); ok {
			return true
		}
		for i := len(path) - 1; i >= 0; i-- {
			if path[i] != '/' {
				continue
			}
			if ok, _ := filepath.Match(prefix, path[:i]); ok {
				return true
			}
		}
		return false
	case strings.HasPrefix(glob, "**/"):
		suffix := strings.TrimPrefix(glob, "**/")
		if ok, _ := filepath.Match(suffix, path); ok {
			return true
		}
		for i := 0; i < len(path); i++ {
			if path[i] == '/' {
				if ok, _ := filepath.Match(suffix, path[i+1:]); ok {
					return true
				}
			}
		}
		return false
	}
	ok, _ := filepath.Match(glob, path)
	if ok {
		return true
	}
	// A bare directory name allowlists everything underneath it.
	return strings.HasPrefix(path, strings.TrimSuffix(glob, "/")+"/")
}
