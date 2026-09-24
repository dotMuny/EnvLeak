package allowlist

import (
	"strings"
)

// Directives parses inline suppression comments.
//
// Two forms are supported, on the offending line or on the line above it:
//
//	secret := "..." // envleak:ignore
//	// envleak:ignore-rule=aws-access-key-id,github-pat-classic
//	secret := "..."
//
// The comment marker itself is not matched: any language's comment syntax
// works, because we only look for the directive text.
type Directives struct {
	marker     string
	ruleMarker string
}

// DefaultDirectives returns the standard "envleak:ignore" directives.
func DefaultDirectives() *Directives {
	return &Directives{
		marker:     "envleak:ignore",
		ruleMarker: "envleak:ignore-rule=",
	}
}

// Suppressed reports whether a finding for ruleID is silenced by a directive
// on line or on prevLine.
func (d *Directives) Suppressed(ruleID, line, prevLine string) bool {
	return d.lineSuppresses(ruleID, line) || d.lineSuppresses(ruleID, prevLine)
}

func (d *Directives) lineSuppresses(ruleID, line string) bool {
	idx := strings.Index(line, d.marker)
	if idx < 0 {
		return false
	}
	rest := line[idx+len(d.marker):]

	// "envleak:ignore-rule=a,b" — scoped suppression.
	if strings.HasPrefix(rest, "-rule=") {
		list := rest[len("-rule="):]
		if end := strings.IndexAny(list, " \t*/#\"'"); end >= 0 {
			list = list[:end]
		}
		for _, id := range strings.Split(list, ",") {
			if strings.TrimSpace(id) == ruleID {
				return true
			}
		}
		return false
	}

	// A bare "envleak:ignore" silences everything on the line. Guard against
	// matching an unrelated longer word such as "envleak:ignorecase".
	if rest == "" {
		return true
	}
	switch rest[0] {
	case ' ', '\t', '\r', '\n', '*', '/', '#', '"', '\'', ')', ']', '}':
		return true
	}
	return false
}
