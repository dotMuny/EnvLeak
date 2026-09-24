package report

import (
	"fmt"
	"io"
	"strings"

	"github.com/dotMuny/EnvLeak/internal/detect"
	"github.com/dotMuny/EnvLeak/internal/rules"
)

type textFormatter struct{}

// ANSI escapes. We write them by hand rather than pull in a colour library:
// four escape sequences do not justify a dependency.
const (
	ansiReset  = "\033[0m"
	ansiBold   = "\033[1m"
	ansiDim    = "\033[2m"
	ansiRed    = "\033[31m"
	ansiYellow = "\033[33m"
	ansiBlue   = "\033[34m"
	ansiCyan   = "\033[36m"
	ansiGreen  = "\033[32m"
)

type painter struct{ on bool }

func (p painter) wrap(code, s string) string {
	if !p.on {
		return s
	}
	return code + s + ansiReset
}

func (p painter) severity(s rules.Severity) string {
	label := strings.ToUpper(string(s))
	switch s {
	case rules.SeverityCritical:
		return p.wrap(ansiBold+ansiRed, label)
	case rules.SeverityHigh:
		return p.wrap(ansiRed, label)
	case rules.SeverityMedium:
		return p.wrap(ansiYellow, label)
	default:
		return p.wrap(ansiDim, label)
	}
}

func (f textFormatter) Format(w io.Writer, r Report, o Options) error {
	p := painter{on: o.Color}

	if len(r.Findings) == 0 {
		_, err := fmt.Fprintf(w, "%s no secrets found (%s, %.2fs)\n",
			p.wrap(ansiGreen, "✓"), plural(r.FilesScanned, "file", "files"), r.DurationSeconds)
		return wrapWrite(err)
	}

	paths, groups := byFile(r.Findings)
	for _, path := range paths {
		if _, err := fmt.Fprintf(w, "\n%s\n", p.wrap(ansiBold+ansiCyan, path)); err != nil {
			return wrapWrite(err)
		}
		for _, fd := range groups[path] {
			if err := writeFinding(w, p, fd, o); err != nil {
				return err
			}
		}
	}

	if err := writeSummary(w, p, r); err != nil {
		return err
	}
	if o.ShowSecrets {
		_, err := fmt.Fprintf(w, "\n%s\n",
			p.wrap(ansiYellow, "warning: --show-secrets printed raw secret values; do not use this in CI logs"))
		return wrapWrite(err)
	}
	return nil
}

func writeFinding(w io.Writer, p painter, fd detect.Finding, o Options) error {
	loc := fmt.Sprintf("%d:%d", fd.Line, fd.StartCol)
	line := fmt.Sprintf("  %s  %s  %s  %s\n",
		p.wrap(ansiDim, pad(loc, 9)),
		pad(p.severity(fd.Severity), 8),
		p.wrap(ansiBlue, pad(fd.RuleID, 32)),
		p.wrap(ansiBold, secretOf(fd, o)),
	)
	if _, err := io.WriteString(w, line); err != nil {
		return wrapWrite(err)
	}

	detail := fmt.Sprintf("             %s  confidence=%s engines=%s",
		fd.Description, fd.Confidence, strings.Join(fd.Engines, "+"))
	if fd.Validated {
		detail += " checksum=ok"
	}
	if fd.Entropy > 0 {
		detail += fmt.Sprintf(" entropy=%.2f", fd.Entropy)
	}
	if fd.Commit != "" {
		state := "removed from HEAD"
		if fd.InHEAD != nil && *fd.InHEAD {
			state = p.wrap(ansiRed, "STILL IN HEAD")
		}
		detail += fmt.Sprintf("\n             commit %s by %s on %s — %s",
			shortHash(fd.Commit), fd.Author, fd.Date, state)
	}
	if _, err := fmt.Fprintf(w, "%s\n", p.wrap(ansiDim, detail)); err != nil {
		return wrapWrite(err)
	}

	if o.Verbose && len(fd.Notes) > 0 {
		if _, err := fmt.Fprintf(w, "%s\n", p.wrap(ansiDim,
			"             note: "+strings.Join(fd.Notes, "; "))); err != nil {
			return wrapWrite(err)
		}
	}
	return nil
}

func writeSummary(w io.Writer, p painter, r Report) error {
	bySeverity := map[rules.Severity]int{}
	byConfidence := map[detect.Confidence]int{}
	for _, f := range r.Findings {
		bySeverity[f.Severity]++
		byConfidence[f.Confidence]++
	}

	var sevParts []string
	for _, s := range []rules.Severity{rules.SeverityCritical, rules.SeverityHigh, rules.SeverityMedium, rules.SeverityLow} {
		if n := bySeverity[s]; n > 0 {
			sevParts = append(sevParts, fmt.Sprintf("%d %s", n, p.severity(s)))
		}
	}
	var confParts []string
	for _, c := range []detect.Confidence{detect.ConfidenceHigh, detect.ConfidenceMedium, detect.ConfidenceLow} {
		if n := byConfidence[c]; n > 0 {
			confParts = append(confParts, fmt.Sprintf("%d %s", n, c))
		}
	}

	_, files := byFile(r.Findings)
	scope := plural(r.FilesScanned, "file", "files") + " scanned"
	if r.CommitsScanned > 0 {
		scope = plural(r.CommitsScanned, "commit", "commits") + " scanned"
	}

	_, err := fmt.Fprintf(w, "\n%s %s in %s  [%s]  confidence: %s\n%s\n",
		p.wrap(ansiBold+ansiRed, "✗"),
		plural(int64(len(r.Findings)), "finding", "findings"),
		plural(int64(len(files)), "file", "files"),
		strings.Join(sevParts, ", "),
		strings.Join(confParts, ", "),
		p.wrap(ansiDim, fmt.Sprintf("  %s in %.2fs", scope, r.DurationSeconds)),
	)
	return wrapWrite(err)
}

// pad right-pads s to n visible characters.
func pad(s string, n int) string {
	visible := visibleLen(s)
	if visible >= n {
		return s
	}
	return s + strings.Repeat(" ", n-visible)
}

// visibleLen counts runes outside ANSI escape sequences.
func visibleLen(s string) int {
	n, inEscape := 0, false
	for _, r := range s {
		switch {
		case r == '\033':
			inEscape = true
		case inEscape && r == 'm':
			inEscape = false
		case !inEscape:
			n++
		}
	}
	return n
}

// plural renders "1 file" / "3 files".
func plural(n int64, one, many string) string {
	if n == 1 {
		return fmt.Sprintf("%d %s", n, one)
	}
	return fmt.Sprintf("%d %s", n, many)
}

func shortHash(h string) string {
	if len(h) > 8 {
		return h[:8]
	}
	return h
}

func wrapWrite(err error) error {
	if err != nil {
		return fmt.Errorf("write report: %w", err)
	}
	return nil
}
