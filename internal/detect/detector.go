package detect

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"strings"

	"github.com/dotMuny/EnvLeak/internal/rules"
)

// GenericEntropyRuleID is the synthetic rule id used by the standalone
// entropy engine, which by definition has no pattern behind it.
const GenericEntropyRuleID = "generic-high-entropy"

// Suppressor decides whether a finding is silenced by an inline comment.
// internal/allowlist implements it; detect only depends on the interface so
// that the engines stay free of configuration concerns.
type Suppressor interface {
	// Suppressed reports whether a finding for ruleID on line (whose preceding
	// line is prevLine) is suppressed by an inline directive.
	Suppressed(ruleID, line, prevLine string) bool
}

// Options configures a Detector.
type Options struct {
	Entropy EntropyConfig
	// EntropyEngine enables the standalone generic-high-entropy detector.
	EntropyEngine bool
	// Suppressor, when set, is consulted for inline ignore directives.
	Suppressor Suppressor
	// MaxLineLength skips regex evaluation on absurdly long lines. Minified
	// bundles routinely ship single lines of several megabytes; running 60
	// regexes over them costs more than the whole rest of the repository.
	MaxLineLength int
	// MaxFindingsPerLine bounds pathological lines (a fixture full of tokens)
	// from flooding the report.
	MaxFindingsPerLine int
}

// DefaultOptions returns the tuned defaults.
func DefaultOptions() Options {
	return Options{
		Entropy:            DefaultEntropyConfig(),
		EntropyEngine:      true,
		MaxLineLength:      16 * 1024,
		MaxFindingsPerLine: 16,
	}
}

// Detector runs the pattern, entropy and validator engines over content and
// aggregates their verdicts.
type Detector struct {
	cat  *rules.Catalogue
	opts Options
	// continuationByRule is resolved once at construction so the hot path
	// never touches the registry map by name.
	continuationByRule map[string]Continuation
}

// New builds a Detector. It resolves every rule's validator name, so an
// unknown validator is a startup error rather than a silently skipped check.
func New(cat *rules.Catalogue, opts Options) (*Detector, error) {
	if cat == nil {
		return nil, fmt.Errorf("detect: nil catalogue")
	}
	for _, r := range cat.Rules {
		if r.Validator != "" && !HasValidator(r.Validator) {
			return nil, fmt.Errorf("detect: rule %q references unknown validator %q", r.ID, r.Validator)
		}
		if r.Continuation != "" && !HasContinuation(r.Continuation) {
			return nil, fmt.Errorf("detect: rule %q references unknown continuation %q", r.ID, r.Continuation)
		}
	}
	if opts.MaxLineLength <= 0 {
		opts.MaxLineLength = DefaultOptions().MaxLineLength
	}
	if opts.MaxFindingsPerLine <= 0 {
		opts.MaxFindingsPerLine = DefaultOptions().MaxFindingsPerLine
	}
	if opts.Entropy.MinLength <= 0 {
		opts.Entropy = DefaultEntropyConfig()
	}
	d := &Detector{cat: cat, opts: opts}
	for _, r := range cat.Rules {
		if r.Continuation == "" {
			continue
		}
		c, err := continuationFor(r.Continuation)
		if err != nil {
			return nil, fmt.Errorf("detect: rule %q: %w", r.ID, err)
		}
		if d.continuationByRule == nil {
			d.continuationByRule = make(map[string]Continuation)
		}
		d.continuationByRule[r.ID] = c
	}
	return d, nil
}

// Catalogue exposes the rule set the detector was built with.
func (d *Detector) Catalogue() *rules.Catalogue { return d.cat }

// Scratch holds the per-worker reusable buffers. Sharing one Scratch between
// goroutines is a data race; give each worker its own.
type Scratch struct {
	lower   []byte
	idx     []int
	spans   []span
	pending []pending
}

type span struct{ start, end int }

// NewScratch allocates worker-local scratch space.
func NewScratch() *Scratch { return &Scratch{} }

const maxScannerLine = 1 << 20 // 1 MiB per line before we give up on it

// ScanReader streams r line by line and returns every finding. It never holds
// more than one line of content in memory, which is what lets envleak walk a
// repository of any size in constant memory.
func (d *Detector) ScanReader(r io.Reader, ctx Context, sc *Scratch) ([]Finding, error) {
	if sc == nil {
		sc = NewScratch()
	}
	br := bufio.NewReaderSize(r, 64*1024)
	scanner := bufio.NewScanner(br)
	scanner.Buffer(make([]byte, 0, 64*1024), maxScannerLine)

	var out []Finding
	prev := ""
	lineNo := 0
	sc.pending = sc.pending[:0]
	for scanner.Scan() {
		lineNo++
		line := scanner.Text()
		// Findings held back from the previous line get their verdict now,
		// before this line contributes any of its own, so output stays in
		// line order.
		out, sc.pending = resolvePending(out, sc.pending, line)
		out = d.scanLine(out, line, prev, lineNo, ctx, sc)
		prev = line
	}
	// A deferred finding that reaches end-of-file has no continuation to
	// check, and is therefore dropped.
	sc.pending = sc.pending[:0]
	if err := scanner.Err(); err != nil {
		return out, fmt.Errorf("read %s: %w", ctx.Path, err)
	}
	return out, nil
}

// ScanBytes is the convenience wrapper used by tests and by the Git history
// walker, which already holds the blob in memory.
func (d *Detector) ScanBytes(b []byte, ctx Context) []Finding {
	f, _ := d.ScanReader(bytes.NewReader(b), ctx, nil) //nolint:errcheck // bytes.Reader never errors
	return f
}

// ScanString is ScanBytes for a string.
func (d *Detector) ScanString(s string, ctx Context) []Finding {
	return d.ScanBytes([]byte(s), ctx)
}

func (d *Detector) scanLine(out []Finding, line, prev string, lineNo int, ctx Context, sc *Scratch) []Finding {
	if line == "" || len(line) > d.opts.MaxLineLength {
		return out
	}

	sc.lower = appendLower(sc.lower[:0], line)
	sc.idx = d.cat.Candidates(sc.lower, sc.idx[:0])
	sc.spans = sc.spans[:0]

	before := len(out)
	for _, ri := range sc.idx {
		if len(out)-before >= d.opts.MaxFindingsPerLine {
			break
		}
		rule := d.cat.Rules[ri]
		for _, m := range rule.Regex.FindAllStringSubmatchIndex(line, d.opts.MaxFindingsPerLine) {
			s, e := m[0], m[1]
			if g := rule.SecretGroup; g > 0 {
				if 2*g+1 >= len(m) || m[2*g] < 0 {
					continue
				}
				s, e = m[2*g], m[2*g+1]
			}
			secret := line[s:e]
			f, ok := d.aggregate(rule, secret, line, prev, lineNo, s, e, ctx)
			if !ok {
				continue
			}
			sc.spans = append(sc.spans, span{s, e})
			out = append(out, f)
		}
	}

	out = dedupeOverlaps(out, before)
	sc.spans = sc.spans[:0]
	for _, f := range out[before:] {
		sc.spans = append(sc.spans, span{f.StartCol - 1, f.EndCol - 1})
	}
	out = d.deferContinuations(out, before, sc)

	if d.opts.EntropyEngine {
		out = d.scanEntropy(out, line, prev, lineNo, ctx, sc)
	}
	return out
}

// dedupeOverlaps keeps one finding per overlapping span on a line.
//
// A single AWS secret assignment matches both aws-secret-access-key and the
// catch-all generic-env-secret; reporting it twice makes the tool look noisy
// and doubles the work of triaging it. The survivor is the most specific and
// most severe match, which is nearly always the provider-specific rule.
func dedupeOverlaps(out []Finding, from int) []Finding {
	tail := out[from:]
	if len(tail) < 2 {
		return out
	}
	keep := make([]Finding, 0, len(tail))
	for _, f := range tail {
		replaced := false
		drop := false
		for i := range keep {
			if !spansOverlap(keep[i], f) {
				continue
			}
			if findingScore(f) > findingScore(keep[i]) {
				keep[i] = f
				replaced = true
			} else {
				drop = true
			}
			break
		}
		if !replaced && !drop {
			keep = append(keep, f)
		}
	}
	return append(out[:from], keep...)
}

// deferContinuations moves findings whose rule declares a continuation out of
// the result and into the pending buffer, to be judged against the next line.
func (d *Detector) deferContinuations(out []Finding, from int, sc *Scratch) []Finding {
	if len(d.continuationByRule) == 0 {
		return out
	}
	kept := out[:from]
	for _, f := range out[from:] {
		c, ok := d.continuationByRule[f.RuleID]
		if !ok {
			kept = append(kept, f)
			continue
		}
		sc.pending = append(sc.pending, pending{finding: f, continuation: c, name: f.RuleID})
	}
	return kept
}

func spansOverlap(a, b Finding) bool {
	return a.StartCol < b.EndCol && b.StartCol < a.EndCol
}

// findingScore ranks a finding for deduplication, in this order:
//
//  1. a validated finding wins outright — a checksum that verifies is the
//     strongest identification available, stronger than any severity;
//  2. then a provider-specific rule beats a "generic-" catch-all;
//  3. then severity, then confidence.
//
// So a JWT inside an Authorization header is reported as `jwt` (structure
// verified) rather than as the broader `authorization-bearer-header`, and an
// AWS key is reported as `aws-secret-access-key` rather than as
// `generic-env-secret`.
func findingScore(f Finding) int {
	score := f.Severity.Rank()*10 + f.Confidence.Rank()
	if !strings.HasPrefix(f.RuleID, "generic-") {
		score += 100
	}
	if f.Validated {
		score += 1000
	}
	return score
}

// aggregate turns one pattern hit into a Finding, letting the entropy and
// validator engines raise or lower the confidence the rule declared.
func (d *Detector) aggregate(rule rules.Compiled, secret, line, prev string, lineNo, start, end int, ctx Context) (Finding, bool) {
	if IsPlaceholder(secret) {
		return Finding{}, false
	}
	if d.opts.Suppressor != nil && d.opts.Suppressor.Suppressed(rule.ID, line, prev) {
		return Finding{}, false
	}

	conf, _ := ParseConfidence(rule.Confidence)
	rank := conf.Rank()
	engines := []string{EnginePattern}
	var notes []string
	var entropy float64

	if rule.EntropyThreshold > 0 {
		entropy = Shannon(secret)
		if entropy >= rule.EntropyThreshold {
			rank++
			engines = append(engines, EngineEntropy)
		} else {
			rank--
			notes = append(notes, fmt.Sprintf("entropy %.2f below rule threshold %.2f", entropy, rule.EntropyThreshold))
		}
	}

	validated := false
	if rule.Validator != "" {
		if v, ok := validators[rule.Validator]; ok {
			if v(secret) {
				validated = true
				rank = ConfidenceHigh.Rank()
				engines = append(engines, EngineValidator)
			} else {
				rank--
				notes = append(notes, "checksum/structure validation failed")
			}
		}
	}

	if ctx.Discounted() {
		rank--
		notes = append(notes, ctx.Reason())
	}

	if rank > ConfidenceHigh.Rank() {
		rank = ConfidenceHigh.Rank()
	}
	if rank < ConfidenceLow.Rank() {
		rank = ConfidenceLow.Rank()
	}

	return Finding{
		RuleID:        rule.ID,
		Description:   rule.Description,
		Severity:      rule.Severity,
		Confidence:    confidenceFromRank(rank),
		Engines:       engines,
		Tags:          rule.Tags,
		Path:          ctx.Path,
		Line:          lineNo,
		StartCol:      start + 1,
		EndCol:        end + 1,
		LineSample:    sampleLine(line),
		Secret:        secret,
		Redacted:      Redact(secret),
		Entropy:       entropy,
		ValidatorName: rule.Validator,
		Validated:     validated,
		Fingerprint:   Fingerprint(rule.ID, ctx.Path, secret),
		SecretHash:    HashSecret(secret),
		Notes:         notes,
	}, true
}

// entropyContextWords gate the standalone entropy engine. Without them it
// fires on every commit hash, UUID and base64 asset in the tree.
var entropyContextWords = []string{
	"secret", "token", "password", "passwd", "pwd", "apikey", "api_key",
	"api-key", "access_key", "accesskey", "private", "credential", "auth",
	"signature", "cert", "bearer", "session",
}

func (d *Detector) scanEntropy(out []Finding, line, prev string, lineNo int, ctx Context, sc *Scratch) []Finding {
	if d.opts.Entropy.Contextual && !containsAny(sc.lower, entropyContextWords) {
		return out
	}
	if d.opts.Suppressor != nil && d.opts.Suppressor.Suppressed(GenericEntropyRuleID, line, prev) {
		return out
	}

	for _, c := range candidates(line, d.opts.Entropy.MinLength) {
		if overlaps(sc.spans, c.start, c.end) {
			continue
		}
		entropy, ok := d.opts.Entropy.Score(c.value)
		if !ok || IsPlaceholder(c.value) {
			continue
		}
		rank := ConfidenceLow.Rank()
		var notes []string
		if ctx.Discounted() {
			notes = append(notes, ctx.Reason())
		}
		alphabet := Classify(c.value)
		out = append(out, Finding{
			RuleID:      GenericEntropyRuleID,
			Description: fmt.Sprintf("High-entropy %s string (%.2f bits/char)", alphabet, entropy),
			Severity:    rules.SeverityLow,
			Confidence:  confidenceFromRank(rank),
			Engines:     []string{EngineEntropy},
			Tags:        []string{"generic", "entropy"},
			Path:        ctx.Path,
			Line:        lineNo,
			StartCol:    c.start + 1,
			EndCol:      c.end + 1,
			LineSample:  sampleLine(line),
			Secret:      c.value,
			Redacted:    Redact(c.value),
			Entropy:     entropy,
			Fingerprint: Fingerprint(GenericEntropyRuleID, ctx.Path, c.value),
			SecretHash:  HashSecret(c.value),
			Notes:       notes,
		})
		if len(out) > 0 && len(out)%d.opts.MaxFindingsPerLine == 0 {
			break
		}
	}
	return out
}

func overlaps(spans []span, start, end int) bool {
	for _, s := range spans {
		if start < s.end && s.start < end {
			return true
		}
	}
	return false
}

func containsAny(lowerLine []byte, words []string) bool {
	for _, w := range words {
		if bytes.Contains(lowerLine, []byte(w)) {
			return true
		}
	}
	return false
}

// appendLower ASCII-lowercases s into dst. The prefilter only ever deals with
// ASCII keywords, so a full unicode fold would be wasted work on the hottest
// path in the program.
func appendLower(dst []byte, s string) []byte {
	if cap(dst) < len(s) {
		dst = make([]byte, 0, len(s))
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		dst = append(dst, c)
	}
	return dst
}

const maxSample = 200

// sampleLine trims a line down to something safe to echo in a report.
func sampleLine(line string) string {
	line = strings.TrimSpace(line)
	if len(line) <= maxSample {
		return line
	}
	return line[:maxSample] + "..."
}
