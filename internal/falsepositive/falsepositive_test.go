// Package falsepositive_test measures envleak's false-positive rate against
// testdata/clean and fails if it regresses.
//
// testdata/clean is deliberately adversarial: it is a repository full of
// things that look exactly like secrets — AWS's own documentation sample,
// placeholder tokens, CI templates, commit hashes, UUIDs, base64 assets,
// lockfile integrity digests, a minified bundle — and contains no real
// credential at all. Every finding it produces is by construction a false
// positive.
//
// The budget below is a ratchet: it may be lowered when the filters improve,
// and raising it requires a deliberate edit and a reason in the commit
// message.
package falsepositive_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dotMuny/EnvLeak/internal/allowlist"
	"github.com/dotMuny/EnvLeak/internal/detect"
	"github.com/dotMuny/EnvLeak/internal/rules"
	"github.com/dotMuny/EnvLeak/internal/scan"
)

// Budgets: the most findings testdata/clean may produce, per confidence level.
//
// The high budget is zero and must stay zero — that is acceptance criterion 4,
// and the whole promise of the confidence field. If a clean corpus can produce
// a high-confidence finding, "high" means nothing.
const (
	budgetHigh   = 0
	budgetMedium = 0
	budgetLow    = 0
	budgetTotal  = 0
)

func cleanCorpus(t *testing.T) string {
	t.Helper()
	dir := filepath.Join("..", "..", "testdata", "clean")
	info, err := os.Stat(dir)
	require.NoError(t, err, "clean corpus is missing")
	require.True(t, info.IsDir())
	return dir
}

func scanClean(t *testing.T) ([]detect.Finding, scan.Stats) {
	t.Helper()

	cat, err := rules.Default()
	require.NoError(t, err)
	list, err := allowlist.New(allowlist.Config{})
	require.NoError(t, err)

	opts := detect.DefaultOptions()
	opts.Suppressor = list
	d, err := detect.New(cat, opts)
	require.NoError(t, err)

	// No allowlist, no baseline, hidden files included: the corpus gets no
	// help beyond the engines themselves.
	s, err := scan.New(d, scan.Options{
		Root:          cleanCorpus(t),
		IncludeHidden: true,
	})
	require.NoError(t, err)

	findings, stats, err := s.Run(context.Background())
	require.NoError(t, err)
	return findings, stats
}

// TestFalsePositiveBudget is the regression gate. It fails if the clean corpus
// starts producing more noise than it does today.
func TestFalsePositiveBudget(t *testing.T) {
	findings, stats := scanClean(t)
	require.Positive(t, stats.FilesScanned, "the corpus scanned nothing; is the path right?")

	counts := map[detect.Confidence]int{}
	for _, f := range findings {
		counts[f.Confidence]++
	}

	t.Logf("clean corpus: %d files, %d findings (high=%d medium=%d low=%d)",
		stats.FilesScanned, len(findings),
		counts[detect.ConfidenceHigh], counts[detect.ConfidenceMedium], counts[detect.ConfidenceLow])
	for _, f := range findings {
		t.Logf("  %s:%d  %s  [%s/%s]  %s", f.Path, f.Line, f.RuleID, f.Severity, f.Confidence, f.Redacted)
	}

	assert.LessOrEqualf(t, counts[detect.ConfidenceHigh], budgetHigh,
		"a corpus with no real secrets produced a HIGH confidence finding; that breaks the meaning of the field")
	assert.LessOrEqual(t, counts[detect.ConfidenceMedium], budgetMedium, "medium-confidence false positives regressed")
	assert.LessOrEqual(t, counts[detect.ConfidenceLow], budgetLow, "low-confidence false positives regressed")
	assert.LessOrEqual(t, len(findings), budgetTotal, "total false positives regressed")
}

// TestCleanCorpusIsActuallyAdversarial guards the guard: if somebody quietly
// deletes the tricky fixtures, the budget test above becomes meaningless.
func TestCleanCorpusIsActuallyAdversarial(t *testing.T) {
	dir := cleanCorpus(t)

	var files, secretShaped int
	markers := []string{
		"AKIAIOSFODNN7EXAMPLE", "ghp_", "sk_live_", "sk-proj-", "hooks.slack.com",
		"postgres://", "redis://", "mongodb://", "AIza", "${{ secrets.",
		"BEGIN RSA PRIVATE KEY", "Bearer ", "integrity", "sha512-",
	}

	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		files++
		data, readErr := os.ReadFile(path) //nolint:gosec // inside testdata
		if readErr != nil {
			return readErr
		}
		for _, m := range markers {
			secretShaped += strings.Count(string(data), m)
		}
		return nil
	})
	require.NoError(t, err)

	assert.GreaterOrEqual(t, files, 10, "the clean corpus should cover a realistic spread of file types")
	assert.GreaterOrEqual(t, secretShaped, 30,
		"the clean corpus must stay full of secret-shaped strings, or it proves nothing")
	t.Logf("clean corpus: %d files containing %d secret-shaped strings", files, secretShaped)
}

// TestPrecisionOnTheAdversarialCorpus states the headline number the README
// quotes, so the documented figure cannot drift from reality.
func TestPrecisionOnTheAdversarialCorpus(t *testing.T) {
	findings, _ := scanClean(t)

	var high int
	for _, f := range findings {
		if f.Confidence == detect.ConfidenceHigh {
			high++
		}
	}
	require.Zero(t, high)

	t.Logf("high-confidence findings on testdata/clean: 0 (total findings at any confidence: %d)", len(findings))
}
