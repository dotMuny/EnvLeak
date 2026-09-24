package allowlist_test

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dotMuny/EnvLeak/internal/allowlist"
	"github.com/dotMuny/EnvLeak/internal/detect"
)

func finding(rule, path, secret string) detect.Finding {
	return detect.Finding{
		RuleID:      rule,
		Path:        path,
		Secret:      secret,
		Redacted:    detect.Redact(secret),
		Confidence:  detect.ConfidenceHigh,
		Fingerprint: detect.Fingerprint(rule, path, secret),
		SecretHash:  detect.HashSecret(secret),
	}
}

func TestSkipPathGlobs(t *testing.T) {
	a, err := allowlist.New(allowlist.Config{
		Paths: []string{
			"vendor/**",
			"**/*.min.js",
			"third_party",
			"docs/legacy/notes.md",
		},
		PathRegexes: []string{`^generated/.*\.pb\.go$`},
	})
	require.NoError(t, err)

	skipped := []string{
		"vendor/github.com/x/y.go",
		"vendor",
		"web/static/app.min.js",
		"app.min.js",
		"third_party/lib/a.c",
		"docs/legacy/notes.md",
		"generated/api.pb.go",
	}
	for _, p := range skipped {
		assert.Truef(t, a.SkipPath(p), "%s should be skipped", p)
	}

	kept := []string{
		"internal/scan/scanner.go",
		"web/static/app.js",
		"docs/legacy/other.md",
		"generated/api.go",
	}
	for _, p := range kept {
		assert.Falsef(t, a.SkipPath(p), "%s should not be skipped", p)
	}

	var nilList *allowlist.Allowlist
	assert.False(t, nilList.SkipPath("anything"), "the zero allowlist allows everything")
}

func TestAllowlistRejectsBadPatterns(t *testing.T) {
	_, err := allowlist.New(allowlist.Config{PathRegexes: []string{"([unclosed"}})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "bad path regex")

	_, err = allowlist.New(allowlist.Config{Regexes: []string{"([unclosed"}})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "bad value regex")

	_, err = allowlist.New(allowlist.Config{Paths: []string{"[bad"}})
	assert.Error(t, err)
}

func TestFilterByRuleValueAndFingerprint(t *testing.T) {
	f1 := finding("aws-access-key-id", "src/a.go", "AKIA2E0A8F3B244C9986")
	f2 := finding("github-pat-classic", "src/b.go", "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")
	f3 := finding("stripe-live-secret-key", "src/c.go", "sk_live_kR7mQz2XvNb8LcYt4WpJd6Sg")

	a, err := allowlist.New(allowlist.Config{
		Rules:        []string{"aws-access-key-id"},
		Regexes:      []string{`^ghp_qiPM`},
		Fingerprints: []string{f3.Fingerprint},
	})
	require.NoError(t, err)

	assert.True(t, a.RuleDisabled("aws-access-key-id"))
	assert.False(t, a.RuleDisabled("github-pat-classic"))
	assert.Empty(t, a.Filter([]detect.Finding{f1, f2, f3}))

	b, err := allowlist.New(allowlist.Config{})
	require.NoError(t, err)
	assert.Len(t, b.Filter([]detect.Finding{f1, f2, f3}), 3)

	var nilList *allowlist.Allowlist
	assert.Len(t, nilList.Filter([]detect.Finding{f1}), 1)
	assert.False(t, nilList.Allowed(f1))
}

func TestInlineDirectives(t *testing.T) {
	d := allowlist.DefaultDirectives()

	t.Run("bare ignore on the same line", func(t *testing.T) {
		assert.True(t, d.Suppressed("any-rule", `key := "x" // envleak:ignore`, ""))
		assert.True(t, d.Suppressed("any-rule", `key = "x"  # envleak:ignore`, ""))
		assert.True(t, d.Suppressed("any-rule", `key: x  <!-- envleak:ignore -->`, ""))
	})
	t.Run("bare ignore on the previous line", func(t *testing.T) {
		assert.True(t, d.Suppressed("any-rule", `key := "x"`, `// envleak:ignore`))
	})
	t.Run("scoped to a rule", func(t *testing.T) {
		line := `key := "x" // envleak:ignore-rule=aws-access-key-id,github-pat-classic`
		assert.True(t, d.Suppressed("aws-access-key-id", line, ""))
		assert.True(t, d.Suppressed("github-pat-classic", line, ""))
		assert.False(t, d.Suppressed("stripe-live-secret-key", line, ""),
			"a scoped directive must not silence everything else")
	})
	t.Run("no directive", func(t *testing.T) {
		assert.False(t, d.Suppressed("any-rule", `key := "x"`, `previous line`))
	})
	t.Run("does not match a longer word", func(t *testing.T) {
		assert.False(t, d.Suppressed("any-rule", `// envleak:ignorecase`, ""))
	})
}

func TestAllowlistImplementsSuppressor(t *testing.T) {
	a, err := allowlist.New(allowlist.Config{})
	require.NoError(t, err)
	var s detect.Suppressor = a
	assert.True(t, s.Suppressed("r", `x // envleak:ignore`, ""))

	var nilList *allowlist.Allowlist
	assert.False(t, nilList.Suppressed("r", `x // envleak:ignore`, ""))
}

func TestBaselineRoundTrip(t *testing.T) {
	findings := []detect.Finding{
		finding("aws-access-key-id", "src/a.go", "AKIA2E0A8F3B244C9986"),
		finding("github-pat-classic", "src/b.go", "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"),
	}
	findings[0].Line = 12
	findings = append(findings, findings[0]) // a duplicate must fold away

	b := allowlist.NewBaseline(findings, "envleak test")
	require.Len(t, b.Fingerprints, 2)
	require.Len(t, b.Entries, 2)
	assert.Equal(t, allowlist.BaselineVersion, b.Version)

	var buf bytes.Buffer
	require.NoError(t, allowlist.WriteBaseline(&buf, b))

	// The baseline must never carry the secret itself; committing it would
	// otherwise leak the credential a second time.
	assert.NotContains(t, buf.String(), "AKIA2E0A8F3B244C9986")
	assert.Contains(t, buf.String(), "AKIA...9986")

	dir := t.TempDir()
	path := filepath.Join(dir, "baseline.json")
	require.NoError(t, os.WriteFile(path, buf.Bytes(), 0o600))

	loaded, err := allowlist.LoadBaseline(path)
	require.NoError(t, err)
	require.NotNil(t, loaded)
	assert.ElementsMatch(t, b.Fingerprints, loaded.Fingerprints)

	a, err := allowlist.New(allowlist.Config{})
	require.NoError(t, err)
	a.AddBaseline(loaded)
	assert.Empty(t, a.Filter(findings), "everything in the baseline is already accepted")

	a.AddBaseline(nil) // must not panic
}

func TestLoadBaselineErrors(t *testing.T) {
	dir := t.TempDir()

	missing, err := allowlist.LoadBaseline(filepath.Join(dir, "nope.json"))
	require.NoError(t, err, "a missing baseline is the normal first-run case")
	assert.Nil(t, missing)

	bad := filepath.Join(dir, "bad.json")
	require.NoError(t, os.WriteFile(bad, []byte("{not json"), 0o600))
	_, err = allowlist.LoadBaseline(bad)
	assert.ErrorContains(t, err, "parse baseline")

	future := filepath.Join(dir, "future.json")
	data, _ := json.Marshal(map[string]any{"version": allowlist.BaselineVersion + 1})
	require.NoError(t, os.WriteFile(future, data, 0o600))
	_, err = allowlist.LoadBaseline(future)
	assert.ErrorContains(t, err, "unsupported version")
}

func TestBaselineMatchesMovedSecrets(t *testing.T) {
	// The same secret at a different line keeps its fingerprint, because the
	// fingerprint deliberately excludes the line number.
	a := finding("aws-access-key-id", "src/a.go", "AKIA2E0A8F3B244C9986")
	a.Line = 10
	b := a
	b.Line = 400
	assert.Equal(t, a.Fingerprint, b.Fingerprint)

	list, err := allowlist.New(allowlist.Config{Fingerprints: []string{a.Fingerprint}})
	require.NoError(t, err)
	assert.True(t, list.Allowed(b), "moving code must not invalidate a baseline")
}
