package rules_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dotMuny/EnvLeak/internal/rules"
)

func TestDefaultCatalogueLoads(t *testing.T) {
	cat, err := rules.Default()
	require.NoError(t, err)

	// The project promises "at least 40 real rules"; guard the floor so a
	// careless edit cannot quietly gut the catalogue.
	assert.GreaterOrEqual(t, cat.Len(), 40, "catalogue shrank below the documented minimum")

	for _, r := range cat.Rules {
		assert.NotEmpty(t, r.Regex, "%s: empty regex", r.ID)
		assert.NotEmpty(t, r.Keywords, "%s: no prefilter keywords", r.ID)
		assert.Equal(t, strings.ToLower(r.ID), r.ID, "%s: rule ids are lowercase", r.ID)
	}
}

// TestKeywordsAreConsistentWithExamples is the check that keeps the prefilter
// honest: a keyword that does not occur in the rule's own positive example
// means the rule can never fire, because the regex is never reached.
func TestKeywordsAreConsistentWithExamples(t *testing.T) {
	cat, err := rules.Default()
	require.NoError(t, err)

	for _, r := range cat.Rules {
		t.Run(r.ID, func(t *testing.T) {
			for _, pos := range r.Examples.Positive {
				lower := strings.ToLower(pos)
				found := false
				for _, kw := range r.Keywords {
					if strings.Contains(lower, kw) {
						found = true
						break
					}
				}
				assert.Truef(t, found,
					"no keyword of %s occurs in its positive example %q; the prefilter would never run the regex",
					r.ID, pos)
			}
		})
	}
}

func TestCandidatesPrefilter(t *testing.T) {
	cat, err := rules.Default()
	require.NoError(t, err)

	t.Run("matches the right rule", func(t *testing.T) {
		idx := cat.Candidates([]byte("token=ghp_0123456789abcdef"), nil)
		require.NotEmpty(t, idx)
		ids := make([]string, 0, len(idx))
		for _, i := range idx {
			ids = append(ids, cat.Rules[i].ID)
		}
		assert.Contains(t, ids, "github-pat-classic")
	})

	t.Run("prose wakes nothing expensive", func(t *testing.T) {
		idx := cat.Candidates([]byte("the quick brown fox jumps over the lazy dog"), nil)
		assert.Empty(t, idx, "an ordinary line should not wake any rule: %v", idx)
	})

	t.Run("dedupes rules with several matching keywords", func(t *testing.T) {
		// gitlab-runner-token declares both "glrt-" and "gr1348941".
		idx := cat.Candidates([]byte("glrt- gr1348941 glrt-"), nil)
		seen := map[int]bool{}
		for _, i := range idx {
			assert.False(t, seen[i], "rule index %d reported twice", i)
			seen[i] = true
		}
	})

	t.Run("reuses the destination slice", func(t *testing.T) {
		buf := make([]int, 0, 8)
		buf = cat.Candidates([]byte("ghp_x"), buf[:0])
		n := len(buf)
		buf = cat.Candidates([]byte("ghp_x"), buf[:0])
		assert.Len(t, buf, n)
	})
}

func TestParseRejectsBadCatalogues(t *testing.T) {
	valid := `version: 1
rules:
  - id: a-rule
    description: A rule
    severity: high
    keywords: [abc]
    regex: 'abc'
    examples:
      positive: ['abc']
      negative: ['xyz']
`
	cases := map[string]struct {
		yaml string
		want string
	}{
		"not yaml":          {"\t\x00not yaml: [", "parse rule catalogue"},
		"no rules":          {"version: 1\nrules: []\n", "no rules defined"},
		"missing id":        {strings.Replace(valid, "id: a-rule", "description2: x", 1), "missing id"},
		"bad severity":      {strings.Replace(valid, "severity: high", "severity: apocalyptic", 1), "unknown severity"},
		"bad regex":         {strings.Replace(valid, "regex: 'abc'", "regex: '([unclosed'", 1), "compile regex"},
		"no keywords":       {strings.Replace(valid, "keywords: [abc]", "keywords: []", 1), "at least one keyword"},
		"no examples":       {strings.Replace(valid, "positive: ['abc']", "positive: []", 1), "positive and one negative"},
		"bad confidence":    {strings.Replace(valid, "severity: high", "severity: high\n    confidence: certain", 1), "unknown confidence"},
		"secret group high": {strings.Replace(valid, "regex: 'abc'", "regex: 'abc'\n    secret_group: 3", 1), "out of range"},
		"duplicate id":      {valid + strings.TrimPrefix(valid, "version: 1\nrules:\n"), "duplicate id"},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := rules.Parse([]byte(tc.yaml))
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.want)
		})
	}
}

func TestParseAcceptsMinimalRule(t *testing.T) {
	cat, err := rules.Parse([]byte(`version: 1
rules:
  - id: a-rule
    description: A rule
    severity: low
    keywords: [ABC]
    regex: 'abc'
    examples:
      positive: ['abc']
      negative: ['xyz']
`))
	require.NoError(t, err)
	require.Equal(t, 1, cat.Len())
	r, ok := cat.Get("a-rule")
	require.True(t, ok)
	assert.Equal(t, "medium", r.Confidence, "confidence defaults to medium")
	assert.Equal(t, []string{"abc"}, r.Keywords, "keywords are lowercased")
}

func TestFilterAndMerge(t *testing.T) {
	cat, err := rules.Default()
	require.NoError(t, err)

	only := cat.Filter(func(r rules.Compiled) bool { return r.ID == "github-pat-classic" })
	require.Equal(t, 1, only.Len())
	idx := only.Candidates([]byte("ghp_abc"), nil)
	assert.Len(t, idx, 1, "the filtered catalogue rebuilt its prefilter")

	override, err := rules.Parse([]byte(`version: 1
rules:
  - id: github-pat-classic
    description: Overridden
    severity: low
    keywords: [ghp_]
    regex: 'ghp_'
    examples:
      positive: ['ghp_']
      negative: ['x']
`))
	require.NoError(t, err)

	merged, err := rules.Merge(cat, override)
	require.NoError(t, err)
	assert.Equal(t, cat.Len(), merged.Len(), "overriding a rule does not add one")
	r, ok := merged.Get("github-pat-classic")
	require.True(t, ok)
	assert.Equal(t, "Overridden", r.Description)
}

func TestSeverityRank(t *testing.T) {
	assert.Greater(t, rules.SeverityCritical.Rank(), rules.SeverityHigh.Rank())
	assert.Greater(t, rules.SeverityHigh.Rank(), rules.SeverityMedium.Rank())
	assert.Greater(t, rules.SeverityMedium.Rank(), rules.SeverityLow.Rank())
	assert.Equal(t, 0, rules.Severity("nonsense").Rank())

	for _, s := range []string{"critical", "HIGH", " medium ", "low"} {
		_, err := rules.ParseSeverity(s)
		assert.NoError(t, err, s)
	}
	_, err := rules.ParseSeverity("urgent")
	assert.Error(t, err)
}

func TestEmbeddedIsTheParsedCatalogue(t *testing.T) {
	cat, err := rules.Parse(rules.Embedded())
	require.NoError(t, err)
	def, err := rules.Default()
	require.NoError(t, err)
	assert.Equal(t, def.Len(), cat.Len())
}

// FuzzParse hammers the catalogue parser. A rule file can come from a
// repository's own extra_rules, so it is untrusted input: the parser must
// return an error, never panic and never hang.
func FuzzParse(f *testing.F) {
	f.Add(string(rules.Embedded()))
	f.Add("version: 1\nrules: []\n")
	f.Add("rules:\n  - id: x\n    regex: '('\n")
	f.Add("rules:\n  - id: x\n    description: d\n    severity: low\n    keywords: [a]\n    regex: 'a'\n    secret_group: -4\n")
	f.Add("\x00\x01\x02")

	f.Fuzz(func(t *testing.T, data string) {
		cat, err := rules.Parse([]byte(data))
		if err != nil {
			return
		}
		require.NotNil(t, cat)
		// A catalogue that parsed must be usable.
		for _, r := range cat.Rules {
			require.NotNil(t, r.Regex, "rule %q compiled to a nil regex", r.ID)
		}
		_ = cat.Candidates([]byte("ghp_ AKIA sk_live_ token=abc"), nil)
	})
}

func BenchmarkPrefilter(b *testing.B) {
	cat, err := rules.Default()
	if err != nil {
		b.Fatal(err)
	}
	lines := [][]byte{
		[]byte("func (s *Scanner) Run(ctx context.Context) ([]detect.Finding, Stats, error) {"),
		[]byte("\tif err != nil { return nil, stats, fmt.Errorf(\"walk: %w\", err) }"),
		[]byte("export AWS_ACCESS_KEY_ID=AKIA2E0A8F3B244C9986"),
		[]byte(strings.Repeat("lorem ipsum dolor sit amet ", 8)),
	}
	buf := make([]int, 0, 16)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		buf = cat.Candidates(lines[i%len(lines)], buf[:0])
	}
	_ = fmt.Sprint(len(buf))
}
