package gitscan_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dotMuny/EnvLeak/internal/allowlist"
	"github.com/dotMuny/EnvLeak/internal/detect"
	"github.com/dotMuny/EnvLeak/internal/gitscan"
	"github.com/dotMuny/EnvLeak/internal/rules"
	"github.com/dotMuny/EnvLeak/internal/testcorpus"
)

func corpus(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "repo")
	_, err := testcorpus.Build(dir)
	require.NoError(t, err)
	return dir
}

func detector(t *testing.T) *detect.Detector {
	t.Helper()
	cat, err := rules.Default()
	require.NoError(t, err)
	list, err := allowlist.New(allowlist.Config{})
	require.NoError(t, err)
	opts := detect.DefaultOptions()
	opts.Suppressor = list
	d, err := detect.New(cat, opts)
	require.NoError(t, err)
	return d
}

// TestHistoryFindsPlantedSecrets is acceptance criterion 2: every secret
// planted in the synthetic repository is found, attributed to the commit that
// introduced it, and correctly labelled as still in HEAD or not.
func TestHistoryFindsPlantedSecrets(t *testing.T) {
	dir := corpus(t)

	s, err := gitscan.Open(dir, detector(t), gitscan.Options{AllRefs: true})
	require.NoError(t, err)

	findings, stats, err := s.Run(context.Background())
	require.NoError(t, err)
	assert.EqualValues(t, 7, stats.Commits)
	assert.Positive(t, stats.Refs)

	byRule := map[string]detect.Finding{}
	for _, f := range findings {
		byRule[f.RuleID] = f
	}

	for _, want := range testcorpus.Expected() {
		t.Run(want.RuleID, func(t *testing.T) {
			got, ok := byRule[want.RuleID]
			require.Truef(t, ok, "planted %s was not found; got %v", want.RuleID, keys(byRule))

			assert.Equal(t, want.Path, got.Path)
			require.NotNil(t, got.InHEAD)
			assert.Equalf(t, want.InHEAD, *got.InHEAD,
				"%s: expected in_head=%v", want.RuleID, want.InHEAD)

			assert.NotEmpty(t, got.Commit)
			assert.Equal(t, "envleak corpus", got.Author)
			assert.Equal(t, "corpus@envleak.test", got.AuthorEmail)
			_, err := time.Parse(time.RFC3339, got.Date)
			assert.NoError(t, err, "date %q is not RFC3339", got.Date)
		})
	}

	assert.Len(t, findings, len(testcorpus.Expected()),
		"the corpus documentation and suppressed fixture must stay quiet: got %v", keys(byRule))
}

// TestRemovedSecretsAreStillReported is the distinction the command exists
// for: deleting a secret in a later commit does not un-leak it.
func TestRemovedSecretsAreStillReported(t *testing.T) {
	dir := corpus(t)

	// The AWS key is not in the working tree any more.
	data, err := os.ReadFile(filepath.Join(dir, "src", "deploy.sh"))
	require.NoError(t, err)
	assert.NotContains(t, string(data), "AKIA")

	s, err := gitscan.Open(dir, detector(t), gitscan.Options{AllRefs: true})
	require.NoError(t, err)
	findings, _, err := s.Run(context.Background())
	require.NoError(t, err)

	var found bool
	for _, f := range findings {
		if f.RuleID == "aws-access-key-id" {
			found = true
			require.NotNil(t, f.InHEAD)
			assert.False(t, *f.InHEAD)
		}
	}
	assert.True(t, found, "a secret removed from HEAD is still in every clone")
}

func TestHistoryHeadOnlyMissesSideBranches(t *testing.T) {
	dir := corpus(t)

	s, err := gitscan.Open(dir, detector(t), gitscan.Options{AllRefs: false})
	require.NoError(t, err)
	findings, stats, err := s.Run(context.Background())
	require.NoError(t, err)
	assert.EqualValues(t, 1, stats.Refs)

	for _, f := range findings {
		assert.NotEqual(t, "github-pat-classic", f.RuleID,
			"the CI token only ever existed on feature/ci, so --all-refs=false must not see it")
	}

	all, err := gitscan.Open(dir, detector(t), gitscan.Options{AllRefs: true})
	require.NoError(t, err)
	allFindings, _, err := all.Run(context.Background())
	require.NoError(t, err)
	assert.Greater(t, len(allFindings), len(findings))
}

func TestHistorySinceDate(t *testing.T) {
	dir := corpus(t)

	since, err := time.Parse(time.RFC3339, "2024-04-01T00:00:00Z")
	require.NoError(t, err)

	s, err := gitscan.Open(dir, detector(t), gitscan.Options{AllRefs: true, Since: since})
	require.NoError(t, err)
	findings, stats, err := s.Run(context.Background())
	require.NoError(t, err)

	assert.Less(t, int(stats.Commits), 7)
	for _, f := range findings {
		when, parseErr := time.Parse(time.RFC3339, f.Date)
		require.NoError(t, parseErr)
		assert.False(t, when.Before(since), "%s predates --since", f.RuleID)
	}
}

func TestHistorySinceCommit(t *testing.T) {
	dir := corpus(t)

	s, err := gitscan.Open(dir, detector(t), gitscan.Options{AllRefs: false, SinceCommit: "HEAD~2"})
	require.NoError(t, err)
	_, stats, err := s.Run(context.Background())
	require.NoError(t, err)
	assert.EqualValues(t, 2, stats.Commits)

	bad, err := gitscan.Open(dir, detector(t), gitscan.Options{SinceCommit: "no-such-revision"})
	require.NoError(t, err)
	_, _, err = bad.Run(context.Background())
	assert.ErrorContains(t, err, "resolve --since")
}

func TestHistoryMaxCommits(t *testing.T) {
	dir := corpus(t)
	s, err := gitscan.Open(dir, detector(t), gitscan.Options{AllRefs: false, MaxCommits: 2})
	require.NoError(t, err)
	_, stats, err := s.Run(context.Background())
	require.NoError(t, err)
	assert.EqualValues(t, 2, stats.Commits)
}

func TestHistoryRespectsAllowlistPaths(t *testing.T) {
	dir := corpus(t)
	s, err := gitscan.Open(dir, detector(t), gitscan.Options{
		AllRefs:  true,
		SkipPath: func(p string) bool { return p == "src/deploy.sh" },
	})
	require.NoError(t, err)
	findings, _, err := s.Run(context.Background())
	require.NoError(t, err)

	for _, f := range findings {
		assert.NotEqual(t, "src/deploy.sh", f.Path)
	}
}

func TestHistoryFingerprintsAreCommitScoped(t *testing.T) {
	dir := corpus(t)
	s, err := gitscan.Open(dir, detector(t), gitscan.Options{AllRefs: true})
	require.NoError(t, err)
	findings, _, err := s.Run(context.Background())
	require.NoError(t, err)

	seen := map[string]bool{}
	for _, f := range findings {
		assert.NotEmpty(t, f.Fingerprint)
		assert.Falsef(t, seen[f.Fingerprint], "duplicate fingerprint for %s", f.RuleID)
		seen[f.Fingerprint] = true
	}
}

func TestOpenErrors(t *testing.T) {
	_, err := gitscan.Open(t.TempDir(), detector(t), gitscan.Options{})
	assert.ErrorContains(t, err, "open git repository")

	_, err = gitscan.Open(corpus(t), nil, gitscan.Options{})
	assert.Error(t, err)
}

func TestHistoryCancellation(t *testing.T) {
	dir := corpus(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	s, err := gitscan.Open(dir, detector(t), gitscan.Options{AllRefs: true})
	require.NoError(t, err)
	_, _, err = s.Run(ctx)
	assert.ErrorContains(t, err, "cancelled")
}

func TestStagedFiles(t *testing.T) {
	dir := corpus(t)

	root, paths, err := gitscan.StagedFiles(dir)
	require.NoError(t, err)
	assert.Equal(t, dir, filepath.Clean(root))
	assert.Empty(t, paths, "a clean corpus has nothing staged")

	_, _, err = gitscan.StagedFiles(t.TempDir())
	assert.ErrorContains(t, err, "open git repository")
}

func TestRepositoryAccessor(t *testing.T) {
	s, err := gitscan.Open(corpus(t), detector(t), gitscan.Options{})
	require.NoError(t, err)
	require.NotNil(t, s.Repository())
	head, err := s.Repository().Head()
	require.NoError(t, err)
	assert.Equal(t, "refs/heads/main", head.Name().String())
}

func keys(m map[string]detect.Finding) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
