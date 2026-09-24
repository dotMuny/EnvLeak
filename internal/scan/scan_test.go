package scan_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dotMuny/EnvLeak/internal/detect"
	"github.com/dotMuny/EnvLeak/internal/rules"
	"github.com/dotMuny/EnvLeak/internal/scan"
)

const (
	awsKey    = "AKIA2E0A8F3B244C9986"
	githubPAT = "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"
	stripeKey = "sk_live_kR7mQz2XvNb8LcYt4WpJd6Sg"
)

func detector(t *testing.T) *detect.Detector {
	t.Helper()
	cat, err := rules.Default()
	require.NoError(t, err)
	d, err := detect.New(cat, detect.DefaultOptions())
	require.NoError(t, err)
	return d
}

// tree writes a map of relative paths to contents into a fresh directory.
func tree(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for rel, content := range files {
		abs := filepath.Join(dir, filepath.FromSlash(rel))
		require.NoError(t, os.MkdirAll(filepath.Dir(abs), 0o750))
		require.NoError(t, os.WriteFile(abs, []byte(content), 0o600))
	}
	return dir
}

func ruleIDs(fs []detect.Finding) []string {
	out := make([]string, 0, len(fs))
	for _, f := range fs {
		out = append(out, f.RuleID)
	}
	return out
}

func TestIsBinary(t *testing.T) {
	assert.True(t, scan.IsBinary([]byte("PK\x03\x04\x00\x00")))
	assert.False(t, scan.IsBinary([]byte("package main\n")))
	assert.False(t, scan.IsBinary(nil))
}

func TestScanWalksTree(t *testing.T) {
	dir := tree(t, map[string]string{
		"src/deploy.sh":     "export AWS_ACCESS_KEY_ID=" + awsKey + "\n",
		"src/nested/ci.yml": "token: " + githubPAT + "\n",
		"src/clean.go":      "package src\n\nfunc main() {}\n",
	})

	s, err := scan.New(detector(t), scan.Options{Root: dir, Concurrency: 2})
	require.NoError(t, err)

	findings, stats, err := s.Run(context.Background())
	require.NoError(t, err)

	assert.ElementsMatch(t, []string{"aws-access-key-id", "github-pat-classic"}, ruleIDs(findings))
	assert.Equal(t, int64(3), stats.FilesScanned)
	assert.Positive(t, stats.BytesScanned)

	// Paths are reported relative to the scan root, with forward slashes.
	for _, f := range findings {
		assert.False(t, filepath.IsAbs(f.Path), "%s should be relative", f.Path)
		assert.NotContains(t, f.Path, `\`)
	}
}

func TestScanRespectsGitignore(t *testing.T) {
	dir := tree(t, map[string]string{
		".gitignore":       "secrets/\n*.local\n",
		"secrets/prod.env": "AWS_ACCESS_KEY_ID=" + awsKey + "\n",
		"config.local":     "token: " + githubPAT + "\n",
		"config.yml":       "token: " + githubPAT + "\n",
		"sub/.gitignore":   "ignored.txt\n",
		"sub/ignored.txt":  "AWS_ACCESS_KEY_ID=" + awsKey + "\n",
		"sub/watched.txt":  "AWS_ACCESS_KEY_ID=" + awsKey + "\n",
	})

	s, err := scan.New(detector(t), scan.Options{Root: dir, RespectGitignore: true})
	require.NoError(t, err)
	findings, _, err := s.Run(context.Background())
	require.NoError(t, err)

	paths := map[string]bool{}
	for _, f := range findings {
		paths[f.Path] = true
	}
	assert.True(t, paths["config.yml"])
	assert.True(t, paths["sub/watched.txt"], "a nested .gitignore only applies to its own subtree")
	assert.False(t, paths["secrets/prod.env"])
	assert.False(t, paths["config.local"])
	assert.False(t, paths["sub/ignored.txt"])

	// Without the flag, everything is fair game.
	s2, err := scan.New(detector(t), scan.Options{Root: dir, RespectGitignore: false})
	require.NoError(t, err)
	all, _, err := s2.Run(context.Background())
	require.NoError(t, err)
	assert.Greater(t, len(all), len(findings))
}

func TestScanSkipsBinaryAndOversizedFiles(t *testing.T) {
	dir := tree(t, map[string]string{
		"blob.bin":  "AWS_ACCESS_KEY_ID=" + awsKey + "\x00\x00binary\n",
		"big.txt":   strings.Repeat("x", 4096) + "\nAWS_ACCESS_KEY_ID=" + awsKey + "\n",
		"small.txt": "AWS_ACCESS_KEY_ID=" + awsKey + "\n",
	})

	s, err := scan.New(detector(t), scan.Options{Root: dir, MaxFileSize: 1024})
	require.NoError(t, err)
	findings, stats, err := s.Run(context.Background())
	require.NoError(t, err)

	require.Len(t, findings, 1)
	assert.Equal(t, "small.txt", findings[0].Path)
	assert.Equal(t, int64(1), stats.SkippedBinary)
	assert.Equal(t, int64(1), stats.SkippedTooBig)
}

func TestScanSkipsHiddenDirsUnlessAsked(t *testing.T) {
	dir := tree(t, map[string]string{
		".secrets/keys.txt": "AWS_ACCESS_KEY_ID=" + awsKey + "\n",
		".env":              "AWS_ACCESS_KEY_ID=" + awsKey + "\n",
		"visible.txt":       "AWS_ACCESS_KEY_ID=" + awsKey + "\n",
	})

	s, err := scan.New(detector(t), scan.Options{Root: dir})
	require.NoError(t, err)
	findings, _, err := s.Run(context.Background())
	require.NoError(t, err)

	paths := map[string]bool{}
	for _, f := range findings {
		paths[f.Path] = true
	}
	assert.True(t, paths["visible.txt"])
	assert.True(t, paths[".env"], ".env is the single most common place to leak a secret")
	assert.False(t, paths[".secrets/keys.txt"])

	s2, err := scan.New(detector(t), scan.Options{Root: dir, IncludeHidden: true})
	require.NoError(t, err)
	all, _, err := s2.Run(context.Background())
	require.NoError(t, err)
	assert.Len(t, all, 3)
}

func TestScanSkipPathCallback(t *testing.T) {
	dir := tree(t, map[string]string{
		"vendor/lib.go": "token = \"" + githubPAT + "\"\n",
		"src/main.go":   "token = \"" + githubPAT + "\"\n",
	})

	s, err := scan.New(detector(t), scan.Options{
		Root:     dir,
		SkipPath: func(rel string) bool { return strings.HasPrefix(rel, "vendor") },
	})
	require.NoError(t, err)
	findings, _, err := s.Run(context.Background())
	require.NoError(t, err)

	require.Len(t, findings, 1)
	assert.Equal(t, "src/main.go", findings[0].Path)
}

func TestScanExplicitPathList(t *testing.T) {
	dir := tree(t, map[string]string{
		"a.txt": "AWS_ACCESS_KEY_ID=" + awsKey + "\n",
		"b.txt": "AWS_ACCESS_KEY_ID=" + awsKey + "\n",
	})

	s, err := scan.New(detector(t), scan.Options{Root: dir, Paths: []string{"a.txt"}})
	require.NoError(t, err)
	findings, _, err := s.Run(context.Background())
	require.NoError(t, err)
	require.Len(t, findings, 1)
	assert.Equal(t, "a.txt", findings[0].Path)
}

func TestScanIsDeterministicAcrossConcurrency(t *testing.T) {
	files := map[string]string{}
	for i := 0; i < 40; i++ {
		files[filepath.Join("pkg", string(rune('a'+i%26))+"_"+string(rune('a'+i/26))+".go")] =
			"const key = \"" + stripeKey + "\"\n"
	}
	dir := tree(t, files)

	var first []string
	for _, workers := range []int{1, 2, 8} {
		s, err := scan.New(detector(t), scan.Options{Root: dir, Concurrency: workers})
		require.NoError(t, err)
		findings, _, err := s.Run(context.Background())
		require.NoError(t, err)

		got := make([]string, 0, len(findings))
		for _, f := range findings {
			got = append(got, f.Path)
		}
		if first == nil {
			first = got
			require.Len(t, first, 40)
			continue
		}
		assert.Equal(t, first, got, "output order must not depend on the worker count")
	}
}

func TestScanCancellation(t *testing.T) {
	files := map[string]string{}
	for i := 0; i < 200; i++ {
		files[filepath.Join("pkg", "f"+string(rune('a'+i%26))+string(rune('a'+i/26))+".txt")] =
			"AWS_ACCESS_KEY_ID=" + awsKey + "\n"
	}
	dir := tree(t, files)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	s, err := scan.New(detector(t), scan.Options{Root: dir, Concurrency: 2})
	require.NoError(t, err)
	_, _, err = s.Run(ctx)
	assert.ErrorContains(t, err, "cancelled")
}

func TestScanNewValidation(t *testing.T) {
	_, err := scan.New(nil, scan.Options{})
	assert.Error(t, err)

	s, err := scan.New(detector(t), scan.Options{})
	require.NoError(t, err, "an empty root defaults to the working directory")
	require.NotNil(t, s)
}

func TestScanStdin(t *testing.T) {
	content := "line one\nSTRIPE_KEY=" + stripeKey + "\n"
	findings, err := scan.Stdin(detector(t), strings.NewReader(content), "<stdin>")
	require.NoError(t, err)
	require.Len(t, findings, 1)
	assert.Equal(t, "<stdin>", findings[0].Path)
	assert.Equal(t, 2, findings[0].Line)
}

func TestGeneratedHeaderIsDetectedFromContent(t *testing.T) {
	dir := tree(t, map[string]string{
		// The name gives nothing away; the banner does.
		"api/service.go": "// Code generated by protoc-gen-go. DO NOT EDIT.\n\n" +
			"const key = \"" + stripeKey + "\"\n",
	})

	s, err := scan.New(detector(t), scan.Options{Root: dir})
	require.NoError(t, err)
	findings, _, err := s.Run(context.Background())
	require.NoError(t, err)

	require.Len(t, findings, 1)
	assert.Equal(t, detect.ConfidenceMedium, findings[0].Confidence)
	assert.Contains(t, findings[0].Notes, "generated file")
}

func TestScanSkipsGitDirectory(t *testing.T) {
	dir := tree(t, map[string]string{
		".git/config":     "token = " + githubPAT + "\n",
		".git/objects/ab": "AWS_ACCESS_KEY_ID=" + awsKey + "\n",
		"src/main.go":     "package main\n",
	})

	s, err := scan.New(detector(t), scan.Options{Root: dir, IncludeHidden: true})
	require.NoError(t, err)
	findings, _, err := s.Run(context.Background())
	require.NoError(t, err)
	assert.Empty(t, findings, ".git holds a second copy of every file; walking it doubles the work")
}

func BenchmarkScanTree(b *testing.B) {
	cat, err := rules.Default()
	if err != nil {
		b.Fatal(err)
	}
	d, err := detect.New(cat, detect.DefaultOptions())
	if err != nil {
		b.Fatal(err)
	}

	dir := b.TempDir()
	body := strings.Repeat("package x\n\nfunc f() { _ = \"just some ordinary source\" }\n", 40)
	for i := 0; i < 200; i++ {
		p := filepath.Join(dir, "f"+string(rune('a'+i%26))+string(rune('a'+i/26))+".go")
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			b.Fatal(err)
		}
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s, err := scan.New(d, scan.Options{Root: dir})
		if err != nil {
			b.Fatal(err)
		}
		if _, _, err := s.Run(context.Background()); err != nil {
			b.Fatal(err)
		}
	}
}
