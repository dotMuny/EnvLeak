package cli_test

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dotMuny/EnvLeak/internal/allowlist"
	"github.com/dotMuny/EnvLeak/internal/cli"
	"github.com/dotMuny/EnvLeak/internal/testcorpus"
)

const (
	awsKey    = "AKIA2E0A8F3B244C9986"
	githubPAT = "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"
	stripeKey = "sk_live_kR7mQz2XvNb8LcYt4WpJd6Sg"
)

type result struct {
	code   int
	stdout string
	stderr string
}

// run executes the CLI exactly as main does, capturing both streams.
func run(t *testing.T, stdin string, args ...string) result {
	t.Helper()
	var out, errBuf bytes.Buffer
	streams := cli.IO{In: strings.NewReader(stdin), Out: &out, Err: &errBuf}

	root := cli.NewRootCommand(streams)
	root.SetArgs(args)
	code := cli.ExecuteContext(context.Background(), root, streams)

	return result{code: code, stdout: out.String(), stderr: errBuf.String()}
}

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

func dirtyTree(t *testing.T) string {
	return tree(t, map[string]string{
		"src/deploy.sh": "#!/bin/sh\nexport AWS_ACCESS_KEY_ID=" + awsKey + "\n",
		"src/clean.go":  "package src\n\nfunc main() {}\n",
	})
}

func TestExitCodes(t *testing.T) {
	t.Run("clean tree exits 0", func(t *testing.T) {
		dir := tree(t, map[string]string{"a.go": "package a\n"})
		r := run(t, "", "scan", dir, "--no-color")
		assert.Equal(t, cli.ExitClean, r.code)
		assert.Contains(t, r.stdout, "no secrets found")
	})

	t.Run("findings exit 1", func(t *testing.T) {
		r := run(t, "", "scan", dirtyTree(t), "--no-color")
		assert.Equal(t, cli.ExitFindings, r.code)
		assert.Contains(t, r.stdout, "aws-access-key-id")
	})

	t.Run("errors exit 2", func(t *testing.T) {
		r := run(t, "", "scan", dirtyTree(t), "--format", "yaml")
		assert.Equal(t, cli.ExitError, r.code)
		assert.Contains(t, r.stderr, "unknown format")
	})

	t.Run("--fail-on none never fails", func(t *testing.T) {
		r := run(t, "", "scan", dirtyTree(t), "--no-color", "--fail-on", "none")
		assert.Equal(t, cli.ExitClean, r.code)
		assert.Contains(t, r.stdout, "aws-access-key-id", "the finding is still reported")
	})

	t.Run("--fail-on above the finding's severity passes", func(t *testing.T) {
		dir := tree(t, map[string]string{"a.env": "STRIPE_TEST=sk_test_kR7mQz2XvNb8LcYt4WpJd6Sg\n"})
		assert.Equal(t, cli.ExitClean, run(t, "", "scan", dir, "--no-color", "--fail-on", "high").code)
		assert.Equal(t, cli.ExitFindings, run(t, "", "scan", dir, "--no-color", "--fail-on", "low").code)
	})
}

func TestScanStdin(t *testing.T) {
	r := run(t, "GITHUB_TOKEN="+githubPAT+"\n", "scan", "-", "--no-color")
	assert.Equal(t, cli.ExitFindings, r.code)
	assert.Contains(t, r.stdout, "<stdin>")
	assert.Contains(t, r.stdout, "github-pat-classic")
	assert.NotContains(t, r.stdout, githubPAT, "stdin output is redacted like any other")
}

func TestShowSecrets(t *testing.T) {
	quiet := run(t, "TOKEN="+githubPAT+"\n", "scan", "-", "--no-color")
	assert.NotContains(t, quiet.stdout, githubPAT)

	loud := run(t, "TOKEN="+githubPAT+"\n", "scan", "-", "--no-color", "--show-secrets")
	assert.Contains(t, loud.stdout, githubPAT)
	assert.Contains(t, loud.stdout, "warning: --show-secrets")
}

func TestFormats(t *testing.T) {
	dir := dirtyTree(t)

	t.Run("json is one object per line", func(t *testing.T) {
		r := run(t, "", "scan", dir, "--format", "json")
		require.Equal(t, cli.ExitFindings, r.code)
		for _, line := range strings.Split(strings.TrimSpace(r.stdout), "\n") {
			var obj map[string]any
			require.NoError(t, json.Unmarshal([]byte(line), &obj), line)
			assert.NotEmpty(t, obj["fingerprint"])
		}
	})

	t.Run("sarif", func(t *testing.T) {
		r := run(t, "", "scan", dir, "--format", "sarif")
		var log map[string]any
		require.NoError(t, json.Unmarshal([]byte(r.stdout), &log))
		assert.Equal(t, "2.1.0", log["version"])
	})

	t.Run("junit", func(t *testing.T) {
		r := run(t, "", "scan", dir, "--format", "junit")
		assert.Contains(t, r.stdout, "<testsuites")
		assert.Contains(t, r.stdout, "aws-access-key-id")
	})
}

func TestOutputToFile(t *testing.T) {
	dir := dirtyTree(t)
	out := filepath.Join(t.TempDir(), "report.sarif")

	r := run(t, "", "scan", dir, "--format", "sarif", "-o", out)
	assert.Equal(t, cli.ExitFindings, r.code)
	assert.Empty(t, r.stdout, "nothing goes to stdout when --output names a file")

	data, err := os.ReadFile(out)
	require.NoError(t, err)
	assert.Contains(t, string(data), `"version": "2.1.0"`)

	bad := run(t, "", "scan", dir, "-o", filepath.Join(dir, "nope", "deep", "r.txt"))
	assert.Equal(t, cli.ExitError, bad.code)
	assert.Contains(t, bad.stderr, "create output file")
}

func TestRuleSelection(t *testing.T) {
	dir := tree(t, map[string]string{
		"a.env": "AWS_ACCESS_KEY_ID=" + awsKey + "\nSTRIPE=" + stripeKey + "\n",
	})

	only := run(t, "", "scan", dir, "--no-color", "--rule", "aws-access-key-id")
	assert.Contains(t, only.stdout, "aws-access-key-id")
	assert.NotContains(t, only.stdout, "stripe-live-secret-key")

	excluded := run(t, "", "scan", dir, "--no-color", "--exclude-rule", "aws-access-key-id")
	assert.NotContains(t, excluded.stdout, "aws-access-key-id")
	assert.Contains(t, excluded.stdout, "stripe-live-secret-key")

	unknown := run(t, "", "scan", dir, "--rule", "no-such-rule")
	assert.Equal(t, cli.ExitError, unknown.code)
	assert.Contains(t, unknown.stderr, "no such rule")
}

func TestConfigFileIsHonoured(t *testing.T) {
	dir := tree(t, map[string]string{
		"src/a.env":    "AWS_ACCESS_KEY_ID=" + awsKey + "\n",
		"vendor/b.env": "AWS_ACCESS_KEY_ID=" + awsKey + "\n",
		".envleak.yml": "version: 1\nallowlist:\n  paths:\n    - \"vendor/**\"\n",
	})

	r := run(t, "", "scan", dir, "--no-color")
	assert.Contains(t, r.stdout, "src/a.env")
	assert.NotContains(t, r.stdout, "vendor/b.env")

	bad := tree(t, map[string]string{".envleak.yml": "allowlist:\n  pathz: [x]\n"})
	assert.Equal(t, cli.ExitError, run(t, "", "scan", bad).code)

	missing := run(t, "", "scan", dir, "--config", filepath.Join(dir, "nope.yml"))
	assert.Equal(t, cli.ExitError, missing.code)
	assert.Contains(t, missing.stderr, "read config")
}

func TestInlineSuppressionEndToEnd(t *testing.T) {
	dir := tree(t, map[string]string{
		// Note the blank line: a bare directive also silences the line
		// *below* it, which is the form people use above a fixture block.
		"a.go": "package a\n\n" +
			"const a = \"" + stripeKey + "\" // envleak:ignore\n" +
			"\n" +
			"const b = \"" + stripeKey + "\" // envleak:ignore-rule=github-pat-classic\n",
	})
	r := run(t, "", "scan", dir, "--no-color")
	assert.Equal(t, cli.ExitFindings, r.code)
	assert.Contains(t, r.stdout, "5:12", "a directive scoped to another rule does not silence this one")
	assert.Equal(t, 1, strings.Count(r.stdout, "stripe-live-secret-key"))
}

func TestBaselineWorkflow(t *testing.T) {
	dir := dirtyTree(t)

	// Before the baseline: one finding, exit 1.
	assert.Equal(t, cli.ExitFindings, run(t, "", "scan", dir, "--no-color").code)

	b := run(t, "", "baseline", dir)
	require.Equal(t, cli.ExitClean, b.code, b.stderr)
	assert.Contains(t, b.stderr, "fingerprint")

	data, err := os.ReadFile(filepath.Join(dir, allowlist.DefaultBaselineFile))
	require.NoError(t, err)
	assert.NotContains(t, string(data), awsKey, "a baseline must never carry the secret itself")

	// After the baseline: the known finding is accepted, exit 0.
	after := run(t, "", "scan", dir, "--no-color")
	assert.Equal(t, cli.ExitClean, after.code, after.stdout)

	// A new secret is still reported.
	require.NoError(t, os.WriteFile(filepath.Join(dir, "src", "new.env"),
		[]byte("STRIPE="+stripeKey+"\n"), 0o600))
	fresh := run(t, "", "scan", dir, "--no-color")
	assert.Equal(t, cli.ExitFindings, fresh.code)
	assert.Contains(t, fresh.stdout, "stripe-live-secret-key")
	assert.NotContains(t, fresh.stdout, "aws-access-key-id")

	// --no-baseline reports everything again.
	all := run(t, "", "scan", dir, "--no-color", "--no-baseline")
	assert.Contains(t, all.stdout, "aws-access-key-id")

	// An explicitly named baseline that does not exist is an error.
	missing := run(t, "", "scan", dir, "--baseline", "nope.json")
	assert.Equal(t, cli.ExitError, missing.code)
	assert.Contains(t, missing.stderr, "does not exist")
}

func TestHistoryCommand(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "repo")
	_, err := testcorpus.Build(dir)
	require.NoError(t, err)

	r := run(t, "", "history", dir, "--no-color")
	assert.Equal(t, cli.ExitFindings, r.code)
	assert.Contains(t, r.stdout, "STILL IN HEAD")
	assert.Contains(t, r.stdout, "removed from HEAD")
	assert.Contains(t, r.stdout, "commits scanned")

	live := run(t, "", "history", dir, "--no-color", "--only-in-head")
	assert.NotContains(t, live.stdout, "removed from HEAD")
	assert.Contains(t, live.stdout, "STILL IN HEAD")

	since := run(t, "", "history", dir, "--no-color", "--since", "2024-05-01")
	assert.NotContains(t, since.stdout, "aws-access-key-id")

	notARepo := run(t, "", "history", t.TempDir())
	assert.Equal(t, cli.ExitError, notARepo.code)
	assert.Contains(t, notARepo.stderr, "open git repository")
}

func TestStagedScan(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "repo")
	_, err := testcorpus.Build(dir)
	require.NoError(t, err)

	// Nothing staged: the hook must not scan the whole tree.
	clean := run(t, "", "scan", dir, "--staged", "--no-color")
	assert.Equal(t, cli.ExitClean, clean.code)
	assert.Contains(t, clean.stdout, "no secrets found")
}

func TestInstallHook(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "repo")
	_, err := testcorpus.Build(dir)
	require.NoError(t, err)

	r := run(t, "", "install-hook", dir)
	require.Equal(t, cli.ExitClean, r.code, r.stderr)

	hook := filepath.Join(dir, ".git", "hooks", "pre-commit")
	data, err := os.ReadFile(hook)
	require.NoError(t, err)
	assert.Contains(t, string(data), "envleak scan --staged")
	assert.Contains(t, string(data), "installed by envleak")

	info, err := os.Stat(hook)
	require.NoError(t, err)
	assert.NotZero(t, info.Mode()&0o100, "the hook must be executable")

	// Re-installing our own hook is fine.
	assert.Equal(t, cli.ExitClean, run(t, "", "install-hook", dir).code)

	// Somebody else's hook is not clobbered without --force.
	require.NoError(t, os.WriteFile(hook, []byte("#!/bin/sh\necho mine\n"), 0o700))
	refused := run(t, "", "install-hook", dir)
	assert.Equal(t, cli.ExitError, refused.code)
	assert.Contains(t, refused.stderr, "--force")

	assert.Equal(t, cli.ExitClean, run(t, "", "install-hook", dir, "--force").code)

	assert.Equal(t, cli.ExitError, run(t, "", "install-hook", t.TempDir()).code)
}

func TestRulesCommand(t *testing.T) {
	r := run(t, "", "rules")
	require.Equal(t, cli.ExitClean, r.code, r.stderr)
	assert.Contains(t, r.stdout, "aws-access-key-id")
	assert.Contains(t, r.stdout, "SEVERITY")
	assert.Regexp(t, `\d+ rules`, r.stdout)

	md := run(t, "", "rules", "--markdown")
	require.Equal(t, cli.ExitClean, md.code)
	assert.Contains(t, md.stdout, "# Rule catalogue")
	assert.Contains(t, md.stdout, "| `aws-access-key-id` |")
	assert.Contains(t, md.stdout, "## Validators")

	tagged := run(t, "", "rules", "--tag", "aws")
	assert.Contains(t, tagged.stdout, "aws-access-key-id")
	assert.NotContains(t, tagged.stdout, "stripe-live-secret-key")
}

func TestVersionCommand(t *testing.T) {
	r := run(t, "", "version")
	assert.Equal(t, cli.ExitClean, r.code)
	assert.Contains(t, r.stdout, "envleak")
	assert.Contains(t, r.stdout, "commit")
}

func TestMinConfidenceFilter(t *testing.T) {
	dir := tree(t, map[string]string{
		"README.md": "STRIPE_KEY=" + stripeKey + "\n",
	})
	// In documentation the finding is downgraded to medium.
	medium := run(t, "", "scan", dir, "--no-color", "--min-confidence", "medium")
	assert.Contains(t, medium.stdout, "stripe-live-secret-key")

	high := run(t, "", "scan", dir, "--no-color", "--min-confidence", "high")
	assert.Contains(t, high.stdout, "no secrets found")

	bad := run(t, "", "scan", dir, "--min-confidence", "certain")
	assert.Equal(t, cli.ExitError, bad.code)
	assert.Contains(t, bad.stderr, "unknown confidence")
}

func TestMaxFileSizeFlag(t *testing.T) {
	dir := tree(t, map[string]string{
		"big.env": strings.Repeat("# padding\n", 200) + "AWS_ACCESS_KEY_ID=" + awsKey + "\n",
	})
	assert.Equal(t, cli.ExitFindings, run(t, "", "scan", dir, "--no-color").code)
	assert.Equal(t, cli.ExitClean, run(t, "", "scan", dir, "--no-color", "--max-file-size", "100B").code)

	bad := run(t, "", "scan", dir, "--max-file-size", "enormous")
	assert.Equal(t, cli.ExitError, bad.code)
}

func TestExtraRules(t *testing.T) {
	dir := tree(t, map[string]string{
		".envleak.yml": "version: 1\nextra_rules:\n  - company.yaml\n",
		"company.yaml": `version: 1
rules:
  - id: acme-internal-token
    description: ACME internal service token
    severity: critical
    confidence: high
    keywords: [acme_tok_]
    regex: '\b(acme_tok_[A-Za-z0-9]{16})\b'
    secret_group: 1
    examples:
      positive: ['acme_tok_kR7mQz2XvNb8LcYt']
      negative: ['acme_tok_short']
`,
		"src/a.go": "const t = \"acme_tok_kR7mQz2XvNb8LcYt\"\n",
	})

	r := run(t, "", "scan", dir, "--no-color")
	assert.Equal(t, cli.ExitFindings, r.code)
	assert.Contains(t, r.stdout, "acme-internal-token")

	broken := tree(t, map[string]string{
		".envleak.yml": "version: 1\nextra_rules:\n  - nope.yaml\n",
	})
	assert.Equal(t, cli.ExitError, run(t, "", "scan", broken).code)
}

func TestEntropyFlags(t *testing.T) {
	dir := tree(t, map[string]string{
		"a.txt": "checksum = kR7mQz2XvNb8LcYt4WpJd6SgHa1FuE3ZiOr9TpKw\n",
	})
	// No secret-ish word on the line, so contextual mode stays quiet.
	assert.Equal(t, cli.ExitClean, run(t, "", "scan", dir, "--no-color").code)

	loud := run(t, "", "scan", dir, "--no-color", "--entropy-all", "--fail-on", "low")
	assert.Equal(t, cli.ExitFindings, loud.code)
	assert.Contains(t, loud.stdout, "generic-high-entropy")

	off := run(t, "", "scan", dir, "--no-color", "--entropy-all", "--no-entropy", "--fail-on", "low")
	assert.Equal(t, cli.ExitClean, off.code)
}

func TestNoGitignoreAndHiddenFlags(t *testing.T) {
	dir := tree(t, map[string]string{
		".gitignore":    "ignored/\n",
		"ignored/a.env": "AWS_ACCESS_KEY_ID=" + awsKey + "\n",
		".hidden/b.env": "AWS_ACCESS_KEY_ID=" + awsKey + "\n",
	})
	assert.Equal(t, cli.ExitClean, run(t, "", "scan", dir, "--no-color").code)
	assert.Equal(t, cli.ExitFindings, run(t, "", "scan", dir, "--no-color", "--no-gitignore").code)
	assert.Equal(t, cli.ExitFindings, run(t, "", "scan", dir, "--no-color", "--hidden").code)
}

func TestHelpMentionsTheShowSecretsRisk(t *testing.T) {
	r := run(t, "", "scan", "--help")
	assert.Equal(t, cli.ExitClean, r.code)
	assert.Contains(t, r.stdout, "--show-secrets")
	assert.Contains(t, r.stdout, "CI logs", "the help must say where a printed secret ends up")
}
