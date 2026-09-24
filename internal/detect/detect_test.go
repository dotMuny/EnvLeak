package detect_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dotMuny/EnvLeak/internal/detect"
	"github.com/dotMuny/EnvLeak/internal/rules"
)

func TestShannon(t *testing.T) {
	cases := []struct {
		in   string
		want float64
	}{
		{"", 0},
		{"aaaaaaaa", 0},
		{"abababab", 1},
		{"abcd", 2},
	}
	for _, tc := range cases {
		assert.InDelta(t, tc.want, detect.Shannon(tc.in), 0.0001, tc.in)
	}
	// Random-looking material must outscore English prose.
	assert.Greater(t,
		detect.Shannon("kR7mQz2XvNb8LcYt4WpJd6SgHa1FuE3Zi"),
		detect.Shannon("the quick brown fox jumps over it"))
}

func TestClassify(t *testing.T) {
	cases := map[string]detect.Alphabet{
		"3f9a1c7e5b2d8460": detect.AlphabetHex,
		"DEADBEEF":         detect.AlphabetHex,
		"kR7mQz2XvNb8LcYt": detect.AlphabetBase64,
		"a+b/c=":           detect.AlphabetBase64,
		"has spaces":       detect.AlphabetOther,
		"emoji🔑":           detect.AlphabetOther,
		"":                 detect.AlphabetOther,
	}
	for in, want := range cases {
		assert.Equal(t, want, detect.Classify(in), in)
	}
	assert.Equal(t, "hex", detect.AlphabetHex.String())
	assert.Equal(t, "base64", detect.AlphabetBase64.String())
	assert.Equal(t, "other", detect.AlphabetOther.String())
}

func TestEntropyScore(t *testing.T) {
	cfg := detect.DefaultEntropyConfig()

	t.Run("short strings never score", func(t *testing.T) {
		_, ok := cfg.Score("ab12cd34")
		assert.False(t, ok, "eight characters is sampling noise, not entropy")
	})
	t.Run("random base64 clears the bar", func(t *testing.T) {
		e, ok := cfg.Score("kR7mQz2XvNb8LcYt4WpJd6SgHa1FuE3ZiOr9TpKw")
		assert.True(t, ok)
		assert.Greater(t, e, cfg.Base64Threshold)
	})
	t.Run("repetitive base64 does not", func(t *testing.T) {
		_, ok := cfg.Score("abababababababababababababababab")
		assert.False(t, ok)
	})
	t.Run("hex uses a lower bar", func(t *testing.T) {
		e, ok := cfg.Score("3f9a1c7e5b2d8460af13ce92b7d045e6")
		assert.True(t, ok, "entropy %.2f under hex threshold %.2f", e, cfg.HexThreshold)
		assert.Less(t, e, cfg.Base64Threshold,
			"this is exactly why hex needs its own threshold: 4 bits per symbol cannot reach the base64 bar")
	})
	t.Run("non-secret alphabets are not scored", func(t *testing.T) {
		_, ok := cfg.Score("this is a sentence with spaces in it")
		assert.False(t, ok)
	})
}

func TestGitHubChecksumValidator(t *testing.T) {
	// Build a token that is valid by construction, then corrupt it.
	payload := "qiPM0w7CCbBexFGwQ7Ru8q77KresIa"
	require.Len(t, payload, 30)
	token := "ghp_" + payload + detect.GitHubChecksum(payload)
	require.Len(t, token, 40)

	d := newDetector(t)
	ctx := detect.Context{Path: "src/main.go"}

	valid := d.ScanString("token = "+token, ctx)
	require.Len(t, valid, 1)
	assert.True(t, valid[0].Validated, "checksum should verify")
	assert.Equal(t, detect.ConfidenceHigh, valid[0].Confidence)

	// Flip one character of the payload: the checksum no longer matches.
	corrupt := "ghp_" + "X" + payload[1:] + detect.GitHubChecksum(payload)
	broken := d.ScanString("token = "+corrupt, ctx)
	require.Len(t, broken, 1)
	assert.False(t, broken[0].Validated)
	assert.Equal(t, detect.ConfidenceMedium, broken[0].Confidence,
		"a failed checksum downgrades but never drops: the token format could have changed")
	assert.Contains(t, strings.Join(broken[0].Notes, " "), "validation failed")
}

func TestJWTValidator(t *testing.T) {
	d := newDetector(t)
	ctx := detect.Context{Path: "src/main.go"}

	real := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
		"eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0." +
		"dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	fs := d.ScanString("jwt: "+real, ctx)
	require.NotEmpty(t, fs)
	assert.True(t, fs[0].Validated, "a real JWT header decodes to JSON with an alg claim")

	// Same shape, but the header is not JSON — the classic false positive.
	fake := "eyJub3Rqc29uAAAAAAAA.eyJub3Rqc29uAAAAAAAA.AAAAAAAAAAAAAAAAAAAA"
	for _, f := range d.ScanString("blob: "+fake, ctx) {
		if f.RuleID == "jwt" {
			assert.False(t, f.Validated)
		}
	}
}

func TestRedact(t *testing.T) {
	assert.Equal(t, "ghp_...uIqi", detect.Redact("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"))
	assert.Equal(t, "********", detect.Redact("12345678"), "short secrets are fully masked")
	assert.Equal(t, "", detect.Redact(""))
	assert.Equal(t, "-----BEGIN RSA PRIVATE KEY-----",
		detect.Redact("-----BEGIN RSA PRIVATE KEY-----"),
		"a PEM banner is a marker, not key material")
}

func TestFingerprintStability(t *testing.T) {
	a := detect.Fingerprint("rule", "a/b.go", "secret")
	assert.Equal(t, a, detect.Fingerprint("rule", "a/b.go", "secret"), "fingerprints are deterministic")
	assert.NotEqual(t, a, detect.Fingerprint("rule", "a/c.go", "secret"))
	assert.NotEqual(t, a, detect.Fingerprint("other", "a/b.go", "secret"))
	assert.Equal(t, detect.HashSecret("secret"), detect.HashSecret("secret"))
	assert.NotEqual(t, detect.HashSecret("secret"), detect.HashSecret("Secret"))
}

func TestIsPlaceholder(t *testing.T) {
	placeholders := []string{
		"AKIAIOSFODNN7EXAMPLE",
		"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		"your-api-key-here",
		"YOUR_TOKEN_HERE",
		"changeme",
		"please-change-this-in-production",
		"<TOKEN>",
		"${GITHUB_TOKEN}",
		"${{ secrets.NPM_TOKEN }}",
		"{{ .Secret }}",
		"$TOKEN",
		"%TOKEN%",
		"[REDACTED]",
		"process.env.API_KEY",
		"var.db_password",
		"secrets.AWS_SECRET_ACCESS_KEY",
		"$(cat /run/secrets/key)",
		"xxxxxxxxxxxxxxxx",
		"0000000000000000",
		"aaaaaaaaaaaaaaaa",
		"sk_test_00000000000000000000000000",
		"password",
		"admin",
		"",
		"   ",
	}
	for _, p := range placeholders {
		assert.Truef(t, detect.IsPlaceholder(p), "%q should be recognised as a placeholder", p)
	}

	real := []string{
		"kR7mQz2XvNb8LcYt4WpJd6SgHa1FuE3Zi",
		"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",
		"3f9a1c7e5b2d8460af13ce92b7d045e6",
		"Tz9sVbLm3XcQ8pNwYe4RdJh6KfAu2GiO",
	}
	for _, r := range real {
		assert.Falsef(t, detect.IsPlaceholder(r), "%q is not a placeholder", r)
	}
}

func TestClassifyPath(t *testing.T) {
	cases := map[string]func(detect.Context) bool{
		"README.md":                  func(c detect.Context) bool { return c.IsDoc },
		"docs/api.mdx":               func(c detect.Context) bool { return c.IsDoc },
		"internal/scan/scan_test.go": func(c detect.Context) bool { return c.IsTest },
		"src/__tests__/a.js":         func(c detect.Context) bool { return c.IsTest },
		"config/.env.example":        func(c detect.Context) bool { return c.IsExample },
		"package-lock.json":          func(c detect.Context) bool { return c.IsLockfile },
		"go.sum":                     func(c detect.Context) bool { return c.IsLockfile },
		"vendor/pkg/a.go":            func(c detect.Context) bool { return c.IsVendored },
		"node_modules/x/index.js":    func(c detect.Context) bool { return c.IsVendored },
		"web/dist/bundle.min.js":     func(c detect.Context) bool { return c.IsMinified },
		"api/service.pb.go":          func(c detect.Context) bool { return c.IsGenerated },
	}
	for path, check := range cases {
		c := detect.ClassifyPath(path)
		assert.Truef(t, check(c), "%s was classified as %+v", path, c)
		assert.Truef(t, c.Discounted(), "%s should be discounted", path)
		assert.NotEmptyf(t, c.Reason(), "%s should explain its discount", path)
	}

	plain := detect.ClassifyPath("internal/scan/scanner.go")
	assert.False(t, plain.Discounted())
	assert.Empty(t, plain.Reason())
}

func TestLooksGenerated(t *testing.T) {
	assert.True(t, detect.LooksGenerated("// Code generated by protoc-gen-go. DO NOT EDIT."))
	assert.True(t, detect.LooksGenerated("# @generated"))
	assert.False(t, detect.LooksGenerated("// Package scan walks a working tree."))
}

func TestContextDowngradesConfidence(t *testing.T) {
	d := newDetector(t)
	line := "STRIPE_KEY=sk_live_kR7mQz2XvNb8LcYt4WpJd6Sg"

	prod := d.ScanString(line, detect.Context{Path: "src/billing.go"})
	require.Len(t, prod, 1)
	assert.Equal(t, detect.ConfidenceHigh, prod[0].Confidence)

	doc := d.ScanString(line, detect.ClassifyPath("docs/billing.md"))
	require.Len(t, doc, 1)
	assert.Equal(t, detect.ConfidenceMedium, doc[0].Confidence,
		"the same secret in documentation is one level less believable")
	assert.Contains(t, doc[0].Notes, "documentation file")
}

func TestOverlappingFindingsAreDeduped(t *testing.T) {
	d := newDetector(t)
	ctx := detect.Context{Path: "src/config.go"}

	// Matches both aws-secret-access-key and the generic-env-secret catch-all.
	fs := d.ScanString("AWS_SECRET_ACCESS_KEY = kQ7vTz2mR9dXpL4wNbGs8yJhCe5AuiZr3VoFxMt1", ctx)
	require.Len(t, fs, 1, "the specific rule wins over the generic one")
	assert.Equal(t, "aws-secret-access-key", fs[0].RuleID)

	// A validated JWT beats the broader bearer-header rule that covers it.
	jwt := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
		"eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0." +
		"dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	fs = d.ScanString("Authorization: Bearer "+jwt, ctx)
	require.Len(t, fs, 1)
	assert.Equal(t, "jwt", fs[0].RuleID, "a verified structure beats a broader pattern")
}

func TestInlineSuppression(t *testing.T) {
	d, err := detect.New(mustCatalogue(t), withSuppressor(suppressorFunc(func(ruleID, line, prev string) bool {
		return strings.Contains(line, "envleak:ignore") || strings.Contains(prev, "envleak:ignore")
	})))
	require.NoError(t, err)

	ctx := detect.Context{Path: "src/main.go"}
	secret := "STRIPE_KEY=sk_live_kR7mQz2XvNb8LcYt4WpJd6Sg"

	assert.Len(t, d.ScanString(secret, ctx), 1)
	assert.Empty(t, d.ScanString(secret+" // envleak:ignore", ctx))
	assert.Empty(t, d.ScanString("// envleak:ignore\n"+secret, ctx))
}

func TestEntropyEngineIsContextual(t *testing.T) {
	cat := mustCatalogue(t)

	opts := detect.DefaultOptions()
	d, err := detect.New(cat, opts)
	require.NoError(t, err)

	ctx := detect.Context{Path: "src/main.go"}
	// A commit hash with no secret-ish word nearby: contextual mode stays quiet.
	assert.Empty(t, entropyFindings(d.ScanString("build = \"kR7mQz2XvNb8LcYt4WpJd6SgHa1FuE3ZiOr9\"", ctx)))

	opts.Entropy.Contextual = false
	loud, err := detect.New(cat, opts)
	require.NoError(t, err)
	assert.NotEmpty(t, entropyFindings(loud.ScanString("build = \"kR7mQz2XvNb8LcYt4WpJd6SgHa1FuE3ZiOr9\"", ctx)),
		"--entropy-all should report it")
}

func TestEntropyEngineCanBeDisabled(t *testing.T) {
	opts := detect.DefaultOptions()
	opts.EntropyEngine = false
	d, err := detect.New(mustCatalogue(t), opts)
	require.NoError(t, err)
	line := "credential blob: kR7mQz2XvNb8LcYt4WpJd6SgHa1FuE3ZiOr9TpKwLmXb"
	assert.Empty(t, entropyFindings(d.ScanString(line, detect.Context{Path: "a.txt"})))
}

func TestScanReaderIsLineOriented(t *testing.T) {
	d := newDetector(t)
	content := strings.Join([]string{
		"line one",
		"AWS_ACCESS_KEY_ID=AKIA2E0A8F3B244C9986",
		"line three",
		"GITHUB_TOKEN=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",
	}, "\n")

	fs := d.ScanBytes([]byte(content), detect.Context{Path: "deploy.sh"})
	require.Len(t, fs, 2)
	assert.Equal(t, 2, fs[0].Line)
	assert.Equal(t, 4, fs[1].Line)
	assert.Equal(t, "deploy.sh", fs[0].Path)
	assert.Positive(t, fs[0].StartCol)
	assert.Greater(t, fs[0].EndCol, fs[0].StartCol)
}

func TestLongLinesAreSkipped(t *testing.T) {
	opts := detect.DefaultOptions()
	opts.MaxLineLength = 64
	d, err := detect.New(mustCatalogue(t), opts)
	require.NoError(t, err)

	padded := strings.Repeat("x", 100) + " AKIA2E0A8F3B244C9986"
	assert.Empty(t, d.ScanString(padded, detect.Context{Path: "bundle.js"}),
		"a minified megabyte-long line is not worth 65 regexes")
}

func TestNewRejectsUnknownValidator(t *testing.T) {
	cat, err := rules.Parse([]byte(`version: 1
rules:
  - id: a-rule
    description: A rule
    severity: low
    keywords: [abc]
    regex: 'abc'
    validator: does-not-exist
    examples:
      positive: ['abc']
      negative: ['xyz']
`))
	require.NoError(t, err)

	_, err = detect.New(cat, detect.DefaultOptions())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown validator")

	_, err = detect.New(nil, detect.DefaultOptions())
	assert.Error(t, err)
}

func TestConfidenceParsing(t *testing.T) {
	for _, s := range []string{"high", "MEDIUM", " low "} {
		_, ok := detect.ParseConfidence(s)
		assert.True(t, ok, s)
	}
	_, ok := detect.ParseConfidence("certain")
	assert.False(t, ok)
	assert.Greater(t, detect.ConfidenceHigh.Rank(), detect.ConfidenceMedium.Rank())
	assert.Greater(t, detect.ConfidenceMedium.Rank(), detect.ConfidenceLow.Rank())
	assert.Equal(t, 0, detect.Confidence("nope").Rank())
}

func TestValidatorRegistry(t *testing.T) {
	assert.True(t, detect.HasValidator("github-crc32"))
	assert.False(t, detect.HasValidator("nope"))
	assert.NotEmpty(t, detect.ValidatorNames())
}

// FuzzEntropy drives the entropy engine with arbitrary input. It must never
// panic, and entropy must stay inside its mathematical bounds: between 0 and
// log2 of the number of distinct symbols, which for bytes is 8.
func FuzzEntropy(f *testing.F) {
	f.Add("")
	f.Add("aaaaaaaaaaaaaaaa")
	f.Add("kR7mQz2XvNb8LcYt4WpJd6SgHa1FuE3Zi")
	f.Add("3f9a1c7e5b2d8460af13ce92b7d045e6")
	f.Add("\x00\xff\xfe binary-ish \x01")
	f.Add(strings.Repeat("ab", 512))

	cfg := detect.DefaultEntropyConfig()
	f.Fuzz(func(t *testing.T, s string) {
		e := detect.Shannon(s)
		require.False(t, e < 0, "entropy %v is negative for %q", e, s)
		require.LessOrEqual(t, e, 8.0001, "entropy %v exceeds 8 bits per byte for %q", e, s)
		if s == "" {
			require.Zero(t, e)
		}

		score, ok := cfg.Score(s)
		require.InDelta(t, e, score, 0.0001)
		if ok {
			require.GreaterOrEqual(t, len(s), cfg.MinLength)
			require.NotEqual(t, detect.AlphabetOther, detect.Classify(s))
		}
	})
}

func BenchmarkScanLine(b *testing.B) {
	cat, err := rules.Default()
	if err != nil {
		b.Fatal(err)
	}
	d, err := detect.New(cat, detect.DefaultOptions())
	if err != nil {
		b.Fatal(err)
	}
	content := []byte(strings.Join([]string{
		"package scan",
		"",
		"import (\n\t\"fmt\"\n\t\"os\"\n)",
		"func main() { fmt.Println(os.Getenv(\"HOME\")) }",
		"// a comment that mentions no secrets at all",
		"AWS_ACCESS_KEY_ID=AKIA2E0A8F3B244C9986",
	}, "\n"))
	ctx := detect.Context{Path: "src/main.go"}

	b.SetBytes(int64(len(content)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = d.ScanBytes(content, ctx)
	}
}

// --- helpers ---------------------------------------------------------------

type suppressorFunc func(ruleID, line, prev string) bool

func (f suppressorFunc) Suppressed(ruleID, line, prev string) bool { return f(ruleID, line, prev) }

func withSuppressor(s detect.Suppressor) detect.Options {
	o := detect.DefaultOptions()
	o.Suppressor = s
	return o
}

func mustCatalogue(t *testing.T) *rules.Catalogue {
	t.Helper()
	cat, err := rules.Default()
	require.NoError(t, err)
	return cat
}

func entropyFindings(fs []detect.Finding) []detect.Finding {
	var out []detect.Finding
	for _, f := range fs {
		if f.RuleID == detect.GenericEntropyRuleID {
			out = append(out, f)
		}
	}
	return out
}

func TestPEMContinuation(t *testing.T) {
	d := newDetector(t)
	ctx := detect.Context{Path: "config/service.pem"}

	t.Run("banner followed by key material fires", func(t *testing.T) {
		fs := d.ScanString(
			"-----BEGIN RSA PRIVATE KEY-----\n"+
				"MIIBOgIBAAJBAKj34GkxFhD90vcNLYLInFEX6Ppy1tPf9Cnzj4p4WGeKLs1Pt8Qu\n"+
				"-----END RSA PRIVATE KEY-----\n", ctx)
		require.Len(t, fs, 1)
		assert.Equal(t, "private-key-rsa", fs[0].RuleID)
		assert.Equal(t, 1, fs[0].Line, "the finding is reported on the banner line, not the body")
	})

	t.Run("banner quoted in prose does not", func(t *testing.T) {
		assert.Empty(t, d.ScanString(
			"Generate one with openssl; the file starts with\n"+
				"-----BEGIN RSA PRIVATE KEY-----\n"+
				"(your key goes here)\n", detect.Context{Path: "README.md"}))
	})

	t.Run("banner at end of file does not", func(t *testing.T) {
		assert.Empty(t, d.ScanString("-----BEGIN RSA PRIVATE KEY-----", ctx),
			"a banner with nothing after it is not a key")
	})

	t.Run("encrypted PEM headers count as a body", func(t *testing.T) {
		fs := d.ScanString("-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\n", ctx)
		require.Len(t, fs, 1)
	})

	t.Run("ordering is preserved around a deferred finding", func(t *testing.T) {
		fs := d.ScanString(
			"-----BEGIN RSA PRIVATE KEY-----\n"+
				"MIIBOgIBAAJBAKj34GkxFhD90vcNLYLInFEX6Ppy1tPf9Cnzj4p4WGeKLs1Pt8Qu\n"+
				"AWS_ACCESS_KEY_ID=AKIA2E0A8F3B244C9986\n", ctx)
		require.Len(t, fs, 2)
		assert.Equal(t, 1, fs[0].Line)
		assert.Equal(t, 3, fs[1].Line)
	})

	t.Run("scratch is not leaked between files", func(t *testing.T) {
		sc := detect.NewScratch()
		first, err := d.ScanReader(strings.NewReader("-----BEGIN RSA PRIVATE KEY-----"), ctx, sc)
		require.NoError(t, err)
		assert.Empty(t, first)

		second, err := d.ScanReader(strings.NewReader("MIIBOgIBAAJBAKj34GkxFhD90vcNLYLInFEX6Ppy1tPf9Cnzj4p4WGeKLs1Pt8Qu"), ctx, sc)
		require.NoError(t, err)
		assert.Empty(t, second, "a pending finding must not survive into the next file")
	})
}

func TestContinuationRegistry(t *testing.T) {
	assert.True(t, detect.HasContinuation("pem-body"))
	assert.False(t, detect.HasContinuation("nope"))
	assert.NotEmpty(t, detect.ContinuationNames())
}

func TestNewRejectsUnknownContinuation(t *testing.T) {
	cat, err := rules.Parse([]byte(`version: 1
rules:
  - id: a-rule
    description: A rule
    severity: low
    keywords: [abc]
    regex: 'abc'
    continuation: does-not-exist
    examples:
      positive: ['abc']
      negative: ['xyz']
`))
	require.NoError(t, err)
	_, err = detect.New(cat, detect.DefaultOptions())
	assert.ErrorContains(t, err, "unknown continuation")
}

func TestClassifyPathUsesSegmentsNotSubstrings(t *testing.T) {
	// Directory markers are whole path segments. Substring matching would
	// call "latest/" a test directory and "godoc/" documentation, and would
	// miss a leading "test/" for want of a leading slash.
	testish := []string{
		"test/images/porter/localhost.key",
		"pkg/webhook/testcerts/certs.go",
		"a/b/testdata/fixture.json",
		"src/__tests__/auth.js",
		"e2e/login.go",
	}
	for _, p := range testish {
		assert.Truef(t, detect.ClassifyPath(p).IsTest, "%s should be a test path", p)
	}

	notTestish := []string{
		"latest/config.yaml",
		"contest/entry.go",
		"internal/attestation/verify.go",
	}
	for _, p := range notTestish {
		assert.Falsef(t, detect.ClassifyPath(p).IsTest, "%s is not a test path", p)
	}

	assert.True(t, detect.ClassifyPath("docs/api.md").IsDoc)
	assert.True(t, detect.ClassifyPath("doc/architecture.txt").IsDoc)
	assert.False(t, detect.ClassifyPath("godocs/api.go").IsDoc)
	assert.True(t, detect.ClassifyPath("examples/main.go").IsExample)
	assert.False(t, detect.ClassifyPath("counterexamples/main.go").IsExample)
	assert.True(t, detect.ClassifyPath("web/dist/app.js").IsMinified)
	assert.False(t, detect.ClassifyPath("redistribute/app.js").IsMinified)
}
