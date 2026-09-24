package config_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dotMuny/EnvLeak/internal/config"
	"github.com/dotMuny/EnvLeak/internal/detect"
)

func TestParseSize(t *testing.T) {
	cases := map[string]int64{
		"1024":   1024,
		"1KB":    1 << 10,
		"512kb":  512 << 10,
		"2MB":    2 << 20,
		" 3 GB ": 3 << 30,
		"900B":   900,
	}
	for in, want := range cases {
		got, err := config.ParseSize(in)
		require.NoErrorf(t, err, in)
		assert.Equalf(t, want, got, in)
	}
	_, err := config.ParseSize("huge")
	assert.Error(t, err)
}

func TestParseFullConfig(t *testing.T) {
	cfg, err := config.Parse([]byte(`
version: 1
max_file_size: 4MB
concurrency: 3
fail_on: high
min_confidence: medium
baseline: .baseline.json
extra_rules:
  - rules/company.yaml
entropy:
  enabled: true
  base64: 4.8
  hex: 3.4
  min_length: 24
  contextual: false
allowlist:
  paths:
    - vendor/**
  path_regexes:
    - '^generated/'
  rules:
    - jwt
  regexes:
    - 'EXAMPLE'
  fingerprints:
    - deadbeefdeadbeefdeadbeef
`))
	require.NoError(t, err)

	assert.Equal(t, config.Size(4<<20), cfg.MaxFileSize)
	assert.Equal(t, 3, cfg.Concurrency)
	assert.Equal(t, "high", cfg.FailOn)
	assert.Equal(t, "medium", cfg.MinConfidence)
	assert.Equal(t, []string{"rules/company.yaml"}, cfg.ExtraRules)

	e := cfg.ApplyEntropy(detect.DefaultEntropyConfig())
	assert.Equal(t, 4.8, e.Base64Threshold)
	assert.Equal(t, 3.4, e.HexThreshold)
	assert.Equal(t, 24, e.MinLength)
	assert.False(t, e.Contextual)
	assert.True(t, cfg.EntropyEnabled(false))

	al := cfg.ToAllowlistConfig()
	assert.Equal(t, []string{"vendor/**"}, al.Paths)
	assert.Equal(t, []string{"jwt"}, al.Rules)
	assert.Equal(t, []string{"deadbeefdeadbeefdeadbeef"}, al.Fingerprints)
}

func TestParseRejectsUnknownKeys(t *testing.T) {
	// A typo in .envleak.yml silently disabling a filter is exactly the sort
	// of failure a security tool must not have.
	_, err := config.Parse([]byte("version: 1\nallowlist:\n  pathz: [vendor]\n"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "parse config")
}

func TestDefaultsWhenFieldsAreAbsent(t *testing.T) {
	cfg, err := config.Parse([]byte("version: 1\n"))
	require.NoError(t, err)
	assert.Equal(t, config.Size(1<<20), cfg.MaxFileSize)
	assert.Equal(t, "medium", cfg.FailOn)
	assert.Equal(t, "low", cfg.MinConfidence)

	base := detect.DefaultEntropyConfig()
	assert.Equal(t, base, cfg.ApplyEntropy(base), "an absent entropy block changes nothing")
	assert.True(t, cfg.EntropyEnabled(true))
	assert.False(t, cfg.EntropyEnabled(false))
}

func TestSizeAcceptsBareNumber(t *testing.T) {
	cfg, err := config.Parse([]byte("max_file_size: 2048\n"))
	require.NoError(t, err)
	assert.Equal(t, config.Size(2048), cfg.MaxFileSize)

	_, err = config.Parse([]byte("max_file_size: [1,2]\n"))
	assert.Error(t, err)
}

func TestLoadFindsBothSpellings(t *testing.T) {
	for _, name := range []string{".envleak.yml", ".envleak.yaml"} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			require.NoError(t, os.WriteFile(filepath.Join(dir, name),
				[]byte("version: 1\nfail_on: critical\n"), 0o600))

			cfg, err := config.Load(dir)
			require.NoError(t, err)
			assert.Equal(t, "critical", cfg.FailOn)
			assert.Equal(t, filepath.Join(dir, name), cfg.Path())
		})
	}
}

func TestLoadWithoutConfigReturnsDefaults(t *testing.T) {
	cfg, err := config.Load(t.TempDir())
	require.NoError(t, err)
	assert.Equal(t, "medium", cfg.FailOn)
	assert.Empty(t, cfg.Path())
}

func TestLoadFileRequiresTheFile(t *testing.T) {
	_, err := config.LoadFile(filepath.Join(t.TempDir(), "nope.yml"))
	assert.ErrorContains(t, err, "read config")

	dir := t.TempDir()
	p := filepath.Join(dir, "c.yml")
	require.NoError(t, os.WriteFile(p, []byte("fail_on: low\n"), 0o600))
	cfg, err := config.LoadFile(p)
	require.NoError(t, err)
	assert.Equal(t, "low", cfg.FailOn)
}

func TestExampleConfigInRepoIsValid(t *testing.T) {
	// The .envleak.yml shipped at the repository root doubles as the
	// documented example; it must actually parse.
	data, err := os.ReadFile(filepath.Join("..", "..", ".envleak.yml"))
	require.NoError(t, err)
	_, err = config.Parse(data)
	assert.NoError(t, err)
}
