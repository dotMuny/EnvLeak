// Package config loads .envleak.yml — the per-repository tuning file that
// holds the allowlist, the entropy thresholds and the scan limits.
package config

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/dotMuny/EnvLeak/internal/allowlist"
	"github.com/dotMuny/EnvLeak/internal/detect"
)

// DefaultFile is the config file envleak looks for at the scan root.
const DefaultFile = ".envleak.yml"

// AltFile is also accepted, because half the ecosystem spells it ".yaml".
const AltFile = ".envleak.yaml"

// Config is the parsed .envleak.yml.
type Config struct {
	Version int `yaml:"version"`

	// MaxFileSize accepts either a number of bytes or a human size ("2MB").
	MaxFileSize   Size   `yaml:"max_file_size"`
	Concurrency   int    `yaml:"concurrency"`
	FailOn        string `yaml:"fail_on"`
	MinConfidence string `yaml:"min_confidence"`

	Entropy EntropyConfig `yaml:"entropy"`

	Allowlist AllowlistConfig `yaml:"allowlist"`

	// ExtraRules points at additional YAML rule files merged into the
	// embedded catalogue.
	ExtraRules []string `yaml:"extra_rules"`

	// Baseline is the default baseline path for this repository.
	Baseline string `yaml:"baseline"`

	// path records where the config was loaded from, for error messages.
	path string
}

// EntropyConfig mirrors detect.EntropyConfig in YAML form.
type EntropyConfig struct {
	Enabled    *bool    `yaml:"enabled"`
	Base64     *float64 `yaml:"base64"`
	Hex        *float64 `yaml:"hex"`
	MinLength  *int     `yaml:"min_length"`
	Contextual *bool    `yaml:"contextual"`
}

// AllowlistConfig is the YAML shape of allowlist.Config.
type AllowlistConfig struct {
	Paths        []string `yaml:"paths"`
	PathRegexes  []string `yaml:"path_regexes"`
	Rules        []string `yaml:"rules"`
	Regexes      []string `yaml:"regexes"`
	Fingerprints []string `yaml:"fingerprints"`
}

// Size is a byte count that accepts "512KB", "2MB", "1048576".
type Size int64

// UnmarshalYAML implements yaml.Unmarshaler.
func (s *Size) UnmarshalYAML(node *yaml.Node) error {
	var raw string
	if err := node.Decode(&raw); err != nil {
		var n int64
		if err2 := node.Decode(&n); err2 != nil {
			return fmt.Errorf("max_file_size: want a number or a size like \"2MB\": %w", err)
		}
		*s = Size(n)
		return nil
	}
	n, err := ParseSize(raw)
	if err != nil {
		return err
	}
	*s = Size(n)
	return nil
}

// ParseSize converts "2MB" / "512kb" / "1048576" into bytes.
func ParseSize(raw string) (int64, error) {
	t := strings.ToUpper(strings.TrimSpace(raw))
	mult := int64(1)
	switch {
	case strings.HasSuffix(t, "KB"):
		mult, t = 1<<10, strings.TrimSpace(strings.TrimSuffix(t, "KB"))
	case strings.HasSuffix(t, "MB"):
		mult, t = 1<<20, strings.TrimSpace(strings.TrimSuffix(t, "MB"))
	case strings.HasSuffix(t, "GB"):
		mult, t = 1<<30, strings.TrimSpace(strings.TrimSuffix(t, "GB"))
	case strings.HasSuffix(t, "B"):
		t = strings.TrimSpace(strings.TrimSuffix(t, "B"))
	}
	n, err := strconv.ParseInt(t, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("parse size %q: %w", raw, err)
	}
	return n * mult, nil
}

// Default returns the configuration used when no file is present.
func Default() *Config {
	return &Config{
		Version:       1,
		MaxFileSize:   Size(1 << 20),
		FailOn:        "medium",
		MinConfidence: "low",
	}
}

// Load reads .envleak.yml (or .envleak.yaml) from dir. A missing file yields
// the defaults, because envleak has to work in a repository that has never
// heard of it.
func Load(dir string) (*Config, error) {
	for _, name := range []string{DefaultFile, AltFile} {
		p := filepath.Join(dir, name)
		data, err := os.ReadFile(p) //nolint:gosec // dir is the user's scan root
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", p, err)
		}
		cfg, err := Parse(data)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", p, err)
		}
		cfg.path = p
		return cfg, nil
	}
	return Default(), nil
}

// LoadFile reads a config from an explicit path. Unlike Load, a missing file
// here is an error: the user asked for it by name.
func LoadFile(path string) (*Config, error) {
	data, err := os.ReadFile(path) //nolint:gosec // path comes from --config
	if err != nil {
		return nil, fmt.Errorf("read config %s: %w", path, err)
	}
	cfg, err := Parse(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	cfg.path = path
	return cfg, nil
}

// Parse decodes a config from YAML, rejecting unknown keys so a typo in
// .envleak.yml fails loudly instead of silently disabling a filter.
func Parse(data []byte) (*Config, error) {
	cfg := Default()
	dec := yaml.NewDecoder(strings.NewReader(string(data)))
	dec.KnownFields(true)
	if err := dec.Decode(cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	if cfg.MaxFileSize <= 0 {
		cfg.MaxFileSize = Default().MaxFileSize
	}
	if cfg.FailOn == "" {
		cfg.FailOn = Default().FailOn
	}
	if cfg.MinConfidence == "" {
		cfg.MinConfidence = Default().MinConfidence
	}
	return cfg, nil
}

// Path reports where the config came from, or "" for defaults.
func (c *Config) Path() string { return c.path }

// ToAllowlistConfig converts to the allowlist package's shape.
func (c *Config) ToAllowlistConfig() allowlist.Config {
	return allowlist.Config{
		Paths:        c.Allowlist.Paths,
		PathRegexes:  c.Allowlist.PathRegexes,
		Rules:        c.Allowlist.Rules,
		Regexes:      c.Allowlist.Regexes,
		Fingerprints: c.Allowlist.Fingerprints,
	}
}

// ApplyEntropy overlays the configured entropy settings on top of the
// defaults, leaving unset fields alone.
func (c *Config) ApplyEntropy(base detect.EntropyConfig) detect.EntropyConfig {
	if c.Entropy.Base64 != nil {
		base.Base64Threshold = *c.Entropy.Base64
	}
	if c.Entropy.Hex != nil {
		base.HexThreshold = *c.Entropy.Hex
	}
	if c.Entropy.MinLength != nil {
		base.MinLength = *c.Entropy.MinLength
	}
	if c.Entropy.Contextual != nil {
		base.Contextual = *c.Entropy.Contextual
	}
	return base
}

// EntropyEnabled reports whether the standalone entropy engine should run.
func (c *Config) EntropyEnabled(def bool) bool {
	if c.Entropy.Enabled != nil {
		return *c.Entropy.Enabled
	}
	return def
}
