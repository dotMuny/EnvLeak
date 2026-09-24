package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/pflag"

	"github.com/dotMuny/EnvLeak/internal/allowlist"
	"github.com/dotMuny/EnvLeak/internal/config"
	"github.com/dotMuny/EnvLeak/internal/detect"
	"github.com/dotMuny/EnvLeak/internal/report"
	"github.com/dotMuny/EnvLeak/internal/rules"
)

// globalFlags are the flags shared by scan and history.
type globalFlags struct {
	configPath    string
	format        string
	output        string
	failOn        string
	minConfidence string
	showSecrets   bool
	noColor       bool
	verbose       bool
	quiet         bool
	concurrency   int
	maxFileSize   string
	baseline      string
	noBaseline    bool
	includeRules  []string
	excludeRules  []string
	noEntropy     bool
	entropyAll    bool
}

func (g *globalFlags) register(fs *pflag.FlagSet) {
	fs.StringVarP(&g.configPath, "config", "c", "", "path to .envleak.yml (default: found at the scan root)")
	fs.StringVarP(&g.format, "format", "f", "text", "output format: "+strings.Join(report.Formats(), "|"))
	fs.StringVarP(&g.output, "output", "o", "-", "write the report to this file (\"-\" for stdout)")
	fs.StringVar(&g.failOn, "fail-on", "", "exit 1 when a finding is at least this severe: critical|high|medium|low|none (default medium)")
	fs.StringVar(&g.minConfidence, "min-confidence", "", "drop findings below this confidence: high|medium|low (default low)")
	fs.BoolVar(&g.showSecrets, "show-secrets", false,
		"print raw secret values instead of redacted ones (DANGEROUS: the output usually ends up in CI logs, which are retained and often world-readable)")
	fs.BoolVar(&g.noColor, "no-color", false, "disable ANSI colour in text output")
	fs.BoolVarP(&g.verbose, "verbose", "v", false, "explain why each finding got its confidence level")
	fs.BoolVarP(&g.quiet, "quiet", "q", false, "suppress the progress and summary lines on stderr")
	fs.IntVar(&g.concurrency, "concurrency", 0, "number of worker goroutines (default: one per CPU)")
	fs.StringVar(&g.maxFileSize, "max-file-size", "", "skip files larger than this, e.g. 2MB (default 1MB)")
	fs.StringVar(&g.baseline, "baseline", "", "baseline file of accepted findings (default: "+allowlist.DefaultBaselineFile+" if present)")
	fs.BoolVar(&g.noBaseline, "no-baseline", false, "ignore any baseline file")
	fs.StringSliceVar(&g.includeRules, "rule", nil, "only run these rule ids (repeatable)")
	fs.StringSliceVar(&g.excludeRules, "exclude-rule", nil, "skip these rule ids (repeatable)")
	fs.BoolVar(&g.noEntropy, "no-entropy", false, "disable the standalone high-entropy detector")
	fs.BoolVar(&g.entropyAll, "entropy-all", false, "run the entropy detector on every line, not only lines mentioning a secret-ish word")
}

// runtimeConfig is everything the flags plus .envleak.yml resolve to.
type runtimeConfig struct {
	cfg           *config.Config
	catalogue     *rules.Catalogue
	detector      *detect.Detector
	allow         *allowlist.Allowlist
	format        report.Format
	reportOptions report.Options
	failOn        int // rules.Severity rank; 0 disables failing
	minConfidence int
	maxFileSize   int64
	concurrency   int
	baselinePath  string
}

// resolve merges defaults, the config file and the command line, in that
// order of increasing precedence.
func (g *globalFlags) resolve(root string, streams IO) (*runtimeConfig, error) {
	cfg, err := g.loadConfig(root)
	if err != nil {
		return nil, err
	}

	format, err := report.ParseFormat(g.format)
	if err != nil {
		return nil, err
	}

	failOn, err := parseFailOn(pick(g.failOn, cfg.FailOn))
	if err != nil {
		return nil, err
	}
	minConf, err := parseMinConfidence(pick(g.minConfidence, cfg.MinConfidence))
	if err != nil {
		return nil, err
	}

	maxSize := int64(cfg.MaxFileSize)
	if g.maxFileSize != "" {
		maxSize, err = config.ParseSize(g.maxFileSize)
		if err != nil {
			return nil, err
		}
	}

	cat, err := g.buildCatalogue(cfg, root)
	if err != nil {
		return nil, err
	}

	allowCfg := cfg.ToAllowlistConfig()
	allow, err := allowlist.New(allowCfg)
	if err != nil {
		return nil, err
	}

	baselinePath, err := g.resolveBaseline(root, cfg, allow)
	if err != nil {
		return nil, err
	}

	entropyCfg := cfg.ApplyEntropy(detect.DefaultEntropyConfig())
	if g.entropyAll {
		entropyCfg.Contextual = false
	}

	opts := detect.DefaultOptions()
	opts.Entropy = entropyCfg
	opts.EntropyEngine = cfg.EntropyEnabled(true) && !g.noEntropy
	opts.Suppressor = allow

	det, err := detect.New(cat, opts)
	if err != nil {
		return nil, err
	}

	concurrency := g.concurrency
	if concurrency == 0 {
		concurrency = cfg.Concurrency
	}

	return &runtimeConfig{
		cfg:       cfg,
		catalogue: cat,
		detector:  det,
		allow:     allow,
		format:    format,
		reportOptions: report.Options{
			ShowSecrets: g.showSecrets,
			Color:       g.useColor(streams),
			Verbose:     g.verbose,
		},
		failOn:        failOn,
		minConfidence: minConf,
		maxFileSize:   maxSize,
		concurrency:   concurrency,
		baselinePath:  baselinePath,
	}, nil
}

func (g *globalFlags) loadConfig(root string) (*config.Config, error) {
	if g.configPath != "" {
		return config.LoadFile(g.configPath)
	}
	return config.Load(root)
}

func (g *globalFlags) buildCatalogue(cfg *config.Config, root string) (*rules.Catalogue, error) {
	cat, err := rules.Default()
	if err != nil {
		return nil, err
	}
	for _, extra := range cfg.ExtraRules {
		p := extra
		if !filepath.IsAbs(p) {
			p = filepath.Join(root, p)
		}
		data, readErr := os.ReadFile(p) //nolint:gosec // path comes from the user's own config
		if readErr != nil {
			return nil, fmt.Errorf("read extra_rules %s: %w", p, readErr)
		}
		extraCat, parseErr := rules.Parse(data)
		if parseErr != nil {
			return nil, fmt.Errorf("extra_rules %s: %w", p, parseErr)
		}
		cat, err = rules.Merge(cat, extraCat)
		if err != nil {
			return nil, err
		}
	}

	include := toSet(g.includeRules)
	exclude := toSet(g.excludeRules)
	for _, id := range cfg.Allowlist.Rules {
		exclude[strings.TrimSpace(id)] = true
	}
	if len(include) == 0 && len(exclude) == 0 {
		return cat, nil
	}
	for id := range include {
		if _, ok := cat.Get(id); !ok {
			return nil, fmt.Errorf("--rule %q: no such rule (see `envleak rules`)", id)
		}
	}
	return cat.Filter(func(r rules.Compiled) bool {
		if len(include) > 0 && !include[r.ID] {
			return false
		}
		return !exclude[r.ID]
	}), nil
}

func (g *globalFlags) resolveBaseline(root string, cfg *config.Config, allow *allowlist.Allowlist) (string, error) {
	if g.noBaseline {
		return "", nil
	}
	path := g.baseline
	if path == "" {
		path = cfg.Baseline
	}
	explicit := path != ""
	if path == "" {
		path = filepath.Join(root, allowlist.DefaultBaselineFile)
	} else if !filepath.IsAbs(path) {
		path = filepath.Join(root, path)
	}

	b, err := allowlist.LoadBaseline(path)
	if err != nil {
		return "", err
	}
	if b == nil {
		if explicit {
			return "", fmt.Errorf("baseline %s does not exist (run `envleak baseline` first)", path)
		}
		return "", nil
	}
	allow.AddBaseline(b)
	return path, nil
}

// useColor decides whether to emit ANSI escapes: only for the text format, on
// a terminal, and never when NO_COLOR is set.
func (g *globalFlags) useColor(streams IO) bool {
	if g.noColor || g.format != string(report.FormatText) || g.output != "-" {
		return false
	}
	if _, set := os.LookupEnv("NO_COLOR"); set {
		return false
	}
	f, ok := streams.Out.(*os.File)
	if !ok {
		return false
	}
	info, err := f.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}

func parseFailOn(s string) (int, error) {
	if strings.EqualFold(s, "none") || s == "" {
		return 0, nil
	}
	sev, err := rules.ParseSeverity(s)
	if err != nil {
		return 0, fmt.Errorf("--fail-on: %w", err)
	}
	return sev.Rank(), nil
}

func parseMinConfidence(s string) (int, error) {
	if s == "" {
		return detect.ConfidenceLow.Rank(), nil
	}
	c, ok := detect.ParseConfidence(s)
	if !ok {
		return 0, fmt.Errorf("--min-confidence: unknown confidence %q (want high|medium|low)", s)
	}
	return c.Rank(), nil
}

func pick(override, fallback string) string {
	if override != "" {
		return override
	}
	return fallback
}

func toSet(in []string) map[string]bool {
	out := make(map[string]bool, len(in))
	for _, s := range in {
		if s = strings.TrimSpace(s); s != "" {
			out[s] = true
		}
	}
	return out
}
