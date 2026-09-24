package cli

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/dotMuny/EnvLeak/internal/allowlist"
	"github.com/dotMuny/EnvLeak/internal/buildinfo"
	"github.com/dotMuny/EnvLeak/internal/detect"
	"github.com/dotMuny/EnvLeak/internal/gitscan"
	"github.com/dotMuny/EnvLeak/internal/scan"
)

func newBaselineCommand(streams IO, g *globalFlags) *cobra.Command {
	var (
		out         string
		withHistory bool
	)

	cmd := &cobra.Command{
		Use:   "baseline [path]",
		Short: "Record the current findings so later runs only report new ones",
		Long: `Scan [path] and write every current finding's fingerprint to a baseline file.

This is how you adopt envleak in a repository that already has findings: take
a snapshot, commit it, and from then on the tool reports only what is new. The
baseline stores fingerprints and redacted values, never the secrets
themselves, so it is safe to commit.

Rotating a leaked credential is still the right thing to do. A baseline is a
way to stop the bleeding, not a way to declare the wound healed.`,
		Example: `  envleak baseline
  envleak baseline --with-history -o .envleak-baseline.json`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			target := "."
			if len(args) == 1 {
				target = args[0]
			}
			return runBaseline(cmd.Context(), streams, g, target, out, withHistory)
		},
	}

	cmd.Flags().StringVarP(&out, "out", "O", allowlist.DefaultBaselineFile, "where to write the baseline")
	cmd.Flags().BoolVar(&withHistory, "with-history", false, "also baseline findings from the Git history")
	return cmd
}

func runBaseline(ctx context.Context, streams IO, g *globalFlags, target, out string, withHistory bool) error {
	if ctx == nil {
		ctx = context.Background()
	}
	// A baseline must record what is there now, not what is left after the
	// previous baseline filtered it out.
	g.noBaseline = true

	rc, err := g.resolve(target, streams)
	if err != nil {
		return err
	}

	scanner, err := scan.New(rc.detector, scan.Options{
		Root:             target,
		Concurrency:      rc.concurrency,
		MaxFileSize:      rc.maxFileSize,
		RespectGitignore: true,
		SkipPath:         rc.allow.SkipPath,
	})
	if err != nil {
		return err
	}
	findings, _, err := scanner.Run(ctx)
	if err != nil {
		return err
	}

	if withHistory {
		hs, hErr := gitscan.Open(target, rc.detector, gitscan.Options{
			AllRefs:     true,
			MaxBlobSize: rc.maxFileSize,
			SkipPath:    rc.allow.SkipPath,
		})
		if hErr != nil {
			return hErr
		}
		histFindings, _, hErr := hs.Run(ctx)
		if hErr != nil {
			return hErr
		}
		findings = append(findings, histFindings...)
	}

	findings = rc.allow.Filter(findings)
	base := allowlist.NewBaseline(findings, buildinfo.String())
	base.SecretHashes = collectSecretHashes(findings)

	path := out
	if !filepath.IsAbs(path) {
		path = filepath.Join(target, path)
	}
	f, err := os.Create(path) //nolint:gosec // path comes from the user's own --out
	if err != nil {
		return fmt.Errorf("create baseline %s: %w", path, err)
	}
	defer func() { _ = f.Close() }()

	if err := allowlist.WriteBaseline(f, base); err != nil {
		return err
	}
	_, err = fmt.Fprintf(streams.Err, "wrote %d fingerprint(s) to %s\n", len(base.Fingerprints), path)
	if err != nil {
		return fmt.Errorf("write summary: %w", err)
	}
	return nil
}

func collectSecretHashes(findings []detect.Finding) []string {
	seen := map[string]bool{}
	var out []string
	for _, f := range findings {
		if seen[f.SecretHash] {
			continue
		}
		seen[f.SecretHash] = true
		out = append(out, f.SecretHash)
	}
	return out
}
