package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	"github.com/dotMuny/EnvLeak/internal/buildinfo"
	"github.com/dotMuny/EnvLeak/internal/detect"
	"github.com/dotMuny/EnvLeak/internal/gitscan"
	"github.com/dotMuny/EnvLeak/internal/report"
	"github.com/dotMuny/EnvLeak/internal/scan"
)

func newScanCommand(streams IO, g *globalFlags) *cobra.Command {
	var (
		staged        bool
		noGitignore   bool
		includeHidden bool
	)

	cmd := &cobra.Command{
		Use:   "scan [path]",
		Short: "Scan a working tree (or stdin) for secrets",
		Long: `Scan the working tree at [path] (default ".").

Files ignored by .gitignore are skipped, as are binaries, symlinks and files
above --max-file-size. Pass "-" as the path to read from standard input, which
is what makes envleak usable inside a pipeline.`,
		Example: `  envleak scan
  envleak scan ./services/api --format sarif -o envleak.sarif
  envleak scan --staged --fail-on high
  cat .env | envleak scan -`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			target := "."
			if len(args) == 1 {
				target = args[0]
			}
			return runScan(cmd.Context(), streams, g, target, scanFlags{
				staged:        staged,
				noGitignore:   noGitignore,
				includeHidden: includeHidden,
			})
		},
	}

	cmd.Flags().BoolVar(&staged, "staged", false, "only scan files staged in the Git index (for pre-commit hooks)")
	cmd.Flags().BoolVar(&noGitignore, "no-gitignore", false, "do not honour .gitignore")
	cmd.Flags().BoolVar(&includeHidden, "hidden", false, "walk hidden directories too")
	return cmd
}

type scanFlags struct {
	staged        bool
	noGitignore   bool
	includeHidden bool
}

func runScan(ctx context.Context, streams IO, g *globalFlags, target string, sf scanFlags) error {
	if ctx == nil {
		ctx = context.Background()
	}
	start := time.Now()

	if target == "-" {
		return runStdin(ctx, streams, g, start)
	}

	root := target
	var restrict []string
	if sf.staged {
		wtRoot, staged, err := gitscan.StagedFiles(target)
		if err != nil {
			return err
		}
		root, restrict = wtRoot, staged
		if len(restrict) == 0 {
			// Nothing staged: emit an empty report rather than scanning the
			// whole tree, which would make the hook unbearably slow.
			return emit(streams, g, nil, report.Report{
				Root: root, Mode: "staged", ToolVersion: buildinfo.Version,
				DurationSeconds: time.Since(start).Seconds(),
			}, nil)
		}
	}

	rc, err := g.resolve(root, streams)
	if err != nil {
		return err
	}

	scanner, err := scan.New(rc.detector, scan.Options{
		Root:             root,
		Concurrency:      rc.concurrency,
		MaxFileSize:      rc.maxFileSize,
		RespectGitignore: !sf.noGitignore,
		IncludeHidden:    sf.includeHidden,
		SkipPath:         rc.allow.SkipPath,
		Paths:            restrict,
	})
	if err != nil {
		return err
	}

	findings, stats, err := scanner.Run(ctx)
	if err != nil {
		return err
	}

	mode := "worktree"
	if sf.staged {
		mode = "staged"
	}
	absRoot, _ := filepath.Abs(root) //nolint:errcheck // a relative root is still a usable label
	return emit(streams, g, rc, report.Report{
		Root:            absRoot,
		Mode:            mode,
		DurationSeconds: time.Since(start).Seconds(),
		FilesScanned:    stats.FilesScanned,
		ToolVersion:     buildinfo.Version,
	}, findings)
}

func runStdin(ctx context.Context, streams IO, g *globalFlags, start time.Time) error {
	_ = ctx
	cwd, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("resolve working directory: %w", err)
	}
	rc, err := g.resolve(cwd, streams)
	if err != nil {
		return err
	}
	findings, err := scan.Stdin(rc.detector, streams.In, "<stdin>")
	if err != nil {
		return err
	}
	return emit(streams, g, rc, report.Report{
		Root:            cwd,
		Mode:            "stdin",
		DurationSeconds: time.Since(start).Seconds(),
		FilesScanned:    1,
		ToolVersion:     buildinfo.Version,
	}, findings)
}

// emit applies the allowlist and confidence filters, writes the report, and
// decides the exit status.
func emit(streams IO, g *globalFlags, rc *runtimeConfig, rep report.Report, findings []detect.Finding) error {
	format := report.FormatText
	opts := report.Options{}
	minConfidence := detect.ConfidenceLow.Rank()
	failOn := 0

	if rc != nil {
		findings = rc.allow.Filter(findings)
		format = rc.format
		opts = rc.reportOptions
		minConfidence = rc.minConfidence
		failOn = rc.failOn
	}

	kept := findings[:0:0]
	for _, f := range findings {
		if f.Confidence.Rank() < minConfidence {
			continue
		}
		kept = append(kept, f)
	}
	scan.SortFindings(kept)
	rep.Findings = kept

	w, closeFn, err := openOutput(streams, g.output)
	if err != nil {
		return err
	}
	defer closeFn()

	formatter, err := report.New(format)
	if err != nil {
		return err
	}
	if err := formatter.Format(w, rep, opts); err != nil {
		return err
	}

	if failOn == 0 {
		return nil
	}
	for _, f := range kept {
		if f.Severity.Rank() >= failOn {
			return ErrFindings
		}
	}
	return nil
}

func openOutput(streams IO, path string) (io.Writer, func(), error) {
	if path == "" || path == "-" {
		return streams.Out, func() {}, nil
	}
	f, err := os.Create(path) //nolint:gosec // path comes from the user's own --output
	if err != nil {
		return nil, nil, fmt.Errorf("create output file %s: %w", path, err)
	}
	return f, func() { _ = f.Close() }, nil
}
