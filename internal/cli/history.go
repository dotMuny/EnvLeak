package cli

import (
	"context"
	"time"

	"github.com/spf13/cobra"

	"github.com/dotMuny/EnvLeak/internal/buildinfo"
	"github.com/dotMuny/EnvLeak/internal/gitscan"
	"github.com/dotMuny/EnvLeak/internal/report"
)

func newHistoryCommand(streams IO, g *globalFlags) *cobra.Command {
	var (
		since      string
		allRefs    bool
		maxCommits int
		onlyLive   bool
	)

	cmd := &cobra.Command{
		Use:   "history [path]",
		Short: "Scan the whole Git history for secrets that were ever committed",
		Long: `Walk the repository's commits and report secrets found in any blob that has
ever existed, along with whether each secret is still reachable from HEAD.

Deleting a secret in a later commit does not un-leak it: anybody who cloned the
repository before the deletion still has it, and so does every fork and every
CI cache. A finding marked "removed from HEAD" therefore still needs the
credential rotated — it only means you will not find it by grepping the
checkout.`,
		Example: `  envleak history
  envleak history --all-refs --since 2024-01-01
  envleak history --since v1.2.0 --format sarif -o history.sarif`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			target := "."
			if len(args) == 1 {
				target = args[0]
			}
			return runHistory(cmd.Context(), streams, g, target, historyFlags{
				since:      since,
				allRefs:    allRefs,
				maxCommits: maxCommits,
				onlyLive:   onlyLive,
			})
		},
	}

	cmd.Flags().StringVar(&since, "since", "",
		"only walk commits after this point: a date (2024-01-31, RFC3339) or a revision (a tag, branch or commit)")
	cmd.Flags().BoolVar(&allRefs, "all-refs", true, "walk every branch and tag, not just HEAD")
	cmd.Flags().IntVar(&maxCommits, "max-commits", 0, "stop after this many commits (0 = no limit)")
	cmd.Flags().BoolVar(&onlyLive, "only-in-head", false, "report only secrets that are still present in HEAD")
	return cmd
}

type historyFlags struct {
	since      string
	allRefs    bool
	maxCommits int
	onlyLive   bool
}

func runHistory(ctx context.Context, streams IO, g *globalFlags, target string, hf historyFlags) error {
	if ctx == nil {
		ctx = context.Background()
	}
	start := time.Now()

	rc, err := g.resolve(target, streams)
	if err != nil {
		return err
	}

	opts := gitscan.Options{
		AllRefs:     hf.allRefs,
		MaxBlobSize: rc.maxFileSize,
		MaxCommits:  hf.maxCommits,
		SkipPath:    rc.allow.SkipPath,
	}
	if hf.since != "" {
		if when, ok := parseSinceDate(hf.since); ok {
			opts.Since = when
		} else {
			opts.SinceCommit = hf.since
		}
	}

	scanner, err := gitscan.Open(target, rc.detector, opts)
	if err != nil {
		return err
	}

	findings, stats, err := scanner.Run(ctx)
	if err != nil {
		return err
	}

	if hf.onlyLive {
		kept := findings[:0:0]
		for _, f := range findings {
			if f.InHEAD != nil && *f.InHEAD {
				kept = append(kept, f)
			}
		}
		findings = kept
	}

	return emit(streams, g, rc, report.Report{
		Root:            target,
		Mode:            "history",
		DurationSeconds: time.Since(start).Seconds(),
		CommitsScanned:  stats.Commits,
		FilesScanned:    stats.BlobsScanned,
		ToolVersion:     buildinfo.Version,
	}, findings)
}

// sinceLayouts are the date formats --since accepts before falling back to
// treating the argument as a git revision.
var sinceLayouts = []string{
	time.RFC3339,
	"2006-01-02T15:04:05",
	"2006-01-02 15:04:05",
	"2006-01-02",
	"2006/01/02",
}

func parseSinceDate(s string) (time.Time, bool) {
	for _, layout := range sinceLayouts {
		if t, err := time.Parse(layout, s); err == nil {
			return t, true
		}
	}
	if d, err := time.ParseDuration(s); err == nil && d > 0 {
		return time.Now().Add(-d), true
	}
	return time.Time{}, false
}
