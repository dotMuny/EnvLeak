// Package cli wires the cobra command tree. It is the only package allowed to
// know about flags, stdout and process exit codes.
package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"

	"github.com/dotMuny/EnvLeak/internal/buildinfo"
)

// Exit codes, as documented in the README.
const (
	ExitClean    = 0 // no findings above the threshold
	ExitFindings = 1 // findings above --fail-on
	ExitError    = 2 // envleak itself failed
)

// ErrFindings signals "we found something", as distinct from "we broke".
var ErrFindings = errors.New("secrets found above the configured threshold")

// IO bundles the streams a command writes to, so tests can capture them.
type IO struct {
	In  io.Reader
	Out io.Writer
	Err io.Writer
}

// StdIO returns the process streams.
func StdIO() IO { return IO{In: os.Stdin, Out: os.Stdout, Err: os.Stderr} }

// NewRootCommand builds the whole command tree.
func NewRootCommand(streams IO) *cobra.Command {
	g := &globalFlags{}

	root := &cobra.Command{
		Use:   "envleak",
		Short: "Find leaked secrets in a Git repository's working tree and history",
		Long: `envleak scans a repository for leaked credentials.

It combines three detection engines — a catalogue of provider-specific
patterns, a Shannon-entropy detector for generic high-entropy strings, and
checksum validators for formats that carry one — and reports each finding with
a confidence level derived from which engines agreed.

Exit codes:
  0  no findings at or above --fail-on
  1  findings at or above --fail-on
  2  envleak failed to run`,
		SilenceUsage:  true,
		SilenceErrors: true,
		Version:       buildinfo.Version,
	}
	root.SetIn(streams.In)
	root.SetOut(streams.Out)
	root.SetErr(streams.Err)
	root.SetVersionTemplate(buildinfo.String() + "\n")

	g.register(root.PersistentFlags())

	root.AddCommand(
		newScanCommand(streams, g),
		newHistoryCommand(streams, g),
		newBaselineCommand(streams, g),
		newRulesCommand(streams, g),
		newInstallHookCommand(streams),
		newVersionCommand(streams),
	)
	return root
}

// Execute runs the CLI with a background context and returns the exit code.
func Execute(streams IO) int {
	return ExecuteContext(context.Background(), NewRootCommand(streams), streams)
}

// ExecuteContext runs a command tree and maps the result onto an exit code.
// Findings are not an error condition for the operator — they are the point of
// the tool — so they get their own code rather than an error message.
func ExecuteContext(ctx context.Context, root *cobra.Command, streams IO) int {
	err := root.ExecuteContext(ctx)
	switch {
	case err == nil:
		return ExitClean
	case errors.Is(err, ErrFindings):
		return ExitFindings
	default:
		// Writing the error is best-effort: if stderr is gone there is
		// nothing useful left to do but return the exit code.
		_, _ = fmt.Fprintf(streams.Err, "envleak: %v\n", err)
		return ExitError
	}
}

func newVersionCommand(streams IO) *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the version and build metadata",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			_, err := fmt.Fprintln(streams.Out, buildinfo.String())
			return err
		},
	}
}
