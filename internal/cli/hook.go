package cli

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/go-git/go-git/v5"
)

// hookMarker lets us recognise a hook we wrote, so --force can distinguish
// between overwriting our own hook and clobbering somebody else's.
const hookMarker = "# installed by envleak"

const hookScript = `#!/bin/sh
` + hookMarker + `
# Blocks a commit that would introduce a secret. Remove this file, or run
# "git commit --no-verify", to bypass it.
set -eu

if ! command -v envleak >/dev/null 2>&1; then
  echo "envleak: not on PATH; skipping the pre-commit secret scan" >&2
  exit 0
fi

exec envleak scan --staged --fail-on %s --no-color
`

func newInstallHookCommand(streams IO) *cobra.Command {
	var (
		force  bool
		failOn string
	)

	cmd := &cobra.Command{
		Use:   "install-hook [path]",
		Short: "Install a pre-commit hook that blocks commits containing secrets",
		Long: `Write .git/hooks/pre-commit so that every commit is scanned before it lands.

The hook runs "envleak scan --staged", which only looks at what is actually
being committed, and exits non-zero when it finds something at or above
--fail-on. If envleak is not on PATH the hook exits 0 rather than blocking a
teammate who has not installed it yet.

If you already use the pre-commit framework, add this repository to your
.pre-commit-config.yaml instead; see .pre-commit-hooks.yaml.`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			target := "."
			if len(args) == 1 {
				target = args[0]
			}
			return installHook(streams, target, failOn, force)
		},
	}

	cmd.Flags().BoolVar(&force, "force", false, "overwrite an existing pre-commit hook")
	cmd.Flags().StringVar(&failOn, "fail-on", "medium", "severity at which the hook blocks the commit")
	return cmd
}

func installHook(streams IO, target, failOn string, force bool) error {
	repo, err := git.PlainOpenWithOptions(target, &git.PlainOpenOptions{DetectDotGit: true})
	if err != nil {
		return fmt.Errorf("open git repository at %s: %w", target, err)
	}
	wt, err := repo.Worktree()
	if err != nil {
		return fmt.Errorf("open worktree: %w", err)
	}
	root := wt.Filesystem.Root()

	hooksDir := filepath.Join(root, ".git", "hooks")
	if err := os.MkdirAll(hooksDir, 0o750); err != nil {
		return fmt.Errorf("create %s: %w", hooksDir, err)
	}
	hookPath := filepath.Join(hooksDir, "pre-commit")

	existing, err := os.ReadFile(hookPath) //nolint:gosec // inside the repository we were pointed at
	switch {
	case err == nil && !force && !strings.Contains(string(existing), hookMarker):
		return fmt.Errorf("%s already exists and was not written by envleak; re-run with --force to replace it", hookPath)
	case err != nil && !errors.Is(err, fs.ErrNotExist):
		return fmt.Errorf("read %s: %w", hookPath, err)
	}

	script := fmt.Sprintf(hookScript, failOn)
	if err := os.WriteFile(hookPath, []byte(script), 0o700); err != nil { //nolint:gosec // a hook must be executable
		return fmt.Errorf("write %s: %w", hookPath, err)
	}

	_, err = fmt.Fprintf(streams.Out, "installed pre-commit hook at %s (fail-on=%s)\n", hookPath, failOn)
	if err != nil {
		return fmt.Errorf("write summary: %w", err)
	}
	return nil
}
