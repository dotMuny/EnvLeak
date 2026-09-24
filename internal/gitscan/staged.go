package gitscan

import (
	"fmt"
	"path/filepath"

	"github.com/go-git/go-git/v5"
)

// StagedFiles returns the repo-relative paths of files in the index that
// differ from HEAD — exactly what a pre-commit hook needs to look at.
//
// It also returns the repository's working-tree root, because the paths are
// relative to that rather than to wherever the hook happened to be invoked.
func StagedFiles(path string) (root string, paths []string, err error) {
	repo, err := git.PlainOpenWithOptions(path, &git.PlainOpenOptions{DetectDotGit: true})
	if err != nil {
		return "", nil, fmt.Errorf("open git repository at %s: %w", path, err)
	}
	wt, err := repo.Worktree()
	if err != nil {
		return "", nil, fmt.Errorf("open worktree: %w", err)
	}
	status, err := wt.Status()
	if err != nil {
		return "", nil, fmt.Errorf("read git status: %w", err)
	}

	for file, st := range status {
		switch st.Staging {
		case git.Added, git.Modified, git.Renamed, git.Copied, git.UpdatedButUnmerged:
			paths = append(paths, filepath.ToSlash(file))
		case git.Deleted, git.Unmodified, git.Untracked:
			// Nothing staged to inspect.
		}
	}
	return wt.Filesystem.Root(), paths, nil
}
