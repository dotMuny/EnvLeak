package scan

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/go-git/go-git/v5/plumbing/format/gitignore"
)

// alwaysSkipDirs are never worth walking. .git in particular would otherwise
// double the work of every scan by re-reading every object as a loose file.
var alwaysSkipDirs = map[string]bool{
	".git": true, ".hg": true, ".svn": true, ".bzr": true,
}

// walker enumerates the candidate files under a root, honouring .gitignore.
type walker struct {
	root     string
	matcher  gitignore.Matcher
	skipPath func(rel string) bool
	hidden   bool
}

// loadIgnorePatterns collects .gitignore patterns from the root downwards plus
// the repository's .git/info/exclude, using go-git's gitignore implementation
// so that our idea of "ignored" matches git's exactly.
func loadIgnorePatterns(root string) ([]gitignore.Pattern, error) {
	var patterns []gitignore.Pattern

	fsys := os.DirFS(root)
	err := fs.WalkDir(fsys, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil //nolint:nilerr // an unreadable directory is skipped, not fatal
		}
		if d.IsDir() {
			if alwaysSkipDirs[d.Name()] && p != "." {
				return fs.SkipDir
			}
			return nil
		}
		if d.Name() != ".gitignore" {
			return nil
		}
		data, readErr := os.ReadFile(filepath.Join(root, filepath.FromSlash(p))) //nolint:gosec // inside the scan root
		if readErr != nil {
			return nil //nolint:nilerr // an unreadable .gitignore just means no extra patterns
		}
		var domain []string
		if dir := filepath.ToSlash(filepath.Dir(p)); dir != "." {
			domain = strings.Split(dir, "/")
		}
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			patterns = append(patterns, gitignore.ParsePattern(line, domain))
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("collect .gitignore files under %s: %w", root, err)
	}

	excludePath := filepath.Join(root, ".git", "info", "exclude")
	if data, readErr := os.ReadFile(excludePath); readErr == nil { //nolint:gosec // a fixed path inside the scan root
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			patterns = append(patterns, gitignore.ParsePattern(line, nil))
		}
	}
	return patterns, nil
}

// walk streams repo-relative paths to emit. It returns the first hard error it
// meets; unreadable individual entries are skipped.
func (w *walker) walk(emit func(rel string) error) error {
	return filepath.WalkDir(w.root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			if d != nil && d.IsDir() {
				return fs.SkipDir
			}
			return nil //nolint:nilerr // skip entries we cannot stat
		}
		rel, relErr := filepath.Rel(w.root, path)
		if relErr != nil {
			return nil //nolint:nilerr // outside the root; cannot happen via WalkDir
		}
		rel = filepath.ToSlash(rel)
		if rel == "." {
			return nil
		}
		name := d.Name()

		if d.IsDir() {
			if alwaysSkipDirs[name] {
				return fs.SkipDir
			}
			if !w.hidden && strings.HasPrefix(name, ".") {
				return fs.SkipDir
			}
			if w.matcher != nil && w.matcher.Match(strings.Split(rel, "/"), true) {
				return fs.SkipDir
			}
			if w.skipPath != nil && w.skipPath(rel+"/") {
				return fs.SkipDir
			}
			return nil
		}

		if !d.Type().IsRegular() {
			// Symlinks are skipped: following them risks walking out of the
			// repository and scanning the same content twice.
			return nil
		}
		if !w.hidden && strings.HasPrefix(name, ".") && !isInterestingDotfile(name) {
			return nil
		}
		if w.matcher != nil && w.matcher.Match(strings.Split(rel, "/"), false) {
			return nil
		}
		if w.skipPath != nil && w.skipPath(rel) {
			return nil
		}
		return emit(rel)
	})
}

// isInterestingDotfile keeps the dotfiles that are the single most common
// place to leak a secret, even when hidden files are otherwise skipped.
func isInterestingDotfile(name string) bool {
	lower := strings.ToLower(name)
	switch {
	case strings.HasPrefix(lower, ".env"):
		return true
	case lower == ".npmrc", lower == ".pypirc", lower == ".netrc", lower == ".dockercfg":
		return true
	case lower == ".htpasswd", lower == ".pgpass", lower == ".my.cnf":
		return true
	}
	return false
}
