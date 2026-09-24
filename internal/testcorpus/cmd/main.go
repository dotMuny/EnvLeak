// Command mkcorpus regenerates testdata/repo so a human can poke at the
// synthetic repository the history tests use. The tests build their own copy
// in a temporary directory; this is purely for inspection.
package main

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/dotMuny/EnvLeak/internal/testcorpus"
)

func main() {
	dir := "testdata/repo"
	if len(os.Args) > 1 {
		dir = os.Args[1]
	}
	if err := clear(dir); err != nil {
		fmt.Fprintf(os.Stderr, "mkcorpus: %v\n", err)
		os.Exit(1)
	}
	if _, err := testcorpus.Build(dir); err != nil {
		fmt.Fprintf(os.Stderr, "mkcorpus: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("built synthetic corpus at %s\n", dir)
}

// clear removes a previously generated corpus. This tool takes a path from
// argv and then deletes it recursively, so it refuses anything that is not a
// relative path inside the working tree, and anything that is not either
// absent or an existing corpus (recognised by its .git directory).
func clear(dir string) error {
	if filepath.IsAbs(dir) {
		return fmt.Errorf("refusing to delete an absolute path %q; pass a path relative to the repository", dir)
	}
	clean := filepath.Clean(dir)
	if clean == "." || strings.HasPrefix(clean, "..") {
		return fmt.Errorf("refusing to delete %q", dir)
	}
	info, err := os.Stat(clean)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("stat %s: %w", clean, err)
	}
	if !info.IsDir() {
		return fmt.Errorf("%s is not a directory", clean)
	}
	if _, err := os.Stat(filepath.Join(clean, ".git")); err != nil {
		return fmt.Errorf("%s does not look like a generated corpus (no .git); refusing to delete it", clean)
	}
	return os.RemoveAll(clean) //nolint:gosec // guarded above
}
