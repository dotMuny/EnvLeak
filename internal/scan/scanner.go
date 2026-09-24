package scan

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/go-git/go-git/v5/plumbing/format/gitignore"

	"github.com/dotMuny/EnvLeak/internal/detect"
)

// Options configures a working-tree scan.
type Options struct {
	// Root is the directory to scan.
	Root string
	// Concurrency is the number of worker goroutines; <= 0 means NumCPU.
	Concurrency int
	// MaxFileSize skips files larger than this many bytes. Secrets are short;
	// a 40 MB file is a database dump or a vendored blob.
	MaxFileSize int64
	// RespectGitignore honours .gitignore files under Root.
	RespectGitignore bool
	// IncludeHidden walks dot-directories too.
	IncludeHidden bool
	// SkipPath is consulted before a file is opened (the allowlist).
	SkipPath func(rel string) bool
	// Paths, when non-empty, restricts the scan to these repo-relative paths
	// and skips the walk entirely. --staged uses it.
	Paths []string
}

// Stats records what a scan actually did, so --stats and the benchmark can
// report something more useful than a wall-clock number.
type Stats struct {
	FilesWalked    int64
	FilesScanned   int64
	FilesSkipped   int64
	SkippedBinary  int64
	SkippedTooBig  int64
	SkippedIgnored int64
	BytesScanned   int64
}

// Scanner walks a tree and runs a Detector over every eligible file.
type Scanner struct {
	det  *detect.Detector
	opts Options
}

// New builds a Scanner.
func New(det *detect.Detector, opts Options) (*Scanner, error) {
	if det == nil {
		return nil, errors.New("scan: nil detector")
	}
	if opts.Root == "" {
		opts.Root = "."
	}
	abs, err := filepath.Abs(opts.Root)
	if err != nil {
		return nil, fmt.Errorf("resolve scan root %q: %w", opts.Root, err)
	}
	opts.Root = abs
	if opts.Concurrency <= 0 {
		opts.Concurrency = runtime.NumCPU()
	}
	if opts.MaxFileSize <= 0 {
		opts.MaxFileSize = 1 << 20
	}
	return &Scanner{det: det, opts: opts}, nil
}

// Run scans the tree and returns every finding, sorted by path and line.
//
// The pipeline is one producer (the directory walk, which is IO-bound and
// inherently sequential) feeding a buffered channel drained by
// Options.Concurrency workers. Each worker owns a detect.Scratch, so the hot
// path allocates nothing per line.
func (s *Scanner) Run(ctx context.Context) ([]detect.Finding, Stats, error) {
	var stats Stats

	paths := make(chan string, s.opts.Concurrency*64)
	results := make(chan []detect.Finding, s.opts.Concurrency)

	var wg sync.WaitGroup
	for i := 0; i < s.opts.Concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sc := detect.NewScratch()
			for rel := range paths {
				fs, err := s.scanFile(rel, sc, &stats)
				if err != nil || len(fs) == 0 {
					continue
				}
				select {
				case results <- fs:
				case <-ctx.Done():
					return
				}
			}
		}()
	}

	collected := make([]detect.Finding, 0, 64)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for fs := range results {
			collected = append(collected, fs...)
		}
	}()

	walkErr := s.produce(ctx, paths, &stats)
	close(paths)
	wg.Wait()
	close(results)
	<-done

	if walkErr != nil {
		return nil, stats, walkErr
	}
	if err := ctx.Err(); err != nil {
		return nil, stats, fmt.Errorf("scan cancelled: %w", err)
	}

	sortFindings(collected)
	return collected, stats, nil
}

func (s *Scanner) produce(ctx context.Context, paths chan<- string, stats *Stats) error {
	emit := func(rel string) error {
		atomic.AddInt64(&stats.FilesWalked, 1)
		select {
		case paths <- rel:
			return nil
		case <-ctx.Done():
			return filepath.SkipAll
		}
	}

	if len(s.opts.Paths) > 0 {
		for _, p := range s.opts.Paths {
			if s.opts.SkipPath != nil && s.opts.SkipPath(p) {
				atomic.AddInt64(&stats.SkippedIgnored, 1)
				continue
			}
			if err := emit(p); err != nil {
				return nil //nolint:nilerr // cancellation is reported by ctx.Err()
			}
		}
		return nil
	}

	w := &walker{root: s.opts.Root, hidden: s.opts.IncludeHidden}
	if s.opts.SkipPath != nil {
		w.skipPath = func(rel string) bool {
			if s.opts.SkipPath(strings.TrimSuffix(rel, "/")) {
				atomic.AddInt64(&stats.SkippedIgnored, 1)
				return true
			}
			return false
		}
	}
	if s.opts.RespectGitignore {
		patterns, err := loadIgnorePatterns(s.opts.Root)
		if err != nil {
			return err
		}
		if len(patterns) > 0 {
			w.matcher = gitignore.NewMatcher(patterns)
		}
	}
	if err := w.walk(emit); err != nil && !errors.Is(err, filepath.SkipAll) {
		return fmt.Errorf("walk %s: %w", s.opts.Root, err)
	}
	return nil
}

// scanFile applies the size, binary and generated-header filters, then streams
// the file through the detector.
func (s *Scanner) scanFile(rel string, sc *detect.Scratch, stats *Stats) ([]detect.Finding, error) {
	abs := filepath.Join(s.opts.Root, filepath.FromSlash(rel))

	info, err := os.Lstat(abs)
	if err != nil {
		atomic.AddInt64(&stats.FilesSkipped, 1)
		return nil, err
	}
	if info.Size() > s.opts.MaxFileSize {
		atomic.AddInt64(&stats.SkippedTooBig, 1)
		atomic.AddInt64(&stats.FilesSkipped, 1)
		return nil, nil
	}

	f, head, r, err := openFile(abs)
	if err != nil {
		atomic.AddInt64(&stats.FilesSkipped, 1)
		return nil, err
	}
	defer func() { _ = f.Close() }()

	if IsBinary(head) {
		atomic.AddInt64(&stats.SkippedBinary, 1)
		atomic.AddInt64(&stats.FilesSkipped, 1)
		return nil, nil
	}

	fctx := detect.ClassifyPath(rel)
	if !fctx.IsGenerated && detect.LooksGenerated(firstLines(head, 3)) {
		fctx.IsGenerated = true
	}

	atomic.AddInt64(&stats.FilesScanned, 1)
	atomic.AddInt64(&stats.BytesScanned, info.Size())

	findings, err := s.det.ScanReader(r, fctx, sc)
	if err != nil {
		return findings, err
	}
	return findings, nil
}

// firstLines returns at most n lines from the head of a buffer.
func firstLines(head []byte, n int) string {
	br := bufio.NewReader(strings.NewReader(string(head)))
	var b strings.Builder
	for i := 0; i < n; i++ {
		line, err := br.ReadString('\n')
		b.WriteString(line)
		if err != nil {
			break
		}
	}
	return b.String()
}

// Stdin runs the detector over standard input, for `envleak scan -`.
func Stdin(det *detect.Detector, r io.Reader, name string) ([]detect.Finding, error) {
	ctx := detect.ClassifyPath(name)
	findings, err := det.ScanReader(r, ctx, detect.NewScratch())
	if err != nil {
		return nil, fmt.Errorf("scan stdin: %w", err)
	}
	sortFindings(findings)
	return findings, nil
}

func sortFindings(f []detect.Finding) {
	sort.SliceStable(f, func(i, j int) bool {
		if f[i].Path != f[j].Path {
			return f[i].Path < f[j].Path
		}
		if f[i].Line != f[j].Line {
			return f[i].Line < f[j].Line
		}
		if f[i].StartCol != f[j].StartCol {
			return f[i].StartCol < f[j].StartCol
		}
		return f[i].RuleID < f[j].RuleID
	})
}

// SortFindings orders findings deterministically for reporting.
func SortFindings(f []detect.Finding) { sortFindings(f) }
