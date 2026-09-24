// Package gitscan walks Git history with go-git and reports secrets found in
// any blob that ever existed in the repository, together with whether that
// secret is still reachable from HEAD.
//
// That distinction is the whole point of the command: a secret deleted in a
// later commit is still compromised, because anybody who cloned the repository
// still has it. A scan that only looks at the working tree gives a false sense
// of safety.
package gitscan

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/go-git/go-git/v5/plumbing/storer"

	"github.com/dotMuny/EnvLeak/internal/detect"
)

// Options configures a history scan.
type Options struct {
	// Since limits the walk to commits at or after this time. Zero means no
	// limit.
	Since time.Time
	// SinceCommit stops the walk once this commit is reached (exclusive).
	SinceCommit string
	// MaxBlobSize skips blobs larger than this many bytes.
	MaxBlobSize int64
	// AllRefs walks every branch and tag rather than just HEAD.
	AllRefs bool
	// SkipPath is the allowlist check, applied to the path a blob was seen at.
	SkipPath func(path string) bool
	// MaxCommits caps the walk; 0 means unlimited.
	MaxCommits int
}

// Stats describes what the history walk covered.
type Stats struct {
	Commits      int64
	Blobs        int64
	BlobsScanned int64
	Refs         int64
}

// Scanner scans a repository's history.
type Scanner struct {
	repo *git.Repository
	det  *detect.Detector
	opts Options
}

// Open opens the repository at path (searching parent directories, like git
// itself does) and returns a history Scanner.
func Open(path string, det *detect.Detector, opts Options) (*Scanner, error) {
	if det == nil {
		return nil, errors.New("gitscan: nil detector")
	}
	repo, err := git.PlainOpenWithOptions(path, &git.PlainOpenOptions{DetectDotGit: true})
	if err != nil {
		return nil, fmt.Errorf("open git repository at %s: %w", path, err)
	}
	if opts.MaxBlobSize <= 0 {
		opts.MaxBlobSize = 1 << 20
	}
	return &Scanner{repo: repo, det: det, opts: opts}, nil
}

// blobSite records where and when a blob first appeared in the traversal.
type blobSite struct {
	path   string
	commit *object.Commit
}

// Run walks the history and returns every finding.
//
// The walk is blob-centric rather than diff-centric: we collect the set of
// (blob, path) pairs introduced by each commit, keep the earliest commit that
// introduced each blob, and then scan each distinct blob exactly once. A file
// that survives ten thousand commits unchanged is therefore read once, not ten
// thousand times, which is what makes the command usable on a real repository.
func (s *Scanner) Run(ctx context.Context) ([]detect.Finding, Stats, error) {
	var stats Stats

	commits, err := s.collectCommits(ctx, &stats)
	if err != nil {
		return nil, stats, err
	}

	sites, err := s.collectBlobs(ctx, commits, &stats)
	if err != nil {
		return nil, stats, err
	}

	headHashes, err := s.headSecretHashes(ctx)
	if err != nil {
		return nil, stats, err
	}

	findings, err := s.scanBlobs(ctx, sites, headHashes, &stats)
	if err != nil {
		return nil, stats, err
	}

	sort.SliceStable(findings, func(i, j int) bool {
		if findings[i].Date != findings[j].Date {
			return findings[i].Date > findings[j].Date
		}
		if findings[i].Path != findings[j].Path {
			return findings[i].Path < findings[j].Path
		}
		return findings[i].Line < findings[j].Line
	})
	return findings, stats, nil
}

// collectCommits enumerates the commits to consider, newest first.
func (s *Scanner) collectCommits(ctx context.Context, stats *Stats) ([]*object.Commit, error) {
	seen := make(map[plumbing.Hash]bool)
	var out []*object.Commit

	starts, err := s.startPoints(stats)
	if err != nil {
		return nil, err
	}

	stop := plumbing.ZeroHash
	if s.opts.SinceCommit != "" {
		h, resolveErr := s.repo.ResolveRevision(plumbing.Revision(s.opts.SinceCommit))
		if resolveErr != nil {
			return nil, fmt.Errorf("resolve --since %q: %w", s.opts.SinceCommit, resolveErr)
		}
		stop = *h
	}

	for _, start := range starts {
		iter, logErr := s.repo.Log(&git.LogOptions{From: start, Order: git.LogOrderCommitterTime})
		if logErr != nil {
			return nil, fmt.Errorf("read log from %s: %w", start.String()[:8], logErr)
		}
		err = iter.ForEach(func(c *object.Commit) error {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if c.Hash == stop {
				return storer.ErrStop
			}
			if seen[c.Hash] {
				return nil
			}
			if !s.opts.Since.IsZero() && c.Committer.When.Before(s.opts.Since) {
				return nil
			}
			seen[c.Hash] = true
			out = append(out, c)
			if s.opts.MaxCommits > 0 && len(out) >= s.opts.MaxCommits {
				return storer.ErrStop
			}
			return nil
		})
		iter.Close()
		if err != nil && !errors.Is(err, storer.ErrStop) {
			if ctxErr := ctx.Err(); ctxErr != nil {
				return nil, fmt.Errorf("history scan cancelled: %w", ctxErr)
			}
			return nil, fmt.Errorf("walk commits: %w", err)
		}
	}

	sort.SliceStable(out, func(i, j int) bool {
		return out[i].Committer.When.After(out[j].Committer.When)
	})
	stats.Commits = int64(len(out))
	return out, nil
}

// startPoints returns the commits to start walking from: HEAD, or every ref
// when AllRefs is set.
func (s *Scanner) startPoints(stats *Stats) ([]plumbing.Hash, error) {
	if !s.opts.AllRefs {
		head, err := s.repo.Head()
		if err != nil {
			return nil, fmt.Errorf("resolve HEAD: %w", err)
		}
		stats.Refs = 1
		return []plumbing.Hash{head.Hash()}, nil
	}

	var starts []plumbing.Hash
	seen := map[plumbing.Hash]bool{}
	iter, err := s.repo.References()
	if err != nil {
		return nil, fmt.Errorf("list references: %w", err)
	}
	defer iter.Close()
	err = iter.ForEach(func(ref *plumbing.Reference) error {
		if ref.Type() != plumbing.HashReference {
			return nil
		}
		name := ref.Name()
		if !name.IsBranch() && !name.IsRemote() && !name.IsTag() {
			return nil
		}
		// A tag may point at a tag object rather than a commit.
		h := ref.Hash()
		if tag, tagErr := s.repo.TagObject(h); tagErr == nil {
			h = tag.Target
		}
		if _, cErr := s.repo.CommitObject(h); cErr != nil {
			return nil
		}
		if seen[h] {
			return nil
		}
		seen[h] = true
		stats.Refs++
		starts = append(starts, h)
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("walk references: %w", err)
	}
	if len(starts) == 0 {
		head, headErr := s.repo.Head()
		if headErr != nil {
			return nil, fmt.Errorf("repository has no usable refs: %w", headErr)
		}
		starts = append(starts, head.Hash())
		stats.Refs = 1
	}
	return starts, nil
}

// collectBlobs diffs each commit against its first parent and records the
// earliest commit that introduced each distinct blob.
func (s *Scanner) collectBlobs(ctx context.Context, commits []*object.Commit, stats *Stats) (map[plumbing.Hash]blobSite, error) {
	sites := make(map[plumbing.Hash]blobSite)

	for _, c := range commits {
		if err := ctx.Err(); err != nil {
			return nil, fmt.Errorf("history scan cancelled: %w", err)
		}
		tree, err := c.Tree()
		if err != nil {
			return nil, fmt.Errorf("read tree of %s: %w", c.Hash.String()[:8], err)
		}

		var parentTree *object.Tree
		if c.NumParents() > 0 {
			parent, pErr := c.Parent(0)
			if pErr == nil {
				parentTree, _ = parent.Tree() //nolint:errcheck // a missing parent tree means "diff against empty"
			}
		}

		changes, err := object.DiffTreeWithOptions(ctx, parentTree, tree, object.DefaultDiffTreeOptions)
		if err != nil {
			return nil, fmt.Errorf("diff commit %s: %w", c.Hash.String()[:8], err)
		}

		for _, ch := range changes {
			_, to, err := ch.Files()
			if err != nil || to == nil {
				continue
			}
			path := ch.To.Name
			if path == "" {
				continue
			}
			if s.opts.SkipPath != nil && s.opts.SkipPath(path) {
				continue
			}
			prev, exists := sites[to.Hash]
			if exists && !c.Committer.When.Before(prev.commit.Committer.When) {
				continue
			}
			if !exists {
				stats.Blobs++
			}
			sites[to.Hash] = blobSite{path: path, commit: c}
		}
	}
	return sites, nil
}

// headSecretHashes scans the HEAD tree and returns the set of secret hashes
// still present there. Comparing on the secret's hash rather than on its path
// means a secret that was merely moved to another file is still correctly
// reported as live.
func (s *Scanner) headSecretHashes(ctx context.Context) (map[string]bool, error) {
	out := map[string]bool{}

	head, err := s.repo.Head()
	if err != nil {
		// A repository with no commits has no HEAD; every history finding is
		// then trivially not in HEAD.
		return out, nil //nolint:nilerr // absent HEAD is a valid state, not a failure
	}
	commit, err := s.repo.CommitObject(head.Hash())
	if err != nil {
		return nil, fmt.Errorf("read HEAD commit: %w", err)
	}
	tree, err := commit.Tree()
	if err != nil {
		return nil, fmt.Errorf("read HEAD tree: %w", err)
	}

	sc := detect.NewScratch()
	walker := object.NewTreeWalker(tree, true, nil)
	defer walker.Close()
	for {
		if err := ctx.Err(); err != nil {
			return nil, fmt.Errorf("HEAD scan cancelled: %w", err)
		}
		name, entry, err := walker.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("walk HEAD tree: %w", err)
		}
		if !entry.Mode.IsFile() {
			continue
		}
		blob, err := s.repo.BlobObject(entry.Hash)
		if err != nil || blob.Size > s.opts.MaxBlobSize {
			continue
		}
		findings, err := s.scanBlob(blob, name, sc)
		if err != nil {
			continue
		}
		for _, f := range findings {
			out[f.SecretHash] = true
		}
	}
	return out, nil
}

// scanBlobs runs the detector over every distinct blob and stamps each finding
// with the commit that introduced it.
func (s *Scanner) scanBlobs(ctx context.Context, sites map[plumbing.Hash]blobSite, headHashes map[string]bool, stats *Stats) ([]detect.Finding, error) {
	var out []detect.Finding
	sc := detect.NewScratch()

	hashes := make([]plumbing.Hash, 0, len(sites))
	for h := range sites {
		hashes = append(hashes, h)
	}
	sort.Slice(hashes, func(i, j int) bool { return hashes[i].String() < hashes[j].String() })

	for _, h := range hashes {
		if err := ctx.Err(); err != nil {
			return nil, fmt.Errorf("history scan cancelled: %w", err)
		}
		site := sites[h]
		blob, err := s.repo.BlobObject(h)
		if err != nil {
			continue
		}
		if blob.Size > s.opts.MaxBlobSize {
			continue
		}
		findings, err := s.scanBlob(blob, site.path, sc)
		if err != nil {
			continue
		}
		stats.BlobsScanned++

		c := site.commit
		for i := range findings {
			inHead := headHashes[findings[i].SecretHash]
			findings[i].Commit = c.Hash.String()
			findings[i].Author = c.Author.Name
			findings[i].AuthorEmail = c.Author.Email
			findings[i].Date = c.Author.When.UTC().Format(time.RFC3339)
			findings[i].InHEAD = &inHead
			// Two identical secrets in two historical paths are two separate
			// findings; fold the commit into the fingerprint so a baseline can
			// accept one without accepting the other.
			findings[i].Fingerprint = detect.Fingerprint(
				findings[i].RuleID, site.path+"@"+c.Hash.String()[:12], findings[i].Secret)
		}
		out = append(out, findings...)
	}
	return out, nil
}

func (s *Scanner) scanBlob(blob *object.Blob, path string, sc *detect.Scratch) ([]detect.Finding, error) {
	r, err := blob.Reader()
	if err != nil {
		return nil, fmt.Errorf("read blob %s: %w", blob.Hash.String()[:8], err)
	}
	defer func() { _ = r.Close() }()

	head := make([]byte, 512)
	n, _ := io.ReadFull(r, head) //nolint:errcheck // a short read just means a short file
	head = head[:n]
	if strings.IndexByte(string(head), 0) >= 0 {
		return nil, nil
	}

	ctx := detect.ClassifyPath(path)
	if detect.LooksGenerated(string(head)) {
		ctx.IsGenerated = true
	}
	full := io.MultiReader(strings.NewReader(string(head)), r)
	return s.det.ScanReader(full, ctx, sc)
}

// Repository exposes the opened repository, for commands that need it.
func (s *Scanner) Repository() *git.Repository { return s.repo }
