// Package testcorpus builds the synthetic Git repository the history tests
// run against.
//
// It is written in Go with go-git rather than as a shell script for two
// reasons: a nested .git directory cannot be committed to the parent
// repository, and the tests then need neither bash nor the git binary. The
// commits carry fixed timestamps, so the corpus is byte-for-byte reproducible.
//
// Every credential below is synthetic. The GitHub tokens are generated with
// envleak's own base62 CRC32 routine so the checksum validator has something
// real to verify; they were never valid.
package testcorpus

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
)

// Planted describes a secret deliberately committed to the corpus, and what
// the history scanner is expected to say about it.
type Planted struct {
	RuleID string
	// Commit is the message of the commit that introduced it.
	Commit string
	Path   string
	// InHEAD is whether the secret should still be reachable from HEAD.
	InHEAD bool
}

// Expected lists every planted secret and its expected verdict. The history
// test asserts this exactly, which is what makes acceptance criterion 2
// checkable rather than a matter of opinion.
func Expected() []Planted {
	return []Planted{
		{RuleID: "aws-access-key-id", Commit: "add deploy script", Path: "src/deploy.sh", InHEAD: false},
		{RuleID: "aws-secret-access-key", Commit: "add deploy script", Path: "src/deploy.sh", InHEAD: false},
		{RuleID: "github-pat-classic", Commit: "wire up CI", Path: ".github-token", InHEAD: false},
		{RuleID: "private-key-rsa", Commit: "add service key", Path: "config/service.pem", InHEAD: true},
		{RuleID: "stripe-live-secret-key", Commit: "production environment file", Path: ".env.production", InHEAD: true},
		{RuleID: "postgres-connection-uri", Commit: "production environment file", Path: ".env.production", InHEAD: true},
	}
}

type step struct {
	message string
	when    time.Time
	branch  string
	files   map[string]string
	deletes []string
}

func at(s string) time.Time {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		panic("testcorpus: bad timestamp " + s) // a literal in this file; a typo is a build bug
	}
	return t
}

// steps is the corpus script: each entry becomes one commit.
func steps() []step {
	return []step{
		{
			message: "initial commit",
			when:    at("2024-01-05T09:00:00Z"),
			files: map[string]string{
				"README.md": "# corpus\n\nConfigure it with:\n\n" +
					"    export SERVICE_API_TOKEN=your-api-key-here\n",
				"src/app.py": "import os\n\nTOKEN = os.environ[\"SERVICE_API_TOKEN\"]\n",
			},
		},
		{
			message: "add deploy script",
			when:    at("2024-02-11T14:22:00Z"),
			files: map[string]string{
				"src/deploy.sh": "#!/bin/sh\n" +
					"export AWS_ACCESS_KEY_ID=AKIA2E0A8F3B244C9986\n" +
					"export AWS_SECRET_ACCESS_KEY=kQ7vTz2mR9dXpL4wNbGs8yJhCe5AuiZr3VoFxMt1\n" +
					"aws s3 sync ./dist s3://corpus-artifacts\n",
			},
		},
		{
			// The AWS credentials disappear from the tree here, but they are
			// still in the history — and therefore still compromised.
			message: "read AWS credentials from the environment",
			when:    at("2024-02-12T08:05:00Z"),
			files: map[string]string{
				"src/deploy.sh": "#!/bin/sh\naws s3 sync ./dist s3://corpus-artifacts\n",
			},
		},
		{
			// A token that only ever existed on a side branch: it is invisible
			// to anything that walks HEAD alone.
			message: "wire up CI",
			when:    at("2024-03-02T11:40:00Z"),
			branch:  "feature/ci",
			files: map[string]string{
				".github-token": "GITHUB_TOKEN=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\n",
			},
		},
		{
			message: "add service key",
			when:    at("2024-04-18T16:10:00Z"),
			branch:  "main",
			files: map[string]string{
				"config/service.pem": "-----BEGIN RSA PRIVATE KEY-----\n" +
					"MIIBOgIBAAJBAKj34GkxFhD90vcNLYLInFEX6Ppy1tPf9Cnzj4p4WGeKLs1Pt8Qu\n" +
					"KUpRKfFLfRYC9AIKjbJTWit+CqvjWYzvQwECAwEAAQJAIJLixBy2qpFoS4DSmoEm\n" +
					"o3qGy0t6z09AIJtH+5OeRV1be+N4cDYJKffGzDa88vQENZiRm0GRq6a+HPGQMd2k\n" +
					"-----END RSA PRIVATE KEY-----\n",
			},
		},
		{
			message: "production environment file",
			when:    at("2024-05-30T10:00:00Z"),
			files: map[string]string{
				".env.production": "STRIPE_SECRET_KEY=sk_live_kR7mQz2XvNb8LcYt4WpJd6Sg\n" +
					"DATABASE_URL=postgres://app:kR7mQz2XvNb8@db.internal:5432/prod\n",
				"docs/configuration.md": "# Configuration\n\n" +
					"| Variable | Example |\n|---|---|\n" +
					"| `STRIPE_SECRET_KEY` | `sk_live_xxxxxxxxxxxxxxxxxxxxxxxx` |\n" +
					"| `AWS_ACCESS_KEY_ID` | `AKIAIOSFODNN7EXAMPLE` |\n" +
					"| `DATABASE_URL` | `postgres://user:${DB_PASSWORD}@localhost/db` |\n",
			},
		},
		{
			// Suppressed inline: the scanner must stay quiet about this one.
			message: "test fixtures",
			when:    at("2024-06-14T12:30:00Z"),
			files: map[string]string{
				"src/fixtures.go": "package src\n\n" +
					"const testToken = \"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\" // envleak:ignore\n",
			},
		},
	}
}

// Build creates the synthetic repository at dir, which must not already exist.
func Build(dir string) (*git.Repository, error) {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, fmt.Errorf("create corpus dir %s: %w", dir, err)
	}
	repo, err := git.PlainInit(dir, false)
	if err != nil {
		return nil, fmt.Errorf("init corpus repository: %w", err)
	}
	// go-git defaults to refs/heads/master; pin main so the corpus matches
	// what a repository created today looks like.
	if err := repo.Storer.SetReference(
		plumbing.NewSymbolicReference(plumbing.HEAD, plumbing.NewBranchReferenceName("main")),
	); err != nil {
		return nil, fmt.Errorf("set HEAD to main: %w", err)
	}

	wt, err := repo.Worktree()
	if err != nil {
		return nil, fmt.Errorf("open corpus worktree: %w", err)
	}

	current := "main"
	for _, s := range steps() {
		if s.branch != "" && s.branch != current {
			if err := checkout(wt, s.branch); err != nil {
				return nil, err
			}
			current = s.branch
		}
		for path, content := range s.files {
			abs := filepath.Join(dir, filepath.FromSlash(path))
			if err := os.MkdirAll(filepath.Dir(abs), 0o750); err != nil {
				return nil, fmt.Errorf("create %s: %w", filepath.Dir(abs), err)
			}
			if err := os.WriteFile(abs, []byte(content), 0o600); err != nil {
				return nil, fmt.Errorf("write %s: %w", abs, err)
			}
		}
		for _, path := range s.deletes {
			if err := os.Remove(filepath.Join(dir, filepath.FromSlash(path))); err != nil {
				return nil, fmt.Errorf("remove %s: %w", path, err)
			}
		}
		if err := wt.AddGlob("."); err != nil {
			return nil, fmt.Errorf("stage files for %q: %w", s.message, err)
		}
		sig := &object.Signature{Name: "envleak corpus", Email: "corpus@envleak.test", When: s.when}
		if _, err := wt.Commit(s.message, &git.CommitOptions{Author: sig, Committer: sig}); err != nil {
			return nil, fmt.Errorf("commit %q: %w", s.message, err)
		}
	}

	if current != "main" {
		if err := checkout(wt, "main"); err != nil {
			return nil, err
		}
	}
	return repo, nil
}

func checkout(wt *git.Worktree, branch string) error {
	ref := plumbing.NewBranchReferenceName(branch)
	err := wt.Checkout(&git.CheckoutOptions{Branch: ref})
	if err == nil {
		return nil
	}
	if cErr := wt.Checkout(&git.CheckoutOptions{Branch: ref, Create: true}); cErr != nil {
		return fmt.Errorf("checkout %s: %w", branch, cErr)
	}
	return nil
}
