# Contributing

## Getting set up

```bash
git clone https://github.com/dotMuny/EnvLeak && cd EnvLeak
make build test lint
```

You need Go 1.22 or later. `make lint` needs
[golangci-lint](https://golangci-lint.run) v2; `make demo` needs Python 3.
Nothing else — the tests build their own Git repositories with go-git, so you do
not need the `git` binary to run them.

## Adding a detection rule

This is the most common contribution and the most valuable one. See
[the README](README.md#adding-a-rule) for the YAML shape. Three things are
enforced and none of them are optional:

1. **Positive and negative examples.** They *are* the tests — `TestRuleExamples`
   runs every one through the real detector. A rule without them does not parse.
2. **Keywords that occur in your positive examples.** The Aho-Corasick prefilter
   only runs your regex on lines containing a keyword, so a keyword that never
   appears means a rule that never fires. A test checks this.
3. **`make docs`.** `docs/rules.md` is generated from the catalogue and CI fails
   if it is stale.

Use a real-looking but synthetic value in your examples. Never a real
credential, not even an expired one, not even your own. If you need a token that
passes a checksum validator, generate it — see `detect.GitHubChecksum`.

### Picking severity and confidence

`severity` is how bad this class of leak is: `critical` for anything granting
write access to production, `low` for test-mode keys and public identifiers.

`confidence` is what a *bare* pattern match is worth, before entropy and
validators have their say. A prefix-anchored format that cannot be anything else
(`ghp_`, `sk_live_`, `AKIA`) earns `high`. A rule that depends on a nearby
keyword or matches a common shape earns `medium` or `low`, and should carry an
`entropy_threshold` so the entropy engine can promote it.

## Changing false-positive behaviour

`internal/falsepositive` is a ratchet. `testdata/clean` must produce **zero**
findings at every confidence level.

* **Lowering a budget** because your change removed noise: welcome, do it in the
  same commit.
* **Raising a budget**: needs a reason in the commit message and a reviewer who
  agrees the trade is worth it.
* **Adding a fixture** to `testdata/clean`: welcome. If it produces a finding,
  that finding is a bug — fix the filter, do not weaken the corpus.

If you are fixing a false positive, add the offending shape to
`testdata/clean` first and watch the test fail. That way the fix is pinned.

## Code shape

* `internal/detect` must not import anything that touches the filesystem or Git.
  It takes `(content, Context)` and returns findings. That constraint is what
  keeps the detection tests fast and hermetic.
* Formatters decide *how* something is printed, never *what* is reported.
* Wrap errors with context: `fmt.Errorf("read %s: %w", path, err)`.
* No `panic` outside `main` and outside genuine programmer errors in code that
  cannot recover (the keyword automaton's state ceiling is the only one today).
* Comments explain *why*. The code already says what.

## Before opening a pull request

```bash
make fmt test lint docs
```

CI additionally runs the race detector, a short fuzzing pass on the rule parser
and the entropy engine, a Docker build, and envleak against its own working tree
and history. Coverage across `internal/` must stay above 80%.

## Reporting a vulnerability

Open a
[security advisory](https://github.com/dotMuny/EnvLeak/security/advisories/new),
not a public issue.
