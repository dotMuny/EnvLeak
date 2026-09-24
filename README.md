# EnvLeak

**Finds credentials that were committed to a Git repository — in the working tree and in every commit that ever existed — and tells you which ones are still live.**

<p align="center">
  <img src="docs/demo/envleak.svg" alt="EnvLeak scanning a repository and reporting four leaked secrets" width="820">
</p>

<p align="center">
  <a href="#quick-start">Quick start</a> ·
  <a href="#output-formats">Output</a> ·
  <a href="#configuration">Configuration</a> ·
  <a href="#performance">Performance</a> ·
  <a href="#false-positives">False positives</a> ·
  <a href="docs/rules.md">Rules</a> ·
  <a href="#design-decisions">Design decisions</a>
</p>

---

A secret you deleted in a later commit is still compromised. Everyone who cloned
the repository still has it, so does every fork, and so does every CI cache.
`envleak history` is the part that matters: it walks every commit on every
branch and tells you, for each credential it finds, whether it is still in HEAD
or was "removed" years ago and never rotated.

Three engines run together, and each finding says which ones agreed:

| Engine | What it does |
|---|---|
| **Pattern** | 65 rules, nearly all provider-specific — AWS, GitHub, GitLab, Slack, Stripe, Google, OpenAI, Anthropic, Twilio, SendGrid, PEM keys, database URIs, Azure, npm, PyPI, Docker Hub and more. A single Aho-Corasick pass over each line decides which regexes are worth running. |
| **Entropy** | Shannon entropy over base64 and hex candidates, with a separate threshold per alphabet, for secrets that have no fixed format. |
| **Validator** | Checksums and structure, where the format carries one: GitHub's base62 CRC32, fine-grained PAT structure, JWT header decoding. |

The result is a `confidence` field that means something. On a deliberately
adversarial corpus — 16 files, 41 strings that look exactly like credentials and
none that are — EnvLeak reports **zero findings at any confidence level**, and a
test fails the build if that ever regresses.

## Installation

```bash
go install github.com/dotMuny/EnvLeak/cmd/envleak@latest
```

```bash
brew install dotMuny/tap/envleak
```

```bash
docker run --rm -v "$PWD:/repo:ro" ghcr.io/dotmuny/envleak:latest scan /repo
```

Or grab a binary from [Releases](https://github.com/dotMuny/EnvLeak/releases) —
linux, darwin and windows, on amd64 and arm64. Every binary is static: no CGO,
no libc, nothing to install alongside it.

From source:

```bash
git clone https://github.com/dotMuny/EnvLeak && cd EnvLeak && make build
```

## Quick start

```bash
envleak scan                  # the working tree, honouring .gitignore
```

```bash
envleak history --all-refs    # every commit on every branch, with "still in HEAD"
```

```bash
envleak install-hook          # block the next commit that would leak something
```

Exit codes are `0` (nothing at or above `--fail-on`), `1` (found something) and
`2` (envleak itself failed), so `envleak scan && deploy` does the obvious thing.

## Output formats

| `--format` | Shape | Use it for |
|---|---|---|
| `text` *(default)* | Coloured, grouped by file, secrets redacted to `ghp_...uIqi` | Reading it yourself |
| `json` | [JSON Lines](docs/json.md) — one object per finding | `jq`, pipelines, your own tooling |
| `sarif` | SARIF 2.1.0, validated against the official OASIS schema in CI | GitHub Code Scanning, the Security tab |
| `junit` | JUnit XML, one failed test case per finding | Jenkins, GitLab, Bamboo |

Secrets are redacted in every format. `--show-secrets` prints raw values and
warns you, in the help text and again after the report, that CI logs are
retained and often world-readable.

```bash
envleak scan --format sarif -o envleak.sarif
envleak scan --format json | jq -r 'select(.confidence=="high") | "\(.path):\(.line) \(.rule_id)"'
```

## Configuration

`.envleak.yml` at the scan root. Everything in it is optional; envleak works
with no config file at all. The copy in this repository is the documented
example, and a test asserts that it parses, so it cannot go stale.

```yaml
version: 1

max_file_size: 1MB   # secrets are short; a 40 MB file is a dump
concurrency: 0       # 0 = one worker per CPU
fail_on: medium      # exit 1 at this severity: critical|high|medium|low|none
min_confidence: low  # drop findings below this before reporting

entropy:
  enabled: true
  base64: 4.5        # bits per character; see "Design decisions"
  hex: 3.0           # hex carries 4 bits per symbol, so it needs its own bar
  min_length: 20     # shorter strings are sampling noise, not entropy
  contextual: true   # only score lines that mention a secret-ish word

allowlist:
  paths:             # gitignore-style globs; these files are never opened
    - "testdata/**"
    - "**/*_test.go"
    - "**/*.min.js"
  path_regexes: []   # full regexes against the same path
  rules: []          # rule ids to switch off; `envleak rules` lists them
  regexes: []        # regexes against the secret value
  fingerprints: []   # accepted findings, inline

extra_rules: []      # your own YAML rule files, merged over the built-ins
```

### Suppressing a single finding

```go
const testToken = "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" // envleak:ignore
```

```go
// envleak:ignore-rule=aws-access-key-id,stripe-live-secret-key
const fixture = "AKIA2E0A8F3B244C9986"
```

A directive works on its own line or the line above, in any language's comment
syntax — only the directive text is matched, not the comment marker.

### Adopting EnvLeak in a repository that already has findings

```bash
envleak baseline --with-history   # writes .envleak-baseline.json
git add .envleak-baseline.json && git commit -m "Baseline envleak findings"
```

From then on only *new* findings are reported. The baseline stores fingerprints
and redacted values, never secrets, so committing it is safe — a test asserts
that. Fingerprints exclude the line number, so reformatting a file does not
invalidate it.

A baseline stops the bleeding. It is not a substitute for rotating the
credentials it accepted.

## Integration

### GitHub Actions

```yaml
permissions:
  contents: read
  security-events: write

steps:
  - uses: actions/checkout@v4
    with: { fetch-depth: 0 }
  - uses: actions/setup-go@v5
    with: { go-version: "1.23" }
  - uses: dotMuny/EnvLeak@v0.1.0
    with:
      mode: history        # or "scan" for the working tree only
      format: sarif
      fail-on: high
```

The action uploads the SARIF itself, so findings appear in the repository's
Security tab with the file and line highlighted. Inputs: `path`, `mode`,
`format`, `output`, `fail-on`, `min-confidence`, `baseline`, `config`,
`upload-sarif`, `version`, `extra-args`. Outputs: `findings`, `report`.

### pre-commit

```yaml
repos:
  - repo: https://github.com/dotMuny/EnvLeak
    rev: v0.1.0
    hooks:
      - id: envleak
```

Or without the framework: `envleak install-hook` writes `.git/hooks/pre-commit`
directly. The hook exits 0 if EnvLeak is not on PATH, so it never blocks a
colleague who has not installed it.

### Docker

```bash
docker run --rm -v "$PWD:/repo:ro" ghcr.io/dotmuny/envleak:latest history /repo --format sarif
```

Multi-stage build onto `scratch`: no shell, no package manager, runs as uid
65532. Nothing to exploit and nothing to patch.

## Performance

Measured on the Kubernetes repository — **31,416 files, 316 MiB of content** —
on a 4-core AMD Ryzen 7 6800U with 4 GB of RAM, warm page cache, three runs per
configuration.

| `--concurrency` | Median | Range | Speed-up |
|---|---|---|---|
| 1 | **7.00 s** | 6.79–7.14 s | 1.0× |
| 4 | **3.73 s** | 3.64–3.84 s | 1.9× |

Peak resident memory: **32 MB**, flat regardless of repository size.

The goal was the Kubernetes working tree in under 30 seconds on 8 cores. On half
that hardware it takes **3.7 seconds** — about 85 MB of source per second, with
1,072 candidate matches evaluated and 739 findings reported.

Scaling is 1.9x from one worker to four rather than the ideal 4x, because the
walk is IO-bound long before it is CPU-bound: on a warm cache the bottleneck is
`read(2)` and page faults, not regex evaluation. That is the intended shape —
the prefilter exists precisely so that CPU stops being the limit.

Memory stays flat because files are streamed line by line and never loaded
whole — 32 MB is the working set for 316 MiB of input.

The history walk is bounded separately, by deduplicating on blob hash: a file
untouched for ten thousand commits is read once, not ten thousand times.
`envleak history` over [spf13/cobra](https://github.com/spf13/cobra) — 1,118
commits, full clone — takes **2.0 s** and 85 MB.

Reproduce it:

```bash
git clone --depth 1 https://github.com/kubernetes/kubernetes /tmp/k8s
make build && time ./bin/envleak scan /tmp/k8s --format json -o /dev/null --fail-on none
```

`make bench` runs the Go microbenchmarks behind these numbers: the prefilter,
the line scanner and the tree walker.

Two design choices account for most of it:

* **The keyword prefilter.** Before any regex runs, one Aho-Corasick pass over
  the lowercased line reports which of the 65 rules have a keyword present.
  Ordinary source code wakes none of them, which is the common case by a wide
  margin. Without it, every line would be matched against 65 compiled regexes.
* **Skipping what cannot contain a secret.** Binary files (a NUL byte in the
  first 8 KiB, the same heuristic git uses), files above `--max-file-size`,
  symlinks, `.git`, and anything `.gitignore` excludes.

## False positives

This is the part that separates the tool from `grep -E`. Six filters run on
every candidate:

| Filter | What it removes |
|---|---|
| **Placeholders** | `AKIAIOSFODNN7EXAMPLE`, `your-api-key-here`, `<TOKEN>`, `${GITHUB_TOKEN}`, `${{ secrets.X }}`, `{{ .Secret }}`, `$(secure_random 32)`, `` `openssl rand -hex 32` ``, `xxxxxxxx`, `changeme`, screaming-snake env var *names*, `var.db_password`, all-lowercase word identifiers like `discovery-token` |
| **Inline suppressions** | `// envleak:ignore`, optionally scoped to a rule |
| **Allowlist** | Paths, globs, path regexes, value regexes, rule ids |
| **Baseline** | Fingerprints already accepted |
| **File context** | Findings in tests, fixtures, docs, `*.example`, lockfiles, vendored code, minified bundles and generated files drop one confidence level |
| **Continuation checks** | A PEM banner is only a key if the next line is actually key material — a banner quoted in a README is prose |

### Measured rate

`testdata/clean` is built to be adversarial: AWS's own documentation sample,
placeholder tokens for eight providers, CI templates full of
`${{ secrets.* }}`, commit hashes, UUIDs, npm integrity digests, a minified
bundle, base64 image data, Terraform variable references, a bootstrap script
that generates its credentials at runtime. **41 secret-shaped strings, zero real
credentials.**

| Confidence | Findings | Budget |
|---|---|---|
| `high` | **0** | 0 |
| `medium` | **0** | 0 |
| `low` | **0** | 0 |

`internal/falsepositive` enforces those budgets as a build failure, and a second
test fails if the corpus stops being adversarial. Lowering the budget is a
routine improvement; raising it takes a deliberate edit and an explanation.

### On a real repository

The same scan over Kubernetes reports **739 findings**, of which **0 are
high-confidence**. Every `private-key-*` hit — 131 of them, and they are real
embedded PEM keys — lands in a `test/`, `testdata/` or `testcerts/` directory
and is correctly discounted to `medium`. They are still reported, and their
`critical` severity still fails the build at the default `--fail-on medium`;
only the confidence label reflects where they live. The remaining findings are
`low`: generic assignments and entropy hits, which is exactly what those engines
are for.

The honest summary: high confidence means "rotate this now", medium means "look
at it", low means "here is something with entropy, you decide".

## Adding a rule

Rules live in [`internal/rules/rules.yaml`](internal/rules/rules.yaml), embedded
at build time with `go:embed`.

```yaml
  - id: acme-internal-token
    description: ACME internal service token
    severity: critical
    confidence: high
    keywords: [acme_tok_]        # the prefilter; the regex only runs if one is present
    regex: '\b(acme_tok_[A-Za-z0-9]{32})\b'
    secret_group: 1              # 0 = the whole match
    entropy_threshold: 4.0       # optional: entropy must confirm it
    validator: ""                # optional: a checksum check from internal/detect
    tags: [acme, saas]
    examples:
      positive: ['ACME_TOKEN=acme_tok_kR7mQz2XvNb8LcYt4WpJd6SgHa1FuE3Z']
      negative: ['ACME_TOKEN=acme_tok_YOUR_TOKEN_HERE']
```

Then `make test docs`. Three things are enforced:

1. **Examples are mandatory and are the tests.** `TestRuleExamples` runs every
   positive and negative example through the real detector. A rule that does not
   work cannot be merged.
2. **Keywords must occur in the positive examples.** Otherwise the prefilter
   would never reach your regex, and the rule would silently never fire.
3. **`docs/rules.md` is generated** from the same YAML by `envleak rules
   --markdown`, and CI fails if it is out of date.

Regexes are Go [RE2](https://github.com/google/re2/wiki/Syntax): no lookaround,
no backreferences, guaranteed linear time. A repository can add its own rules
without forking, via `extra_rules` in `.envleak.yml`.

The full catalogue, with severities, validators and continuation checks, is in
**[docs/rules.md](docs/rules.md)**.

## Design decisions

The short version. The full log, including what was rejected and why, is in
**[docs/decisions.md](docs/decisions.md)**.

### Why go-git instead of shelling out to `git`

Shelling out would have been thirty lines instead of a package, and it was the
wrong trade. It makes the tool's behaviour depend on a program it does not ship:
the user's git version, their `~/.gitconfig`, their `safe.directory` policy,
their locale, their `core.quotepath` setting. A pre-commit hook that works on
your laptop and fails on a colleague's because their git is three years older is
a support burden with no upside. It also rules out the `scratch` container
image, which has no shell at all, and makes handling filenames containing
newlines roughly impossible.

go-git is the project's largest dependency and it is slower than git on very
large histories. The blob-centric walk is how that cost is paid down: the
history scanner collects the distinct blobs each commit introduces, attributes
each to the earliest commit that introduced it, and scans each blob exactly
once. Kubernetes' history has millions of tree entries and only a fraction as
many distinct blobs.

### Why the keyword prefilter

With 65 rules, the obvious prefilter — loop over rules, `strings.Contains` each
keyword — is around 150 substring searches for every line of every file. That is
the hot loop of the entire program, and most lines are ordinary source code that
matches nothing.

Aho-Corasick replaces it with one O(len(line)) pass that reports which rules
woke up. The automaton is built as a full DFA, so the scan loop never follows a
failure link, and it is immutable after construction, so the worker pool shares
it without locking. Keywords are *mandatory*: a rule without them would silently
undo the prefilter for the whole catalogue, so the parser rejects it.

### How the entropy thresholds were calibrated

Shannon entropy is bits per *symbol*, and the symbol alphabet matters. A
64-character alphabet caps at 6.0 bits; a 16-character one caps at 4.0. A
perfectly random hex string scores about 3.9 and would fail a 4.5 bar forever.
So base64 gets 4.5 and hex gets 3.0, and `Classify` checks hex first, because
every hex string is also a valid base64 string.

The numbers started at the conventional ones and were then checked against the
corpora rather than against intuition. At 4.5/3.0 with the contextual gate on,
`testdata/clean` — commit hashes, UUIDs, npm integrity digests, a minified
bundle, base64 PNG data — produces nothing. Dropping the base64 bar to 4.0 makes
the bundle and the PNG data light up. Raising it to 5.0 loses shorter real keys,
whose entropy is depressed by sampling: a 20-character random base64 string has
only 20 samples to spread across 64 symbols.

The minimum length of 20 matters as much as the threshold. Entropy on a short
string is sampling noise — `ab12cd34` scores 3.0 on eight characters, which
means nothing — so shorter candidates are never scored. Both numbers are
configurable in `.envleak.yml` precisely because they are empirical.

### Why validators fail open

A failed checksum lowers confidence by one level; it never drops the finding.
Provider token formats change without announcement, and the base62 alphabet
GitHub uses is not formally specified anywhere citable. If that assumption is
wrong, failing open costs some precision. Failing closed would silently hide
every GitHub token in the repository — and for a security tool, a false negative
is the worse failure.

### What is deliberately not here

**Validating tokens against provider APIs.** It would be the single biggest
precision win available, and it is not implemented. It would turn local static
analysis into something that makes unsolicited authenticated requests to third
parties using credentials found in somebody else's repository — exfiltrating the
secret to the provider from a shared CI runner, lighting up the victim's audit
log from an unexpected IP, and doing something of dubious legality in several
jurisdictions. If it is ever added it belongs behind an explicit opt-in flag,
off by default. See [docs/decisions.md](docs/decisions.md).

Also out of scope, on purpose: automatic rotation or revocation, a server mode,
a database, and a web UI.

## Dependencies

Five direct, each one load-bearing:

| Module | Why |
|---|---|
| `github.com/go-git/go-git/v5` | Git access without shelling out. Also provides the `gitignore` matcher, so EnvLeak's idea of "ignored" is exactly git's. |
| `github.com/spf13/cobra` (+ `pflag`) | The command tree, flag parsing and shell completion. |
| `gopkg.in/yaml.v3` | The embedded rule catalogue and `.envleak.yml`. |
| `github.com/stretchr/testify` | Test assertions. Test-only. |
| `github.com/santhosh-tekuri/jsonschema/v6` | Validates SARIF output against the official OASIS 2.1.0 schema. Test-only, and the reason the SARIF claim is checkable rather than asserted. |

There is no colour library (four ANSI escapes, written by hand), no SARIF
library (the emitted subset is a few structs, pinned by a schema test), and no
logging framework.

## Development

```bash
make build      # static binary into ./bin
make test       # the full suite
make cover      # coverage report; CI enforces an 80% floor on internal/
make lint       # golangci-lint: errcheck, gosec, govet, staticcheck, revive
make fuzz       # 30s each on the rule parser and the entropy engine
make bench      # prefilter, line scanner and tree walker
make docs       # regenerate docs/rules.md from the catalogue
make demo       # regenerate the demo SVG from a real run
make testdata   # write the synthetic history repo to testdata/repo
```

Current coverage across `internal/` is **89.7%**, every production package above
80%. CI runs build and test on Linux, macOS and Windows, plus the race detector,
fuzzing, lint, a docs-freshness check, a Docker build, and envleak scanning its
own working tree and history.

```
cmd/envleak/            main: signals, wiring, exit codes
internal/rules/         embedded YAML catalogue, parser, Aho-Corasick prefilter
internal/detect/        pattern, entropy and validator engines; confidence aggregation
internal/scan/          tree walker, .gitignore, binary/size filters, worker pool
internal/gitscan/       history walk with go-git, "still in HEAD" detection
internal/allowlist/     allowlist, inline suppressions, baseline
internal/report/        text, json, sarif, junit formatters
internal/config/        .envleak.yml
internal/cli/           cobra command tree
internal/testcorpus/    the synthetic Git repository the history tests use
testdata/clean/         the adversarial false-positive corpus
```

`internal/detect` never touches the filesystem or Git: it takes `(content,
Context)` and returns findings, which is why every detection test runs against a
string. Formatters decide *how* something is printed, never *what* is reported.

## Security

Every credential in this repository — in the rule examples, the corpora and the
tests — is synthetic and was never valid. The GitHub tokens are generated with
EnvLeak's own base62 CRC32 routine so that the checksum validator has something
real to verify.

Found a vulnerability in EnvLeak itself? Open a
[security advisory](https://github.com/dotMuny/EnvLeak/security/advisories/new)
rather than an issue.

## License

MIT. See [LICENSE](LICENSE).
