# Design decisions

Every entry is a choice that had more than one reasonable answer. The rule the
project follows is: pick the simplest thing that works, implement it, and write
down what was rejected and why, so the next person does not have to rediscover
the reasoning.

## Architecture

### go-git instead of shelling out to `git`

**Chosen:** `github.com/go-git/go-git/v5`.
**Rejected:** `exec.Command("git", ...)`, which would have been about thirty
lines instead of a package.

Shelling out makes the binary's behaviour depend on a program it does not ship:
the user's git version, their `~/.gitconfig`, their `core.quotepath` setting,
their locale, their credential helper, their `safe.directory` policy. A
pre-commit hook that works on the maintainer's laptop and fails on a colleague's
because their git is three years older is a support burden the tool does not
need. It also rules out the `scratch` container image, which has no shell at
all, and makes parsing robust against filenames containing newlines
approximately impossible.

The cost is real: go-git is the project's largest dependency, and it is slower
than git for very large histories. The blob-centric walk below is how that cost
is contained.

### Blob-centric history walk instead of per-commit diffs

**Chosen:** collect the set of distinct blobs each commit introduces, attribute
each blob to the earliest commit that introduced it, then scan each blob exactly
once.
**Rejected:** scanning every commit's full diff, or every commit's full tree.

A file that survives ten thousand commits unchanged appears in ten thousand
trees. Scanning trees is O(commits x files); scanning diffs re-reads a file
every time it is touched. Deduplicating by blob hash means the scanner reads
each distinct version of each file once, no matter how long the history is.

The trade-off is that a blob is attributed to one commit, not to all the
branches it appears on. For the question the command answers — "was this
credential ever committed, and by whom" — the first commit is the useful answer.

### "Still in HEAD" is decided by the secret's hash, not by its path

**Chosen:** scan the HEAD tree once, collect the hashes of every secret found
there, and mark a historical finding live if its secret hash is in that set.
**Rejected:** checking whether the file still exists at the same path.

A secret that was moved to a different file is still live. A path check would
report it as removed, which is exactly the wrong answer.

### `internal/detect` does not know what a file is

**Chosen:** the detection engines take `(content, Context)` and return
findings. Path classification happens in `ClassifyPath`, which is a pure string
function; inline suppression reaches the engines through a `Suppressor`
interface that `internal/allowlist` implements.
**Rejected:** passing an `*os.File`, or letting `detect` import `allowlist`.

Every detection test in the project runs against a string. There is no
temporary directory, no fixture tree, no cleanup, and no reason for a detection
test to be slow.

### Formatters build the SARIF rule list from the findings, not from the catalogue

**Chosen:** the SARIF driver's `rules` array is derived from the findings being
reported.
**Rejected:** injecting the rule catalogue into the formatter.

The entropy engine produces findings for `generic-high-entropy`, which has no
catalogue entry because it has no pattern. Deriving the rule list from the
findings means that case needs no special handling, and the driver can never
describe a rule that produced no result or omit one that did.

## Detection

### Aho-Corasick prefilter instead of per-keyword `strings.Contains`

**Chosen:** one automaton over every keyword in the catalogue; a line is walked
once and reports which rules woke up.
**Rejected:** looping over rules and calling `strings.Contains` per keyword.

With 65 rules the naive prefilter is roughly 150 substring searches per line of
every file in the repository. Aho-Corasick is a single O(len(line)) pass. On an
ordinary source line — which wakes no rule at all, the overwhelmingly common
case — this is the difference between the prefilter being free and it being the
program. `BenchmarkPrefilter` measures it.

The automaton is built as a full DFA (every state has a transition for every
byte) so the scan loop never follows a failure link, and it is immutable after
construction so the worker pool can share it without locking.

### Keywords are mandatory

**Chosen:** `rules.Parse` rejects a rule with no keywords.
**Rejected:** letting a keyword-less rule run its regex on every line.

One such rule would silently undo the prefilter for the whole catalogue.
`TestKeywordsAreConsistentWithExamples` goes further and checks that each rule's
keywords actually occur in its own positive examples, so a typo cannot produce a
rule that can never fire.

### Validators fail open

**Chosen:** a failed checksum lowers a finding's confidence by one level.
**Rejected:** dropping the finding.

Provider token formats change without announcement, and the base62 alphabet
GitHub uses for its checksum is not formally specified anywhere the project can
cite. If that assumption is wrong, failing open costs some precision; failing
closed would silently hide every GitHub token in the repository. For a security
tool, a false negative is the worse failure.

This is also why `GitHubChecksum` is exported: the test builds tokens that are
valid by construction, so the round trip is verified even though no real token
can be committed to the repository.

### Two entropy thresholds, not one

**Chosen:** 4.5 bits/char for base64-alphabet strings, 3.0 for hex, minimum
length 20.
**Rejected:** a single threshold.

Shannon entropy is measured in bits *per symbol*, and the symbol alphabet
differs. A 64-character alphabet caps at 6.0; a 16-character one caps at 4.0. A
perfectly random hex string scores about 3.9 and would fail a 4.5 bar forever,
so a single threshold either misses every hex secret or floods on every
identifier. See "Calibration" below for how the numbers were picked.

### The standalone entropy engine is contextual by default

**Chosen:** the generic high-entropy detector only fires on lines that also
mention a secret-ish word, and its findings are `low` confidence and `low`
severity.
**Rejected:** scoring every high-entropy string in the repository.

Without the gate it reports every commit hash, every UUID, every content digest
and every base64 asset — on Kubernetes, thousands of them. `--entropy-all`
turns the gate off for the cases where that is what you want.

### Deduplicating overlapping findings

**Chosen:** when two rules match overlapping spans on the same line, keep one,
preferring (1) a validated finding, (2) a provider-specific rule over a
`generic-` one, (3) higher severity, (4) higher confidence.
**Rejected:** reporting both.

`AWS_SECRET_ACCESS_KEY=...` matches both `aws-secret-access-key` and the
catch-all `generic-env-secret`. Reporting it twice doubles the triage work and
makes the tool look noisier than it is. Validation wins outright because a
checksum that verifies is the strongest identification available: a JWT inside
an `Authorization: Bearer` header is reported as `jwt`, not as the broader
`authorization-bearer-header`.

### Continuation checks for banner-style rules

**Chosen:** a rule may declare a `continuation`; its match is held back one line
and dropped if the following line fails the check. `private-key-*` uses
`pem-body`.
**Rejected:** treating any `-----BEGIN ... PRIVATE KEY-----` as a finding, or
buffering whole files so the detector can look ahead freely.

A PEM banner in a README, in a shell comment, or in an `openssl genrsa` example
is prose. The same banner with base64 on the next line is a leaked key. One line
of lookahead distinguishes them and costs one held finding per scratch buffer;
buffering whole files would have given up the constant-memory streaming
guarantee for a case that only ever needs one line.

### Fingerprints exclude the line number

**Chosen:** `sha256(ruleID || path || secret)`.
**Rejected:** including the line, or hashing the whole line.

Moving code around must not invalidate a baseline. Including the line number
would mean a reformat invalidates every accepted finding in the file, and a
baseline that noisy is a baseline nobody keeps. History findings additionally
fold the commit into the path component, so the same secret in two historical
paths stays two separately-acceptable findings.

### Baselines store hashes, never secrets

**Chosen:** the baseline file holds fingerprints, secret hashes and redacted
values.
**Rejected:** storing the matched value for easier review.

The baseline is meant to be committed. A baseline containing the secret would
leak the credential a second time, in a file whose whole purpose is to be
checked in. `TestBaselineRoundTrip` asserts the raw secret never appears.

### Weak sample values are matched exactly; the rest by substring

**Chosen:** `"password"`, `"admin"`, `"guest"` and friends are compared against
the whole captured value; `"example"`, `"changeme"`, `"your-api-key"` are
matched as substrings.
**Rejected:** substring matching everything.

`strings.Contains(secret, "secret")` would discard a real credential that
happened to contain those six letters. An exact comparison cannot.

## Output

### JSONL, not a JSON array

**Chosen:** one JSON object per line.
**Rejected:** a single array.

JSONL streams. It pipes into `jq`, `grep`, `split` and `head` without the
consumer buffering a whole scan, and appending to it is trivial. The cost is
that the output is not a single valid JSON document; `jq -s` covers that case.

### Redaction shows the first and last four characters

**Chosen:** `ghp_...uIqi`.
**Rejected:** full masking, or a fixed-width `********`.

The reader needs to correlate a finding with a key in their password manager or
provider console in order to rotate the right one. Four characters at each end
is enough to do that and not enough to reconstruct the credential. PEM banners
are exempt: `-----...-----` throws away the only informative part of the
message, and the banner is not key material.

`--show-secrets` prints raw values and says so in the help text, in the flag
description and in a warning after the report, because the place that output
usually ends up is a CI log.

### Exit code 1 keys on severity, not confidence

**Chosen:** `--fail-on` takes a severity; `--min-confidence` separately controls
what gets reported at all.
**Rejected:** one combined threshold.

They answer different questions. Severity is "how bad is this kind of leak";
confidence is "how sure are we this is one". A critical finding you are not sure
about and a low-severity finding you are certain of both exist, and collapsing
them into one number makes the tool impossible to tune.

## Tooling

### The synthetic corpus is built in Go, not by a shell script

**Chosen:** `internal/testcorpus` builds the repository with go-git at test
time, into a temporary directory.
**Rejected:** committing `testdata/repo` with its `.git`, or generating it with
a `mkcorpus.sh`.

A nested `.git` cannot be committed to the parent repository — git turns it into
a gitlink. A shell script would make the tests depend on bash and on the git
binary, which is the same dependency the tool itself went out of its way to
avoid. Building it in Go with fixed timestamps makes the corpus reproducible
and the tests self-contained. `make testdata` still writes a copy to
`testdata/repo` for humans who want to poke at it.

### Rule examples are the tests

**Chosen:** every rule carries `positive` and `negative` examples in the YAML;
`TestRuleExamples` asserts all of them, and `docs/rules.md` is generated from
the same file.
**Rejected:** a separate table of test cases in Go.

Two lists of examples drift apart. One list cannot. A rule with no examples, or
with an example that does not work, fails to parse.

### The false-positive budget is a ratchet, not a report

**Chosen:** `internal/falsepositive` fails the build if `testdata/clean`
produces more findings than the recorded budget, which is currently zero at
every confidence level.
**Rejected:** printing the rate and letting a human notice.

A number in a README is a number nobody reads twice. A test that fails is a
number somebody has to deal with. `TestCleanCorpusIsActuallyAdversarial` guards
the guard: it fails if the corpus stops being full of secret-shaped strings.

## Calibration

### How the entropy thresholds were chosen

The starting points were the conventional ones — 4.5 for base64, 3.0 for hex —
and they were then checked against the two corpora rather than against
intuition:

* `testdata/clean` contains 40 secret-shaped strings that are not secrets:
  commit hashes, UUIDs, npm integrity digests, a minified bundle, base64 image
  data. At 4.5/3.0 with the contextual gate on, it produces zero findings.
* The rules that carry their own `entropy_threshold` were tuned individually
  against their examples: the AWS secret key rule sits at 4.0 because a real
  40-character AWS secret scores about 5.3 while `wJalrXUtnFEMI/K7MDENG/...`
  (AWS's own documentation sample) is filtered by the placeholder list before
  entropy is consulted at all.
* Lowering the base64 bar to 4.0 makes the clean corpus produce findings from
  the minified bundle and the base64 PNG. Raising it to 5.0 loses shorter real
  keys, whose entropy is depressed by sampling: a 20-character random base64
  string only has 20 samples to spread over 64 symbols.

The minimum length of 20 matters as much as the threshold. Shannon entropy on a
short string is dominated by sampling noise — `ab12cd34` scores 3.0 on eight
characters, which means nothing — so anything shorter is never scored.

These numbers are configurable in `.envleak.yml` precisely because they are
empirical, not derived.

### Rejected: validating tokens against provider APIs

Checking whether a found token is still live would be the single biggest
precision win available, and it is deliberately not implemented.

It would turn a local static analysis tool into something that makes
unsolicited authenticated requests to third parties using credentials it found
in somebody else's repository. That changes the legal and privacy profile of
the tool completely: on a shared CI runner it would exfiltrate the secret to the
provider, it would light up the victim's audit log from an unexpected IP, and in
several jurisdictions using a credential you found without authorisation is not
obviously lawful even to test it.

If it is ever added, it belongs behind an explicit opt-in flag, off by default,
documented as sending data to third parties, and restricted to providers with a
documented token-introspection endpoint intended for this use.
