# Security policy

## Reporting a vulnerability in EnvLeak

Open a [security advisory](https://github.com/dotMuny/EnvLeak/security/advisories/new).
Please do not open a public issue for a vulnerability.

Expect an acknowledgement within a few days and a fix or an explanation of why
it is not one within two weeks.

## What counts

EnvLeak is a local static analysis tool. It reads files and Git objects, and it
writes reports. It makes no network requests at all. So the interesting attack
surface is what happens when it is pointed at a hostile repository:

* A crafted file or blob that makes it crash, hang, or consume unbounded memory.
  The line scanner, the entropy engine and the rule parser are all fuzzed for
  exactly this; a reproducer is very welcome.
* A crafted `.envleak.yml`, `extra_rules` file or baseline that causes anything
  worse than a parse error.
* A path in a repository that makes EnvLeak read or write outside the scan root.
* Any way to get a secret into output that the operator did not ask for with
  `--show-secrets` — including into `line_sample`, the baseline file, or a
  SARIF message.

That last one is the one we care most about. A tool that finds secrets and then
prints them into a CI log has made the problem worse.

## What does not count

* False positives and false negatives in the rule catalogue. Those are bugs, and
  ordinary issues are the right place for them.
* EnvLeak reporting a secret you consider public. Use the allowlist.
* Resource use proportional to repository size. Use `--max-file-size` and
  `--concurrency`.

## About the credentials in this repository

Every credential in the rule examples, in `testdata/`, and in the tests is
synthetic and was never valid. The GitHub tokens are generated with EnvLeak's
own base62 CRC32 routine so that the checksum validator has something real to
verify against — they satisfy the format and correspond to no account.

If you believe one of them is a real credential, please report it as a
vulnerability. That would be a serious mistake on our part.

## Why GitHub's own scanner is configured to skip parts of this repository

`.github/secret_scanning.yml` excludes the rule catalogue, both corpora and the
test fixtures from GitHub secret scanning. Without it, GitHub's push protection
refuses every push to this repository, because it correctly recognises the
synthetic samples as credential-shaped.

The exclusion list mirrors `allowlist.paths` in `.envleak.yml`: the files
EnvLeak skips when scanning itself are exactly the ones GitHub is asked to skip.
Everything else — every non-test Go file, every workflow, every configuration
file — is still scanned by both, and the repository's own CI runs EnvLeak
against its working tree and its full history on every push.
