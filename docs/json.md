# JSONL output schema

`envleak --format json` emits [JSON Lines](https://jsonlines.org): one
self-contained JSON object per finding, newline separated, in the order the
findings are reported. No findings means no output.

The schema is versioned by the `schema` field and is stable: fields may be
added in a minor release, and are never removed or retyped without a new
schema version.

```sh
envleak scan . --format json | jq -r 'select(.confidence == "high") | "\(.path):\(.line) \(.rule_id)"'
```

## Fields

| Field | Type | Always present | Meaning |
|---|---|---|---|
| `schema` | string | yes | Schema identifier, currently `envleak.finding/v1`. |
| `tool` | string | yes | Tool name and version that produced the record. |
| `rule_id` | string | yes | Stable rule identifier. `generic-high-entropy` for entropy-only findings. |
| `description` | string | yes | Human-readable description of the rule. |
| `severity` | string | yes | `critical`, `high`, `medium` or `low`. How bad this kind of leak is. |
| `confidence` | string | yes | `high`, `medium` or `low`. How sure we are it is a real secret. |
| `engines` | array of string | yes | Which engines agreed: `pattern`, `entropy`, `validator`. |
| `tags` | array of string | no | Rule tags, e.g. `["aws","cloud"]`. |
| `path` | string | yes | Repo-relative path, forward slashes. `<stdin>` for piped input. |
| `line` | number | yes | 1-based line number. |
| `start_column`, `end_column` | number | yes | 1-based column range of the secret within the line. |
| `line_sample` | string | no | The line, trimmed to 200 characters, with the secret redacted unless `--show-secrets`. |
| `secret` | string | only with `--show-secrets` | The raw matched value. |
| `redacted` | string | yes | First and last four characters, e.g. `ghp_...uIqi`. |
| `entropy` | number | no | Shannon entropy in bits per character, when entropy was consulted. |
| `validator` | string | no | Name of the checksum/structure validator the rule declares. |
| `validated` | boolean | yes | Whether that validator passed. |
| `fingerprint` | string | yes | Stable identity of the finding: `sha256(rule_id \|\| path \|\| secret)`, truncated. Excludes the line number, so moving code does not change it. This is what a baseline matches on. |
| `secret_hash` | string | yes | Hash of the secret value alone, independent of where it was found. |
| `commit` | string | history scans only | Full hash of the commit that introduced the blob. |
| `author`, `author_email` | string | history scans only | Author of that commit. |
| `date` | string | history scans only | Author date, RFC 3339. |
| `in_head` | boolean | history scans only | Whether the secret is still reachable from HEAD. `false` means it was removed from the tree — and is still compromised. |
| `notes` | array of string | no | Why the confidence was adjusted, e.g. `["documentation file"]`. |

## Example

```json
{"schema":"envleak.finding/v1","tool":"envleak v0.1.0","rule_id":"github-pat-classic","description":"GitHub classic personal access token","severity":"critical","confidence":"high","engines":["pattern","validator"],"tags":["github","vcs"],"path":"src/deploy.sh","line":12,"start_column":14,"end_column":54,"line_sample":"GITHUB_TOKEN=ghp_...uIqi","redacted":"ghp_...uIqi","validator":"github-crc32","validated":true,"fingerprint":"5b2d8460af13ce92b7d045e6","secret_hash":"3f9a1c7e5b2d8460af13ce92b7d045e6"}
```

## Exit codes

| Code | Meaning |
|---|---|
| `0` | No findings at or above `--fail-on`. |
| `1` | At least one finding at or above `--fail-on`. |
| `2` | EnvLeak failed to run: bad flags, unreadable config, not a Git repository. |

A `2` always means something needs fixing in the invocation. Treat `1` as "the
tool worked and found something".
