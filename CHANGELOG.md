# Changelog

All notable changes are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `envleak scan` — working-tree scanning with `.gitignore` support, binary and
  size filters, a worker pool sized by `runtime.NumCPU()`, `--staged` for
  pre-commit hooks, and `-` for stdin.
- `envleak history` — walks every commit on every branch and reports, for each
  finding, whether the secret is still reachable from HEAD. `--since` accepts a
  date, a duration or a revision.
- `envleak baseline` — records current findings so later runs report only what
  is new. Stores fingerprints and redacted values, never secrets.
- `envleak rules` — lists the catalogue; `--markdown` generates `docs/rules.md`.
- `envleak install-hook` — writes a pre-commit hook that will not clobber an
  existing one without `--force`.
- 65 detection rules covering AWS, GitHub, GitLab, Slack, Stripe, Google, GCP,
  OpenAI, Anthropic, Twilio, SendGrid, Mailgun, Mailchimp, Telegram, Discord,
  PEM private keys, database and queue URIs, Azure, npm, PyPI, Docker Hub,
  DigitalOcean, Heroku, Cloudflare, Shopify, Square, Datadog, New Relic,
  Sentry, Algolia, HashiCorp Vault, JWTs and generic assignments.
- Three detection engines — pattern, Shannon entropy and checksum validators —
  aggregated into a `confidence` field.
- Checksum and structure validators: `github-crc32`, `github-pat-structure`,
  `jwt`.
- `continuation` checks: a PEM banner is only reported when the following line
  is actually key material.
- False-positive filters: placeholder detection, inline `// envleak:ignore`
  directives, a configurable allowlist, baselines, and confidence discounting
  for tests, docs, examples, lockfiles, vendored and generated files.
- Output formats: `text`, `json` (JSONL), `sarif` (2.1.0) and `junit`.
- Integrations: composite GitHub Action with SARIF upload,
  `.pre-commit-hooks.yaml`, and a multi-stage Dockerfile onto `scratch`.
- `.envleak.yml` for per-repository configuration, including custom rule files.

[Unreleased]: https://github.com/dotMuny/EnvLeak/compare/v0.1.0...HEAD
