# Contributing to Emberlink

Thanks for your interest. A few things to know before you open a PR:

## How contributions land here

This repository is a curated downstream of an active development monorepo.
`main` is write-locked to a sync bot; direct commits and merges by external
contributors are not possible. See [PUBLISHING.md](PUBLISHING.md) for the
overview.

Internal maintainer tooling and ship workflows live upstream in the
development monorepo. They are not part of the public contributor workflow for
this downstream mirror.

**You can still open a PR.** Here's what happens:

1. You open your PR against `main`.
2. A maintainer reviews it — including a mandatory security review for any
   code change.
3. If accepted, a maintainer cherry-picks your change through the
   maintainer's process, with your `Co-Authored-By:` trailer preserved.
4. The next sync brings the change here. Your PR is closed with a link to
   the synced commit.

Credit stays with you. The delay is typically 1–3 business days.

## Before you open a PR

**Any of these will be rejected or require a design discussion first:**

- Changes to files in `.github/CODEOWNERS` (crypto, authorization, policy
  engine, event lifecycle)
- New workspace dependencies or changes to `Cargo.lock`
- Changes to `.github/workflows/*`, `build.rs`, or `mise.toml`
- Changes that touch how secrets are read, logged, or passed between
  processes
- Changes without tests
- Changes without a clear motivation in the PR description

**Good contributions:**

- Bug fixes with regression tests
- Documentation improvements
- Performance improvements with a `criterion` bench
- New examples, demo scripts, or SDK additions
- Typo fixes, clarity improvements in comments
- New language bindings for the SDK (with discussion first)

## PR format

Please include:

- **What changed** — one-sentence summary
- **Why** — the problem this solves
- **How** — brief technical approach if it isn't obvious from the diff
- **Tests** — what you tested, how a reviewer can verify

## Code style

- Rust: `cargo fmt` + `cargo clippy -- -D warnings` must pass
- Conventional Commits format for commit messages (`feat:`, `fix:`,
  `refactor:`, `docs:`, `chore:`, `test:`, `perf:`)
- First commit line under 72 characters

## Design proposals

For anything substantial, open an issue first with the `rfc` label. We'd
rather discuss direction before you invest time in an implementation.

## Security reports

See [SECURITY.md](SECURITY.md). Please do not open public issues for
security-sensitive findings.

## Code of conduct

See [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

## Questions

Open an issue with the `question` label, or discuss in GitHub Discussions.
