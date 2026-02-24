# rls2fga

[![CI](https://github.com/LucaCappelletti94/rls2fga/actions/workflows/ci.yml/badge.svg)](https://github.com/LucaCappelletti94/rls2fga/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/LucaCappelletti94/rls2fga/graph/badge.svg)](https://codecov.io/gh/LucaCappelletti94/rls2fga)
[![License](https://img.shields.io/github/license/LucaCappelletti94/rls2fga)](https://github.com/LucaCappelletti94/rls2fga/blob/main/LICENSE)

Rust crate to convert Postgres Row Level Security (RLS) to `OpenFGA`'s Fine Grained Authorization

## Policy Role Scope Translation

When a policy uses `TO <role>` (and not `TO PUBLIC`), generated output now models
that scope explicitly:

- model generation adds a policy scope relation per scoped policy
- model generation adds a `pg_role` type with `member` relation
- tuple generation emits `pg_role:<role>` scope tuples per protected row

You still need to load `pg_role#member` tuples in your environment so users are
mapped to the right `PostgreSQL` roles.

## Pre-commit hook (Rust-based)

Install the repository hooks:

```bash
./scripts/install-hooks.sh
```

Installed hooks:

- `pre-commit`: runs Rust quality checks
- `commit-msg`: validates Conventional Commit format

`pre-commit` runs:

- `cargo fmt --all -- --check`
- `cargo clippy --all-targets --all-features -- -D warnings`
- `cargo test --features db`

Run the same checks manually:

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --features db --lib --tests
```

Validate a commit message manually:

```bash
./scripts/validate-commit-msg.sh .git/COMMIT_EDITMSG
```

Include Docker-backed ignored tests (`OpenFGA` + `PostgreSQL` 18):

```bash
cargo test --features db --tests -- --ignored
```

## CI

GitHub Actions CI is defined in `.github/workflows/ci.yml` with:

- `quality` matrix job (`ubuntu`, `macos`, `windows`) via direct cargo checks
- `docs` job (`ubuntu`) building rustdoc with warnings denied
- `security-audit` job (`ubuntu`) checking dependencies with `cargo audit`
- `docker-integration` job (`ubuntu`) for ignored Docker-backed integration tests
- `coverage` job (`ubuntu`) generating coverage via `cargo llvm-cov` and uploading to Codecov

## Dependency update policy

`sqlparser` is currently tracked from the upstream `main` branch.

When `Cargo.lock` updates that dependency, include in the same PR:

- `cargo test --lib`
- `cargo clippy --all-targets --all-features -- -D warnings`
- snapshot/test updates for parser-classifier-generator behavior changes
