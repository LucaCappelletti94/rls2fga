# rls2fga

[![CI](https://github.com/LucaCappelletti94/rls2fga/actions/workflows/ci.yml/badge.svg)](https://github.com/LucaCappelletti94/rls2fga/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/LucaCappelletti94/rls2fga/graph/badge.svg)](https://codecov.io/gh/LucaCappelletti94/rls2fga)
[![License](https://img.shields.io/github/license/LucaCappelletti94/rls2fga)](LICENSE)

Rust crate to convert Postgres Row Level Security (RLS) to OpenFGA's Fine Grained Authorization

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
cargo run --bin xtask -- precommit
```

Validate a commit message manually:

```bash
cargo run --bin xtask -- commit-msg .git/COMMIT_EDITMSG
```

Include Docker-backed ignored tests (OpenFGA + PostgreSQL 18):

```bash
cargo run --bin xtask -- precommit --with-docker
```

## CI

GitHub Actions CI is defined in `.github/workflows/ci.yml` with:

- `quality` matrix job (`ubuntu`, `macos`, `windows`) via `xtask ci --locked`
- `docs` job (`ubuntu`) building rustdoc with warnings denied
- `security-audit` job (`ubuntu`) checking dependencies with `cargo audit`
- `docker-integration` job (`ubuntu`) for ignored Docker-backed integration tests
- `coverage` job (`ubuntu`) generating coverage via `cargo llvm-cov` and uploading to Codecov
