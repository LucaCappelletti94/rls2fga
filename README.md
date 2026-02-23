# rls2fga

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
- `docker-integration` job (`ubuntu`) for ignored Docker-backed integration tests
