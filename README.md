# rls2fga

Rust crate to convert Postgres Row Level Security (RLS) to OpenFGA's Fine Grained Authorization

## Pre-commit hook (Rust-based)

Install the repository hooks:

```bash
./scripts/install-hooks.sh
```

The pre-commit hook runs:

- `cargo fmt --all -- --check`
- `cargo clippy --all-targets --all-features -- -D warnings`
- `cargo test --features db`

Run the same checks manually:

```bash
cargo run --bin xtask -- precommit
```

Include Docker-backed ignored tests (OpenFGA + PostgreSQL 18):

```bash
cargo run --bin xtask -- precommit --with-docker
```

## CI

GitHub Actions CI is defined in `.github/workflows/ci.yml` with:

- `checks` job for format, lint, and tests via `xtask precommit`
- `docker-integration` job for ignored Docker-backed integration tests
