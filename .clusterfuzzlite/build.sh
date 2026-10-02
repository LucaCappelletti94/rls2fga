#!/bin/bash
set -eu

cd "$SRC/rls2fga"
# the base image exports its own nightly as RUSTUP_TOOLCHAIN, so no toolchain is named here
cargo fuzz build -O --debug-assertions --fuzz-dir fuzz

targets=$(cargo fuzz list --fuzz-dir fuzz)
if [[ -z "$targets" ]]; then
    echo "cargo fuzz list named no target" >&2
    exit 1
fi

target_dir=fuzz/target/x86_64-unknown-linux-gnu/release
for name in $targets; do
    cp "$target_dir/$name" "$OUT/"
    cp fuzz/rls.dict "$OUT/$name.dict"
    printf '[libfuzzer]\nrss_limit_mb = 4096\n' >"$OUT/$name.options"
done

# the runner unpacks <target>_seed_corpus.zip as the starting corpus
for dir in fuzz/seeds/*/; do
    name=$(basename "$dir")
    zip -qj "$OUT/${name}_seed_corpus.zip" "$dir"*
done
