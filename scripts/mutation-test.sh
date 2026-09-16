#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────────────────
#   mutation-test.sh — Run cargo-mutants scoped to zk_range_proof & verkle
#
#   Usage:
#     ./scripts/mutation-test.sh               # run all tests (slow)
#     ./scripts/mutation-test.sh -- test_verkle # filter to verkle only
#     ./scripts/mutation-test.sh -- test_zk     # filter to range proof only
#
#   Requires: cargo-mutants >= 27
#   Install:  cargo install cargo-mutants --locked
# ──────────────────────────────────────────────────────────────────────────────
set -euo pipefail

CRATE_DIR="$(dirname "$0")/../contracts/scoregate-score"
FILTER_ARGS=("$@")

echo "==> cargo-mutants: zk_range_proof.rs + verkle.rs"
echo "    Filter args: ${FILTER_ARGS[*]:-(none)}"
echo ""

exec cargo mutants \
    --manifest-path "$CRATE_DIR/Cargo.toml" \
    --file src/zk_range_proof.rs \
    --file src/verkle.rs \
    --timeout 300 \
    "${FILTER_ARGS[@]}"
