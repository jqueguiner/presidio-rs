#!/usr/bin/env bash
# Fail unless line coverage of the analyzer + anonymizer crates is >= 95%.
# Used by the pre-commit `coverage-95` hook and reproducible locally.
set -euo pipefail

MIN="${COVERAGE_MIN:-95}"

if ! command -v cargo-llvm-cov >/dev/null 2>&1; then
  echo "error: cargo-llvm-cov not found." >&2
  echo "  rustup component add llvm-tools-preview" >&2
  echo "  cargo install cargo-llvm-cov" >&2
  exit 1
fi

# Collect instrumented coverage, then report + enforce the floor.
cargo llvm-cov --no-report -p presidio-analyzer -p presidio-anonymizer
cargo llvm-cov report
cargo llvm-cov report --fail-under-lines "$MIN"
