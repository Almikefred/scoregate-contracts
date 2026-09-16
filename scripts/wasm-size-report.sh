#!/usr/bin/env bash
set -euo pipefail

TOP=10
OUTPUT=""
WASM_PATH="target/wasm32-unknown-unknown/release/scoregate_score.wasm"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --top)
      TOP="$2"
      shift 2
      ;;
    --output)
      OUTPUT="$2"
      shift 2
      ;;
    --wasm)
      WASM_PATH="$2"
      shift 2
      ;;
    -h|--help)
      echo "Usage: $0 [--top <N>] [--output <PATH>] [--wasm <PATH>]"
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      exit 1
      ;;
  esac
done

if [[ ! -f "$WASM_PATH" ]]; then
  echo "WASM binary not found at $WASM_PATH. Building..."
  cargo build --target wasm32-unknown-unknown --release -p scoregate-score
fi

if ! command -v twiggy &> /dev/null; then
  echo "Error: twiggy is not installed. Install it with: cargo install twiggy" >&2
  exit 1
fi

generate_report() {
  echo "# WASM Binary Size Report: scoregate-score.wasm"
  echo ""
  echo "Binary: $WASM_PATH"
  echo "Binary Size: $(wc -c < "$WASM_PATH" | tr -d ' ') bytes"
  echo ""
  echo "## 1. Top Shallow Size Contributors (twiggy top)"
  echo ""
  echo "\`\`\`"
  twiggy top -n "$TOP" "$WASM_PATH"
  echo "\`\`\`"
  echo ""
  echo "## 2. Top Retained Size / Dominator Tree (twiggy dominators)"
  echo ""
  echo "\`\`\`"
  twiggy dominators -r "$TOP" "$WASM_PATH"
  echo "\`\`\`"
}

if [[ -n "$OUTPUT" ]]; then
  mkdir -p "$(dirname "$OUTPUT")"
  generate_report > "$OUTPUT"
  echo "WASM size report written to: $OUTPUT"
else
  generate_report
fi
