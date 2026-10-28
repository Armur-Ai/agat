#!/usr/bin/env bash
#
# demo/showcase-setup.sh — build the 19-file showcase corpus for the
# 60-second cinematic MP4 (demo/showcase.tape).
#
# Run demo/run.sh first (it trains the model in demo/.work/local/home and
# learns the metamorphic family). This script then synthesizes a folder of
# unknown binaries — a dozen metamorphic variants, an AI-rewritten variant,
# and a handful of benign utilities — all synthetic, inert and deterministic,
# and ingests the AI-rewritten sample so `agat diff` has it on hand.
#
#   demo/run.sh
#   demo/showcase-setup.sh
#   vhs demo/showcase.tape        # -> demo/.work/agat-showcase.mp4

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="$REPO_ROOT/demo/.work/local"
HOME_DIR="$WORK/home"
AGAT="$REPO_ROOT/target/release/agat"
TOOLS="$REPO_ROOT/tools"

[[ -x "$AGAT" ]] || { echo "build first: cargo build --release -p agat-cli" >&2; exit 1; }
[[ -d "$HOME_DIR" ]] || { echo "train first: demo/run.sh" >&2; exit 1; }

export AGAT_VAULT_PASSWORD="agat-demo"
SHOW="$WORK/showcase"
rm -rf "$SHOW"; mkdir -p "$SHOW"

# A dozen metamorphic variants of the trained family (register/encoding/
# instruction-substitution siblings) — recognized by the memory cell.
python3 "$TOOLS/meta_gen.py" "$SHOW/mutant" --count 12 >/dev/null

# One AI-rewritten variant (algorithm substituted) — a malicious anomaly.
python3 "$TOOLS/ai_gen.py" "$SHOW/ai_rewrite_1.bin" >/dev/null

# A handful of benign utilities (self-like structure) for color/contrast.
for k in 0x11 0x22 0x33 0x44 0x55 0x66; do
  python3 "$TOOLS/poly_gen.py" "$SHOW/util_$k.bin" --key "$k" >/dev/null 2>&1
done

echo "corpus: $(find "$SHOW" -type f | wc -l | tr -d ' ') files in $SHOW"

# Ingest the AI-rewritten sample so the TUI and `agat diff` can reference it.
"$AGAT" --home "$HOME_DIR" ingest "$SHOW/ai_rewrite_1.bin" >/dev/null 2>&1 || true
"$AGAT" --home "$HOME_DIR" analyze >/dev/null 2>&1 || true

echo "ready — render with: vhs demo/showcase.tape"
