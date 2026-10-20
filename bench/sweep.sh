#!/usr/bin/env bash
#
# sweep.sh — affinity-weight sensitivity sweep.
#
# The antigen's six group weights (opcode, block, struct, entropy, style,
# imports) are engineered, all 1.0 by default. This retrains the whole
# immune pipeline under perturbed weights — each weight halved and doubled
# alone, then N random vectors with every weight in [x0.5, x2] — and
# reports how detection and false positives move. A stable result means
# the verdicts come from the data, not from a hand-tuned knife edge.
#
# Same corpus split as run.sh: a 16-variant metamorphic family (train 8,
# hold out 8) and a real benign corpus split train/held-out, plus the
# synthetic stubs in self. Runs offline.
#
# Usage:
#   bench/sweep.sh [--benign-dir DIR] [--random N] [--json] [--keep]
#
# --benign-dir defaults to bench/corpus/debian-bin (bench/fetch-benign.sh).

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

BENIGN_DIR="bench/corpus/debian-bin"
RANDOM_N=20
JSON=""
KEEP=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --benign-dir) BENIGN_DIR="$2"; shift 2 ;;
    --random)     RANDOM_N="$2"; shift 2 ;;
    --json)       JSON="--json"; shift ;;
    --keep)       KEEP=1; shift ;;
    -h|--help) grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done
if [[ ! -d "$BENIGN_DIR" ]]; then
  echo "no benign corpus at $BENIGN_DIR — run bench/fetch-benign.sh or pass --benign-dir" >&2
  exit 2
fi

WORK="$(mktemp -d)"
cleanup() { [[ "$KEEP" -eq 1 ]] && echo "kept $WORK" >&2 || rm -rf "$WORK"; }
trap cleanup EXIT
mkdir -p "$WORK"/{train-benign,train-family,heldout-family,heldout-benign}

echo "==> corpus" >&2
for i in $(seq 1 8); do
  python3 tools/poly_gen.py "$WORK/train-benign/stub_$i.bin" \
    --key "$(( (i * 37 + 11) % 255 + 1 ))" --seed "$((1000 + i))" >/dev/null
done
python3 tools/meta_gen.py "$WORK/fam" --count 16 >/dev/null
for i in $(seq 1 16); do
  if [[ "$i" -le 8 ]]; then mv "$WORK/fam_v$i.bin" "$WORK/train-family/"
  else mv "$WORK/fam_v$i.bin" "$WORK/heldout-family/"; fi
done
n=0
while IFS= read -r f; do
  if (( n % 2 == 0 )); then cp "$f" "$WORK/train-benign/real_$n"; else cp "$f" "$WORK/heldout-benign/real_$n"; fi
  n=$((n + 1))
done < <(find "$BENIGN_DIR" -type f -size +0 | sort)

echo "==> sweep (retrains the pipeline per weighting)" >&2
cargo run -q --release -p agat-engine --example sweep -- "$WORK" --random "$RANDOM_N" $JSON
