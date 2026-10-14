#!/usr/bin/env bash
#
# generalize.sh — agat's headline benchmark, made reproducible.
#
# The claim: agat recognizes metamorphic variants it has never seen. Not
# by memorizing hashes, but because clonal selection grows a family
# memory cell that covers the family's neighborhood in antigen space.
#
# This script proves it end to end on real ELF binaries:
#
#   1. synthesize a benign "self" corpus and an N-variant metamorphic
#      family (tools/poly_gen.py, tools/meta_gen.py),
#   2. ingest + analyze everything, build the self-model, and generate
#      the negative-selection repertoire,
#   3. mature the family memory on variants v1..v(N-1),
#   4. HOLD OUT variant vN — never shown during training — and recognize
#      it: it must come back non-self, attributed to the family, with
#      high affinity, via a secondary (memory) response,
#   5. CONTROL: recognize a benign sample; it must NOT be swallowed into
#      the family (no overgeneralization).
#
# Exit code: 0 if both the held-out hit and the control pass, 1 otherwise.
#
# Usage:
#   bench/generalize.sh [--count N] [--agat PATH] [--keep]
#
# Requires: python3, and either a prebuilt `agat` (pass --agat) or cargo.

set -euo pipefail

COUNT=8
AGAT=""
KEEP=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --count) COUNT="$2"; shift 2 ;;
    --agat)  AGAT="$2"; shift 2 ;;
    --keep)  KEEP=1; shift ;;
    -h|--help) grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

if [[ "$COUNT" -lt 4 ]]; then
  echo "need --count >= 4 (train on >=3, hold out 1)" >&2
  exit 2
fi

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

# Locate or build the agat binary.
if [[ -z "$AGAT" ]]; then
  if [[ -x "./target/release/agat" ]]; then
    AGAT="./target/release/agat"
  elif [[ -x "./target/debug/agat" ]]; then
    AGAT="./target/debug/agat"
  else
    echo "building agat (debug)..." >&2
    cargo build -p agat-cli >&2
    AGAT="./target/debug/agat"
  fi
fi

WORK="$(mktemp -d)"
cleanup() { [[ "$KEEP" -eq 1 ]] || rm -rf "$WORK"; }
trap cleanup EXIT

export AGAT_VAULT_PASSWORD="bench-$$"
HOME_DIR="$WORK/home"
SAMPLES="$WORK/samples"
mkdir -p "$SAMPLES"

echo "==> corpus: 4 benign + $COUNT-variant metamorphic family"
for k in 0x11 0x42 0x7e 0xa5; do
  python3 tools/poly_gen.py "$SAMPLES/benign_$k.bin" --key "$k" >/dev/null
done
python3 tools/meta_gen.py "$SAMPLES/fam" --count "$COUNT" >/dev/null

echo "==> ingest + analyze"
"$AGAT" --home "$HOME_DIR" ingest "$SAMPLES"/*.bin >/dev/null
"$AGAT" --home "$HOME_DIR" analyze >/dev/null 2>&1

# Map original filename -> short id from `agat list`.
id_of() {
  "$AGAT" --home "$HOME_DIR" list 2>/dev/null \
    | awk -v f="$1" '$NF==f {print $1}'
}

echo "==> build self-model + negative-selection repertoire"
BENIGN_IDS=()
for k in 0x11 0x42 0x7e 0xa5; do BENIGN_IDS+=("$(id_of "benign_$k.bin")"); done
"$AGAT" --home "$HOME_DIR" self build "${BENIGN_IDS[@]}" >/dev/null
"$AGAT" --home "$HOME_DIR" repertoire generate --seed 1 >/dev/null

echo "==> train family memory on v1..v$((COUNT-1)) (holding out v$COUNT)"
for i in $(seq 1 $((COUNT-1))); do
  "$AGAT" --home "$HOME_DIR" mature "$(id_of "fam_v$i.bin")" --family metamorph >/dev/null
done

HELD_OUT_ID="$(id_of "fam_v$COUNT.bin")"
CONTROL_ID="$(id_of "benign_0x42.bin")"

# Extract fields from a recognize --json run. `recognize` exits with the
# verdict severity code (0/2/3) by design, so capture output tolerantly
# rather than letting errexit treat a non-clean verdict as a failure.
field() { # <sample-id> <python-expr over d>
  local out
  out="$("$AGAT" --home "$HOME_DIR" recognize "$1" --json 2>/dev/null)" || true
  printf '%s' "$out" | python3 -c "import sys,json;d=json.load(sys.stdin);print($2)"
}

echo
echo "================ held-out variant v$COUNT (never trained) ================"
H_REC=$(field "$HELD_OUT_ID" "d['recognition']['recognized']")
H_FAM=$(field "$HELD_OUT_ID" "d['recognition'].get('family')")
H_AFF=$(field "$HELD_OUT_ID" "round(d['recognition']['affinity'],3)")
H_SEC=$(field "$HELD_OUT_ID" "d['recognition']['secondary_response']")
echo "  recognized:         $H_REC"
echo "  family:             $H_FAM"
echo "  affinity:           $H_AFF"
echo "  secondary response: $H_SEC"

echo
echo "================ control: benign sample ================"
C_FAM=$(field "$CONTROL_ID" "d['recognition'].get('family')")
echo "  family attribution: $C_FAM   (must be None)"

echo
PASS=1
if [[ "$H_REC" != "True" || "$H_FAM" != "metamorph" ]]; then
  echo "FAIL: held-out variant not recognized as family 'metamorph'"; PASS=0
fi
# Affinity should be clearly positive (generalization, not a graze).
if python3 -c "import sys; sys.exit(0 if float('$H_AFF')>=0.5 else 1)"; then :; else
  echo "FAIL: held-out affinity $H_AFF below 0.5"; PASS=0
fi
if [[ "$C_FAM" == "metamorph" ]]; then
  echo "FAIL: benign control was swallowed into the family (overgeneralization)"; PASS=0
fi

if [[ "$PASS" -eq 1 ]]; then
  echo "PASS: trained on $((COUNT-1)) variants, recognized a held-out sibling"
  echo "      (family '$H_FAM', affinity $H_AFF) and kept benign out."
  exit 0
else
  echo "benchmark failed"
  exit 1
fi
