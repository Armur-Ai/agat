#!/usr/bin/env bash
#
# throughput.sh — how fast does agat scan?
#
# Measures stateless scan throughput over a directory of real binaries at
# a range of worker counts, so you can size a deployment. Reports files
# per second and the parallel speedup. Needs a trained model and a corpus
# (bench/fetch-benign.sh gives you one).
#
# Usage:
#   bench/throughput.sh [--home DIR] [--corpus DIR] [--jobs "1 2 4 8"] [--agat PATH]

set -euo pipefail

HOME_DIR=""
CORPUS="bench/corpus/debian-bin"
JOBS_LIST="1 2 4 8"
AGAT=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --home)   HOME_DIR="$2"; shift 2 ;;
    --corpus) CORPUS="$2"; shift 2 ;;
    --jobs)   JOBS_LIST="$2"; shift 2 ;;
    --agat)   AGAT="$2"; shift 2 ;;
    -h|--help) grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"
if [[ -z "$AGAT" ]]; then
  for c in ./target/release/agat ./target/debug/agat; do [[ -x "$c" ]] && { AGAT="$c"; break; }; done
  [[ -n "$AGAT" ]] || { cargo build -q --release -p agat-cli >&2; AGAT=./target/release/agat; }
fi
[[ -d "$CORPUS" ]] || { echo "no corpus at $CORPUS — run bench/fetch-benign.sh" >&2; exit 2; }

# A trained model is needed to scan. If none was given, train a throwaway.
WORK=""
if [[ -z "$HOME_DIR" ]]; then
  WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT
  HOME_DIR="$WORK/home"
  export AGAT_VAULT_PASSWORD="tput-$$"
  echo "==> training a throwaway model" >&2
  files=$(find "$CORPUS" -type f | head -20)
  "$AGAT" --home "$HOME_DIR" ingest $files >/dev/null 2>&1
  "$AGAT" --home "$HOME_DIR" analyze >/dev/null 2>&1
  ids=$("$AGAT" --home "$HOME_DIR" list 2>/dev/null | awk 'NR>1{print $1}')
  "$AGAT" --home "$HOME_DIR" self build $ids >/dev/null
  "$AGAT" --home "$HOME_DIR" repertoire generate --seed 1 >/dev/null
  unset AGAT_VAULT_PASSWORD
fi

N=$(find "$CORPUS" -type f | wc -l | tr -d ' ')
echo
echo "================ scan throughput ($N files, $CORPUS) ================"
printf "  %-8s %-10s %-10s %s\n" "jobs" "seconds" "files/s" "speedup"
base=""
for j in $JOBS_LIST; do
  start=$(python3 -c 'import time;print(time.time())')
  "$AGAT" --home "$HOME_DIR" scan "$CORPUS" -j "$j" --output json --fail-on never >/dev/null 2>&1
  end=$(python3 -c 'import time;print(time.time())')
  secs=$(python3 -c "print(f'{$end-$start:.2f}')")
  fps=$(python3 -c "print(f'{$N/($end-$start):.0f}')")
  [[ -z "$base" ]] && base="$secs"
  spd=$(python3 -c "print(f'{$base/$secs:.1f}x')")
  printf "  %-8s %-10s %-10s %s\n" "$j" "$secs" "$fps" "$spd"
done
