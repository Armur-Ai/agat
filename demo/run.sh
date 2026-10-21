#!/usr/bin/env bash
#
# demo/run.sh — the agat demo, one command, deterministic, offline.
#
#   act 0  train: model benign "self", learn one metamorphic family
#   act 1  an unseen metamorphic variant: recognized as the family by a
#          memory cell (secondary response), with no hash or signature
#   act 2  an AI-rewritten variant: the algorithm was swapped, so it is
#          NOT a family match, but it is non-self and its danger signals
#          (LLM artifacts, recovered decryptor) fire: malicious anomaly
#   act 3  a file from the benign baseline: clean
#   act 4  the pipeline view: a batch scan to SARIF, and the exit code
#
# Every agat call runs either the local binary or, with --docker IMAGE,
# `docker run --network none` (no network at all). The transcript is
# written to demo/.work/transcript-<mode>.txt; --compare runs both and
# diffs them. Identical output is the air-gap proof.
#
# Usage:
#   demo/run.sh                      # local binary
#   demo/run.sh --docker agat:dev    # same demo in a --network none container
#   demo/run.sh --compare agat:dev   # both, then diff the transcripts
#   demo/run.sh --agat PATH          # a specific local binary
#   demo/run.sh --pace 2             # pause N seconds between acts (on stage)
#
# Requires: python3 (fixture generation) and either a built agat or docker.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MODE="local"
IMAGE=""
AGAT=""
PACE=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --docker)  MODE="docker"; IMAGE="$2"; shift 2 ;;
    --compare) MODE="compare"; IMAGE="$2"; shift 2 ;;
    --agat)    AGAT="$2"; shift 2 ;;
    --pace)    PACE="$2"; shift 2 ;;
    -h|--help) grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

if [[ "$MODE" == "compare" ]]; then
  "$0" ${AGAT:+--agat "$AGAT"} >/dev/null
  "$0" --docker "$IMAGE" >/dev/null
  W="$REPO_ROOT/demo/.work"
  if diff -u "$W/transcript-local.txt" "$W/transcript-docker.txt"; then
    echo "IDENTICAL: laptop and \`docker run --network none\` produced the same"
    echo "           $(wc -l < "$W/transcript-local.txt" | tr -d ' ')-line transcript."
    exit 0
  fi
  echo "DIFFERENT: see the diff above" >&2
  exit 1
fi

if [[ "$MODE" == "local" && -z "$AGAT" ]]; then
  for c in "$REPO_ROOT/target/release/agat" "$REPO_ROOT/target/debug/agat"; do
    [[ -x "$c" ]] && { AGAT="$c"; break; }
  done
  if [[ -z "$AGAT" ]]; then
    (cd "$REPO_ROOT" && cargo build --release -p agat-cli >&2)
    AGAT="$REPO_ROOT/target/release/agat"
  fi
fi

# The script cd's into its work tree; pin the binary to an absolute path.
[[ -n "$AGAT" && "$AGAT" != /* ]] && AGAT="$(cd "$(dirname "$AGAT")" && pwd)/$(basename "$AGAT")"

# Fresh, fixed working tree. All paths agat sees are relative to it, so the
# local and container runs print the same names.
WORK="$REPO_ROOT/demo/.work/$MODE"
rm -rf "$WORK"
mkdir -p "$WORK"/{baseline,family,suspects}
cd "$WORK"
export AGAT_VAULT_PASSWORD="agat-demo"

agat() {
  if [[ "$MODE" == "docker" ]]; then
    docker run --rm --network none --user "$(id -u):$(id -g)" \
      -e AGAT_VAULT_PASSWORD -v "$WORK:/scan" -w /scan \
      "$IMAGE" --home home "$@"
  else
    "$AGAT" --home home "$@"
  fi
}

TRANSCRIPT="$REPO_ROOT/demo/.work/transcript-$MODE.txt"
: > "$TRANSCRIPT"
say()  { printf '%s\n' "$*" | tee -a "$TRANSCRIPT"; }
run()  { # echo the command, run it, record stdout; never stop on a verdict code
  say ""
  say "\$ agat $*"
  agat "$@" 2>/dev/null </dev/null | tee -a "$TRANSCRIPT" || true
}
act()  { say ""; say "════════ $* ════════"; [[ "$PACE" == 0 ]] || sleep "$PACE"; }

# ---- fixtures (synthetic, benign, deterministic) --------------------
G="$REPO_ROOT/tools"
for k in 0x11 0x42 0x7e 0xa5; do
  python3 "$G/poly_gen.py" "baseline/tool_$k.bin" --key "$k" >/dev/null
done
python3 "$G/meta_gen.py" family/fam --count 8 >/dev/null
mv family/fam_v8.bin suspects/unseen_variant.bin
python3 "$G/ai_gen.py" suspects/ai_rewritten.bin >/dev/null
cp baseline/tool_0x42.bin suspects/baseline_tool.bin

act "act 0 · train: benign self + one family (7 variants)"
agat ingest baseline/*.bin family/*.bin >/dev/null 2>&1
agat analyze >/dev/null 2>&1
id_of() { agat list 2>/dev/null | awk -v f="$1" '$NF==f {print $1}'; }
BASE_IDS=(); for k in 0x11 0x42 0x7e 0xa5; do BASE_IDS+=("$(id_of "tool_$k.bin")"); done
run self build "${BASE_IDS[@]}"
run repertoire generate --seed 1
for i in 1 2 3 4 5 6 7; do
  agat mature "$(id_of "fam_v$i.bin")" --family metamorph >/dev/null 2>&1
done
say ""
say "(matured family 'metamorph' on fam_v1..fam_v7)"

act "act 1 · a metamorphic variant agat has never seen"
run scan suspects/unseen_variant.bin

act "act 2 · an AI-rewritten variant (algorithm substituted)"
run scan suspects/ai_rewritten.bin

act "act 3 · a file from the benign baseline"
run scan suspects/baseline_tool.bin

act "act 4 · in a pipeline: batch → SARIF, exit code"
run scan suspects --sarif
code=0; agat scan suspects >/dev/null 2>&1 </dev/null || code=$?
say ""
say "\$ agat scan suspects; echo \$?"
say "$code"

# Outside the transcript, so local and docker transcripts stay comparable.
echo ""
if [[ "$MODE" == docker ]]; then
  echo "every agat call above ran under docker --network none."
else
  echo "run \`demo/run.sh --compare <image>\` to repeat this under docker --network none and diff."
fi
