#!/usr/bin/env bash
#
# run.sh — corpus-level metrics for agat, reproducible and offline.
#
# Where generalize.sh proves one held-out variant is recognized, this
# script measures rates over a corpus, the numbers an evaluator asks for:
#
#   detection rate   held-out family variants (never trained) that come
#                    back non-self AND attributed to the family
#   severity mix     how those held-out variants were prioritized
#   benign FP rate   held-out REAL benign binaries (never in the
#                    self-model) that come back anything other than
#                    clean; reported for "any non-clean", "malicious",
#                    and wrongful family attribution. Needs --benign-dir.
#   lookalike stress synthetic XOR-decryptor stubs (tools/poly_gen.py)
#                    with a fresh payload: same loop shape as the family,
#                    different plaintext. Reported, never gated: matching
#                    them structurally is arguably correct, and they are
#                    not a stand-in for real benign software.
#
# Pipeline:
#   1. synthesize a benign corpus (tools/poly_gen.py, distinct keys and
#      seeds) and a metamorphic family (tools/meta_gen.py --count N),
#   2. split both: the self-model sees only the benign TRAIN half; the
#      family memory matures only on the first --train variants,
#   3. scan every held-out file with the stateless `agat scan --json`
#      (no vault, nothing written) and compute the rates.
#
# --benign-dir DIR adds a real benign corpus (e.g. /usr/bin on an x86-64
# Linux box: ELF binaries agat parses fully). Its files are split
# deterministically (sorted, alternating): the even half joins the
# self-model's training set, the odd half is held out and scanned for
# the real FP rate. A real deployment trains self on its own benign
# software in the same way. Without it, the FP rate is measured on
# synthetic benign samples only, and the report says so.
#
# Exit code: 0 if detection >= --min-detect and (with --benign-dir) the
# real malicious-FP rate <= --max-fp; 1 otherwise (so CI can gate on
# regressions); 2 on usage error.
#
# Usage:
#   bench/run.sh [--count N] [--train T] [--benign N] [--benign-dir DIR]
#                [--min-detect R] [--max-fp R] [--agat PATH] [--json] [--keep]
#
# Requires: python3, and either a prebuilt `agat` (pass --agat) or cargo.

set -euo pipefail

COUNT=16        # family size
TRAIN=8         # variants matured; the rest are held out
BENIGN=16       # synthetic benign samples; half train self, half held out
BENIGN_DIR=""
MIN_DETECT=0.9
MAX_FP=0.0
AGAT=""
JSON=0
KEEP=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --count)      COUNT="$2"; shift 2 ;;
    --train)      TRAIN="$2"; shift 2 ;;
    --benign)     BENIGN="$2"; shift 2 ;;
    --benign-dir) BENIGN_DIR="$2"; shift 2 ;;
    --min-detect) MIN_DETECT="$2"; shift 2 ;;
    --max-fp)     MAX_FP="$2"; shift 2 ;;
    --agat)       AGAT="$2"; shift 2 ;;
    --json)       JSON=1; shift ;;
    --keep)       KEEP=1; shift ;;
    -h|--help) grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

if [[ "$TRAIN" -lt 3 || "$TRAIN" -ge "$COUNT" ]]; then
  echo "need 3 <= --train < --count" >&2; exit 2
fi
if [[ "$BENIGN" -lt 4 ]]; then
  echo "need --benign >= 4 (half train self, half held out)" >&2; exit 2
fi
if [[ -n "$BENIGN_DIR" && ! -d "$BENIGN_DIR" ]]; then
  echo "--benign-dir $BENIGN_DIR is not a directory" >&2; exit 2
fi

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

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
cleanup() { [[ "$KEEP" -eq 1 ]] && echo "kept $WORK" >&2 || rm -rf "$WORK"; }
trap cleanup EXIT

# Training needs the vault (ingest/analyze); scanning does not.
export AGAT_VAULT_PASSWORD="bench-$$"
HOME_DIR="$WORK/home"
TRAIN_DIR="$WORK/train"
HELD_FAM="$WORK/heldout-family"
HELD_BENIGN="$WORK/heldout-benign"
mkdir -p "$TRAIN_DIR" "$HELD_FAM" "$HELD_BENIGN"
agat() { "$AGAT" --home "$HOME_DIR" "$@"; }

log() { echo "$@" >&2; }

log "==> corpus: $BENIGN synthetic lookalike stubs + $COUNT-variant metamorphic family"
HALF=$((BENIGN / 2))
for i in $(seq 1 "$BENIGN"); do
  key=$(( (i * 37 + 11) % 255 + 1 ))      # distinct non-zero keys
  if [[ "$i" -le "$HALF" ]]; then dir="$TRAIN_DIR"; else dir="$HELD_BENIGN"; fi
  python3 tools/poly_gen.py "$dir/benign_$i.bin" --key "$key" --seed "$((1000 + i))" >/dev/null
done
python3 tools/meta_gen.py "$WORK/fam" --count "$COUNT" >/dev/null
for i in $(seq 1 "$COUNT"); do
  if [[ "$i" -le "$TRAIN" ]]; then mv "$WORK/fam_v$i.bin" "$TRAIN_DIR/"
  else mv "$WORK/fam_v$i.bin" "$HELD_FAM/"; fi
done

# Split the real benign corpus: even-indexed files train self, odd are held out.
REAL_TRAIN="$WORK/real-train"
REAL_HELD="$WORK/real-heldout"
mkdir -p "$REAL_TRAIN" "$REAL_HELD"
if [[ -n "$BENIGN_DIR" ]]; then
  n=0
  while IFS= read -r f; do
    if (( n % 2 == 0 )); then cp "$f" "$REAL_TRAIN/real_$n"; else cp "$f" "$REAL_HELD/real_$n"; fi
    n=$((n + 1))
  done < <(find "$BENIGN_DIR" -type f -size +0 2>/dev/null | sort)
fi
REAL_TRAIN_N=$(find "$REAL_TRAIN" -type f | wc -l | tr -d ' ')

log "==> train: self-model on $HALF synthetic + $REAL_TRAIN_N real benign, memory on $TRAIN variants"
agat ingest "$TRAIN_DIR"/*.bin >/dev/null 2>&1
if [[ "$REAL_TRAIN_N" -gt 0 ]]; then agat ingest "$REAL_TRAIN"/* >/dev/null 2>&1; fi
agat analyze >/dev/null 2>&1
LISTING="$(agat list 2>/dev/null)"
id_of() { awk -v f="$1" '$NF==f {print $1}' <<<"$LISTING"; }
BENIGN_IDS=()
for i in $(seq 1 "$HALF"); do BENIGN_IDS+=("$(id_of "benign_$i.bin")"); done
for f in "$REAL_TRAIN"/*; do
  [[ -e "$f" ]] || continue
  id="$(id_of "$(basename "$f")")"
  [[ -n "$id" ]] && BENIGN_IDS+=("$id")
done
agat self build "${BENIGN_IDS[@]}" >/dev/null
agat repertoire generate --seed 1 >/dev/null
for i in $(seq 1 "$TRAIN"); do
  agat mature "$(id_of "fam_v$i.bin")" --family metamorph >/dev/null
done

# Stateless scans of everything held out. --fail-on never: the verdicts
# are the data here, not a reason to stop.
log "==> scan held-out sets (stateless)"
unset AGAT_VAULT_PASSWORD
agat scan "$HELD_FAM" --json --fail-on never 2>/dev/null </dev/null > "$WORK/fam.json"
agat scan "$HELD_BENIGN" --json --fail-on never 2>/dev/null </dev/null > "$WORK/benign.json"
REAL_JSON=""
if [[ -n "$BENIGN_DIR" ]]; then
  log "==> scan held-out half of real benign corpus $BENIGN_DIR"
  REAL_JSON="$WORK/real.json"
  # Unreadable/odd files are skipped by scanning one at a time.
  find "$REAL_HELD" -type f | sort > "$WORK/real.list"
  echo "[" > "$REAL_JSON"; first=1
  while IFS= read -r f; do
    out="$(agat scan "$f" --json --fail-on never 2>/dev/null </dev/null)" || continue
    [[ -z "$out" ]] && continue
    [[ "$first" -eq 1 ]] && first=0 || echo "," >> "$REAL_JSON"
    printf '%s\n' "$out" >> "$REAL_JSON"
  done < "$WORK/real.list"
  echo "]" >> "$REAL_JSON"
fi

python3 - "$WORK/fam.json" "$WORK/benign.json" "${REAL_JSON:-}" \
  "$COUNT" "$TRAIN" "$BENIGN" "$MIN_DETECT" "$MAX_FP" "$JSON" <<'PY'
import json, sys

fam_path, benign_path, real_path = sys.argv[1:4]
count, train, benign = map(int, sys.argv[4:7])
min_detect, max_fp = map(float, sys.argv[7:9])
as_json = sys.argv[9] == "1"

def load(p):
    d = json.load(open(p))
    return d if isinstance(d, list) else [d]

def sev(r): return r["verdict"]["severity"]

fam = load(fam_path)
detected = [r for r in fam if r["recognition"]["recognized"]
            and r["recognition"].get("family") == "metamorph"]
mix = {s: sum(sev(r) == s for r in fam) for s in ("malicious", "suspicious", "review", "clean")}
aff = sorted(r["recognition"]["affinity"] for r in detected)

def fp_block(results, label, gated):
    n = len(results)
    nonclean = sum(sev(r) != "clean" for r in results)
    malicious = sum(sev(r) == "malicious" for r in results)
    swallowed = sum(r["recognition"].get("family") == "metamorph" for r in results)
    return {
        "corpus": label, "gated": gated, "n": n,
        "nonclean": nonclean, "nonclean_rate": nonclean / n if n else None,
        "malicious": malicious, "malicious_rate": malicious / n if n else None,
        "family_swallowed": swallowed,
    }

lookalike = fp_block(load(benign_path), "synthetic lookalike stubs", False)
real = fp_block(load(real_path), "real benign, held out", True) if real_path else None

detect_rate = len(detected) / len(fam) if fam else 0.0
real_fp = (real["malicious_rate"] or 0.0) if real else None
passed = detect_rate >= min_detect and (real_fp is None or real_fp <= max_fp)

report = {
    "family": {"size": count, "trained": train, "held_out": len(fam),
               "detected": len(detected), "detection_rate": detect_rate,
               "severity_mix": mix,
               "affinity_min": aff[0] if aff else None,
               "affinity_median": aff[len(aff) // 2] if aff else None},
    "benign_fp": real,
    "lookalike_stress": lookalike,
    "gate": {"min_detect": min_detect, "max_malicious_fp": max_fp,
             "fp_measured": real is not None, "passed": passed},
}

def show(b, title):
    print(f"\n================ {title} ================")
    if not b["n"]:
        print(f"  [{b['corpus']}] no scannable files"); return
    print(f"  [{b['corpus']}] n={b['n']}")
    print(f"    any non-clean     {b['nonclean']}/{b['n']}  = {b['nonclean_rate']:.1%}")
    print(f"    malicious         {b['malicious']}/{b['n']}  = {b['malicious_rate']:.1%}")
    print(f"    family swallowed  {b['family_swallowed']}/{b['n']}")

if as_json:
    print(json.dumps(report, indent=2))
else:
    f = report["family"]
    print(f"\n================ detection: held-out family variants ================")
    print(f"  family size {f['size']} · trained on {f['trained']} · held out {f['held_out']}")
    print(f"  detected (non-self + family)   {f['detected']}/{f['held_out']}  = {detect_rate:.1%}")
    print(f"  severity mix                   " +
          " · ".join(f"{k} {v}" for k, v in mix.items()))
    if aff:
        print(f"  affinity                       min {aff[0]:.3f} · median {aff[len(aff)//2]:.3f}")
    if real:
        show(real, "false positives: real benign, held out")
    else:
        print("\n================ false positives: NOT MEASURED ================")
        print("  pass --benign-dir DIR (real x86-64 ELF/PE binaries) to measure the FP rate.")
    show(lookalike, "stress (reported, not gated): synthetic lookalike stubs")
    print("  these share the family's decryptor loop with a fresh payload; a structural")
    print("  match is expected, and they do not represent real benign software.")
    fp_txt = f"real malicious-FP {real_fp:.1%} (need <= {max_fp:.0%})" if real else "FP not measured"
    print(f"\n{'PASS' if passed else 'FAIL'}: detection {detect_rate:.1%} (need >= {min_detect:.0%}), {fp_txt}")

sys.exit(0 if passed else 1)
PY
