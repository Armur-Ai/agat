#!/usr/bin/env bash
#
# evaluate.sh — agat against a LABELED corpus you supply.
#
# The other bench scripts use synthetic families. This one measures agat
# on whatever labeled samples you point it at — real malware families,
# your own curated set — without shipping or naming any of them.
#
# Input: a manifest, one `<relative/path>\t<label>` per line, under a
# corpus root. Use the label `benign` for benign software; any other
# label is a family. Lines beginning with `#` are ignored.
#
#   bench/evaluate.sh --corpus /data/samples --labels /data/labels.tsv
#
# What it does, per family and for benign, deterministically:
#   1. sorts each label's samples and splits them `--holdout` (default
#      0.3) into a training part and a held-out part;
#   2. trains the self-model on benign-train and matures each family's
#      memory on that family's train part;
#   3. scans every held-out sample statelessly and reports, as numbers:
#        detection rate   held-out family samples called non-self
#        attribution      of those, the share put in the RIGHT family
#        confusion        held-out samples attributed to each family
#        benign FP        held-out benign called non-clean / malicious
#
# Exit 0 if detection >= --min-detect and benign malicious-FP <= --max-fp,
# else 1 (CI-gateable), 2 on a usage error.
#
# Requires: python3, and either a prebuilt agat (--agat) or cargo.

set -euo pipefail

CORPUS=""
LABELS=""
HOLDOUT=0.3
MIN_PER_FAMILY=4
MIN_DETECT=0.0
MAX_FP=1.0
AGAT=""
JSON=0
SEED=1
KEEP=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --corpus)      CORPUS="$2"; shift 2 ;;
    --labels)      LABELS="$2"; shift 2 ;;
    --holdout)     HOLDOUT="$2"; shift 2 ;;
    --min-per-family) MIN_PER_FAMILY="$2"; shift 2 ;;
    --min-detect)  MIN_DETECT="$2"; shift 2 ;;
    --max-fp)      MAX_FP="$2"; shift 2 ;;
    --agat)        AGAT="$2"; shift 2 ;;
    --json)        JSON=1; shift ;;
    --seed)        SEED="$2"; shift 2 ;;
    --keep)        KEEP=1; shift ;;
    -h|--help) grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

[[ -n "$CORPUS" && -d "$CORPUS" ]] || { echo "--corpus DIR is required" >&2; exit 2; }
[[ -n "$LABELS" && -f "$LABELS" ]] || { echo "--labels FILE is required" >&2; exit 2; }

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"
if [[ -z "$AGAT" ]]; then
  for c in ./target/release/agat ./target/debug/agat; do [[ -x "$c" ]] && { AGAT="$c"; break; }; done
  [[ -n "$AGAT" ]] || { cargo build -q --release -p agat-cli >&2; AGAT=./target/release/agat; }
fi

WORK="$(mktemp -d)"
cleanup() { [[ "$KEEP" -eq 1 ]] && echo "kept $WORK" >&2 || rm -rf "$WORK"; }
trap cleanup EXIT
export AGAT_VAULT_PASSWORD="eval-$$"
HOME_DIR="$WORK/home"
agat() { "$AGAT" --home "$HOME_DIR" "$@"; }
log() { echo "$@" >&2; }

# Split the manifest into train/holdout parts (per label, sorted,
# deterministic). Emits two files of absolute paths per label plus a
# plan the Python reporter reads.
python3 - "$CORPUS" "$LABELS" "$HOLDOUT" "$MIN_PER_FAMILY" "$SEED" "$WORK" <<'PY'
import os, sys, hashlib
corpus, labels, holdout, min_per, seed, work = sys.argv[1:7]
holdout = float(holdout); min_per = int(min_per)

by_label = {}
for raw in open(labels, encoding="utf-8", errors="replace"):
    line = raw.rstrip("\n")
    if not line or line.lstrip().startswith("#"):
        continue
    parts = line.split("\t")
    if len(parts) < 2:
        parts = line.rsplit(None, 1)
    if len(parts) < 2:
        continue
    rel, label = parts[0].strip(), parts[1].strip()
    path = os.path.join(corpus, rel)
    if os.path.isfile(path):
        by_label.setdefault(label, []).append(os.path.abspath(path))

plan = []
os.makedirs(f"{work}/split", exist_ok=True)
for label, paths in sorted(by_label.items()):
    # Deterministic shuffle: sort by a salted hash of the path.
    paths = sorted(set(paths), key=lambda p: hashlib.sha256(f"{seed}:{p}".encode()).hexdigest())
    if len(paths) < min_per:
        print(f"skip label '{label}': {len(paths)} sample(s) < min {min_per}", file=sys.stderr)
        continue
    n_hold = max(1, round(len(paths) * holdout))
    n_hold = min(n_hold, len(paths) - 1)  # always keep >=1 for training
    hold, train = paths[:n_hold], paths[n_hold:]
    with open(f"{work}/split/{label}.train", "w") as f:
        f.write("\n".join(train) + "\n")
    with open(f"{work}/split/{label}.hold", "w") as f:
        f.write("\n".join(hold) + "\n")
    plan.append((label, len(train), len(hold)))

if not any(l != "benign" for l, _, _ in plan):
    print("no family labels with enough samples; nothing to evaluate", file=sys.stderr)
    sys.exit(2)
with open(f"{work}/plan.tsv", "w") as f:
    for label, nt, nh in plan:
        f.write(f"{label}\t{nt}\t{nh}\n")
PY

PLAN=()
while IFS= read -r row; do PLAN+=("$row"); done < "$WORK/plan.tsv"

# Ingest + analyze every training sample.
log "==> ingest + analyze training samples"
TRAIN_FILES=()
while IFS= read -r f; do TRAIN_FILES+=("$f"); done < <(cat "$WORK"/split/*.train)
# Ingest in chunks to keep the argv bounded.
printf '%s\0' "${TRAIN_FILES[@]}" | xargs -0 -n 64 "$AGAT" --home "$HOME_DIR" ingest >/dev/null 2>&1 || true
agat analyze >/dev/null 2>&1

# Map each training file to its stored id.
LISTING="$(agat list 2>/dev/null)"
id_of_name() { awk -v f="$1" '$NF==f {print $1}' <<<"$LISTING" | head -1; }

log "==> build self-model on benign-train"
BENIGN_IDS=()
if [[ -f "$WORK/split/benign.train" ]]; then
  while IFS= read -r f; do
    id="$(id_of_name "$(basename "$f")")"; [[ -n "$id" ]] && BENIGN_IDS+=("$id")
  done < "$WORK/split/benign.train"
fi
[[ ${#BENIGN_IDS[@]} -gt 0 ]] || { log "no benign training samples; add some labeled 'benign'"; exit 2; }
agat self build "${BENIGN_IDS[@]}" >/dev/null
agat repertoire generate --seed "$SEED" >/dev/null

log "==> mature family memory"
for row in "${PLAN[@]}"; do
  label="${row%%$'\t'*}"
  [[ "$label" == "benign" ]] && continue
  while IFS= read -r f; do
    id="$(id_of_name "$(basename "$f")")"
    [[ -n "$id" ]] && agat mature "$id" --family "$label" >/dev/null 2>&1 || true
  done < "$WORK/split/$label.train"
done

# Scan every held-out sample statelessly; record label + result JSON.
log "==> scan held-out samples"
unset AGAT_VAULT_PASSWORD
: > "$WORK/results.ndjson"
for row in "${PLAN[@]}"; do
  label="${row%%$'\t'*}"
  while IFS= read -r f; do
    [[ -f "$f" ]] || continue
    out="$(agat scan "$f" --json --fail-on never 2>/dev/null </dev/null)" || true
    [[ -z "$out" ]] && continue
    printf '%s\t%s\n' "$label" "$(printf '%s' "$out" | tr -d '\n')" >> "$WORK/results.ndjson"
  done < "$WORK/split/$label.hold"
done

python3 - "$WORK/results.ndjson" "$MIN_DETECT" "$MAX_FP" "$JSON" <<'PY'
import json, sys
from collections import defaultdict

rows = []
for line in open(sys.argv[1]):
    label, js = line.rstrip("\n").split("\t", 1)
    rows.append((label, json.loads(js)))
min_detect, max_fp = float(sys.argv[2]), float(sys.argv[3])
as_json = sys.argv[4] == "1"

families = sorted({l for l, _ in rows if l != "benign"})
per_family = {}
confusion = defaultdict(lambda: defaultdict(int))
for fam in families:
    samples = [r for l, r in rows if l == fam]
    detected = [r for r in samples if r["recognition"]["recognized"]]
    correct = [r for r in detected if r["recognition"].get("family") == fam]
    for r in samples:
        confusion[fam][r["recognition"].get("family") or "(none)"] += 1
    per_family[fam] = {
        "held_out": len(samples),
        "detected": len(detected),
        "detection_rate": len(detected) / len(samples) if samples else 0.0,
        "correct_family": len(correct),
        "attribution_rate": len(correct) / len(detected) if detected else 0.0,
    }

benign = [r for l, r in rows if l == "benign"]
def sev(r): return r["verdict"]["severity"]
benign_stats = {
    "held_out": len(benign),
    "non_clean": sum(sev(r) != "clean" for r in benign),
    "malicious": sum(sev(r) == "malicious" for r in benign),
    "attributed_to_a_family": sum(r["recognition"].get("family") is not None for r in benign),
}

tot = sum(f["held_out"] for f in per_family.values())
det = sum(f["detected"] for f in per_family.values())
cor = sum(f["correct_family"] for f in per_family.values())
overall_detect = det / tot if tot else 0.0
benign_mal_fp = benign_stats["malicious"] / benign_stats["held_out"] if benign_stats["held_out"] else 0.0
passed = overall_detect >= min_detect and benign_mal_fp <= max_fp

report = {
    "families": per_family,
    "confusion": {k: dict(v) for k, v in confusion.items()},
    "benign": benign_stats,
    "overall": {
        "family_samples": tot, "detected": det, "detection_rate": overall_detect,
        "correctly_attributed": cor,
        "attribution_rate": cor / det if det else 0.0,
        "benign_malicious_fp": benign_mal_fp,
    },
    "gate": {"min_detect": min_detect, "max_benign_malicious_fp": max_fp, "passed": passed},
}

if as_json:
    print(json.dumps(report, indent=2))
else:
    print("\n================ labeled-corpus evaluation ================")
    print(f"  {'family':<24} {'held':>5} {'detect':>8} {'attrib':>8}")
    for fam in families:
        f = per_family[fam]
        print(f"  {fam[:24]:<24} {f['held_out']:>5} {f['detection_rate']:>7.1%} {f['attribution_rate']:>7.1%}")
    print(f"  {'— overall —':<24} {tot:>5} {overall_detect:>7.1%} {report['overall']['attribution_rate']:>7.1%}")
    print(f"\n  benign held-out: n={benign_stats['held_out']} · "
          f"non-clean {benign_stats['non_clean']} · malicious {benign_stats['malicious']} · "
          f"mis-attributed {benign_stats['attributed_to_a_family']}")
    # Confusion: only rows with any cross-family leakage.
    leaks = {fam: dict(v) for fam, v in confusion.items()
             if any(k not in (fam, "(none)") for k in v)}
    if leaks:
        print("\n  confusion (held-out family → attributed family):")
        for fam, v in leaks.items():
            cells = " · ".join(f"{k} {n}" for k, n in sorted(v.items(), key=lambda kv: -kv[1]))
            print(f"    {fam}: {cells}")
    print(f"\n{'PASS' if passed else 'FAIL'}: detection {overall_detect:.1%} "
          f"(need >= {min_detect:.0%}), benign malicious-FP {benign_mal_fp:.1%} (need <= {max_fp:.0%})")

sys.exit(0 if passed else 1)
PY
