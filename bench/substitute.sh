#!/usr/bin/env bash
#
# substitute.sh — recognition across instruction substitution.
#
# Metamorphic engines swap instructions for equivalents (inc ↔ add 1 ↔
# lea +1, xor r,r ↔ mov r,0, mov r,imm ↔ push imm; pop r). This benchmark
# builds all 54 such variants of one decryptor (tools/meta_gen.py
# --substitute), then:
#
#   1. checks they collapse to ONE canonical CFG fingerprint,
#   2. trains the family memory on --train of them (default 6), and
#   3. scans the remaining held-out variants statelessly: each must come
#      back non-self AND attributed to the family.
#
# Exit 0 if all variants share one fingerprint and every held-out
# variant is recognized, 1 otherwise.
#
# Usage: bench/substitute.sh [--train N] [--agat PATH] [--keep]

set -euo pipefail

TRAIN=6
AGAT=""
KEEP=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --train) TRAIN="$2"; shift 2 ;;
    --agat)  AGAT="$2"; shift 2 ;;
    --keep)  KEEP=1; shift ;;
    -h|--help) grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"
if [[ -z "$AGAT" ]]; then
  for c in ./target/release/agat ./target/debug/agat; do [[ -x "$c" ]] && { AGAT="$c"; break; }; done
  [[ -n "$AGAT" ]] || { cargo build -q --release -p agat-cli; AGAT=./target/release/agat; }
fi

WORK="$(mktemp -d)"
cleanup() { [[ "$KEEP" -eq 1 ]] && echo "kept $WORK" >&2 || rm -rf "$WORK"; }
trap cleanup EXIT
export AGAT_VAULT_PASSWORD="subst-$$"
agat() { "$AGAT" --home "$WORK/home" "$@"; }
mkdir -p "$WORK/train" "$WORK/heldout"

for k in 0x11 0x42 0x7e 0xa5; do
  python3 tools/poly_gen.py "$WORK/train/benign_$k.bin" --key "$k" >/dev/null
done
python3 tools/meta_gen.py "$WORK/sub" --substitute 54 >/dev/null
for i in $(seq 1 54); do
  if [[ "$i" -le "$TRAIN" ]]; then mv "$WORK/sub_s$i.bin" "$WORK/train/"
  else mv "$WORK/sub_s$i.bin" "$WORK/heldout/"; fi
done

agat ingest "$WORK"/train/*.bin "$WORK"/heldout/*.bin >/dev/null 2>&1
agat analyze >/dev/null 2>&1
FINGERPRINTS=$(agat cluster 2>/dev/null | grep -c "sub_s" || true)
FAMILIES=$(agat cluster 2>/dev/null | awk '/^(family|singleton)/{f=$0} /sub_s/{print f}' | sort -u | wc -l | tr -d ' ')

LISTING="$(agat list 2>/dev/null)"
id_of() { awk -v f="$1" '$NF==f {print $1}' <<<"$LISTING"; }
agat self build $(for k in 0x11 0x42 0x7e 0xa5; do id_of "benign_$k.bin"; done) >/dev/null
agat repertoire generate --seed 1 >/dev/null
for i in $(seq 1 "$TRAIN"); do agat mature "$(id_of "sub_s$i.bin")" --family substituted >/dev/null; done

unset AGAT_VAULT_PASSWORD
agat scan "$WORK/heldout" --json --fail-on never 2>/dev/null </dev/null > "$WORK/heldout.json"

python3 - "$WORK/heldout.json" "$FINGERPRINTS" "$FAMILIES" "$TRAIN" <<'PY'
import json, sys
rs = json.load(open(sys.argv[1]))
variants, groups, train = int(sys.argv[2]), int(sys.argv[3]), int(sys.argv[4])
hit = [r for r in rs if r["recognition"]["recognized"] and r["recognition"].get("family") == "substituted"]
aff = sorted(r["recognition"]["affinity"] for r in hit)
print("\n================ instruction substitution ================")
print(f"  variants                      {variants}")
print(f"  distinct CFG fingerprints     {groups}   (must be 1)")
print(f"  trained on                    {train}")
print(f"  held-out recognized + family  {len(hit)}/{len(rs)}")
if aff:
    print(f"  affinity                      min {aff[0]:.3f} · median {aff[len(aff)//2]:.3f}")
ok = groups == 1 and len(hit) == len(rs)
print(f"\n{'PASS' if ok else 'FAIL'}")
sys.exit(0 if ok else 1)
PY
