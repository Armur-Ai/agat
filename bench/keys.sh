#!/usr/bin/env bash
#
# keys.sh — key-recovery benchmark for register-held and multi-byte keys.
#
# Generates N decryptor-stub ELFs per key length with random keys held in
# a register and rotated each byte (tools/poly_gen.py --rolling-key), so
# no key appears as an immediate operand. agat must recover the EXACT key
# by cryptanalysis of the ciphertext (agat_poly::solve). A near-miss key
# counts as a failure: it would corrupt the plaintext fingerprint.
#
# --stress DIR additionally runs the solver WITHOUT the analyzer's
# decryptor-loop gate, under every operation, on every non-executable
# section of every benign binary in DIR (e.g. bench/corpus/debian-bin).
# Any key accepted there is a false positive of the acceptance rule.
#
# Exit 0 if every key is recovered exactly (and, with --stress, no key is
# accepted on the benign corpus), 1 otherwise.
#
# Usage: bench/keys.sh [--per-length N] [--payload-size B] [--stress DIR]
#                      [--agat PATH] [--seed S]

set -euo pipefail

PER=10
SIZE=1024
STRESS=""
AGAT=""
SEED=7
while [[ $# -gt 0 ]]; do
  case "$1" in
    --per-length) PER="$2"; shift 2 ;;
    --agat)       AGAT="$2"; shift 2 ;;
    --seed)       SEED="$2"; shift 2 ;;
    --payload-size) SIZE="$2"; shift 2 ;;
    --stress)     STRESS="$2"; shift 2 ;;
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
trap 'rm -rf "$WORK"' EXIT
export AGAT_VAULT_PASSWORD="keys-$$"

python3 - "$WORK" "$PER" "$SEED" "$SIZE" <<'PY'
import random, subprocess, sys
work, per, seed, size = sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), sys.argv[4]
rng = random.Random(seed)
with open(f"{work}/expected.tsv", "w") as out:
    for length in (1, 2, 4, 8):
        for i in range(per):
            key = bytes(rng.randrange(1, 256) for _ in range(length))
            name = f"k{length}_{i}.bin"
            subprocess.run(["python3", "tools/poly_gen.py", f"{work}/{name}",
                            "--rolling-key", key.hex(), "--seed", str(rng.randrange(10**6)),
                            "--payload-size", size],
                           check=True, stdout=subprocess.DEVNULL)
            out.write(f"{name}\t{key.hex()}\n")
PY

"$AGAT" --home "$WORK/home" ingest "$WORK"/*.bin >/dev/null 2>&1
"$AGAT" --home "$WORK/home" analyze >/dev/null 2>&1
"$AGAT" --home "$WORK/home" list 2>/dev/null | awk 'NR>1 {print $1 "\t" $NF}' > "$WORK/ids.tsv"

while IFS=$'\t' read -r id name; do
  got="$("$AGAT" --home "$WORK/home" show "$id" --poly 2>/dev/null \
         | sed -n 's/.*with key 0x\([0-9a-f]*\).*/\1/p')"
  printf '%s\t%s\n' "$name" "${got:--}"
done < "$WORK/ids.tsv" > "$WORK/got.tsv"

RESULT=0
python3 - "$WORK/expected.tsv" "$WORK/got.tsv" "$SIZE" <<'PY' || RESULT=1
import sys
exp = dict(l.split("\t") for l in open(sys.argv[1]).read().split("\n") if l)
got = dict(l.split("\t") for l in open(sys.argv[2]).read().split("\n") if l)
by_len = {}
for name, key in exp.items():
    L = len(key) // 2
    ok = got.get(name) == key
    by_len.setdefault(L, [0, 0])
    by_len[L][0] += ok
    by_len[L][1] += 1
    if not ok:
        print(f"  miss: {name} expected {key} got {got.get(name)}")
total_ok = sum(v[0] for v in by_len.values()); total = sum(v[1] for v in by_len.values())
print("\n================ register-held key recovery ================")
print(f"  payload {sys.argv[3]} bytes")
for L in sorted(by_len):
    ok, n = by_len[L]
    print(f"  {L}-byte keys   {ok}/{n} exact")
print(f"\n{'PASS' if total_ok == total else 'FAIL'}: {total_ok}/{total} keys recovered exactly")
sys.exit(0 if total_ok == total else 1)
PY

if [[ -n "$STRESS" ]]; then
  echo
  echo "================ false-positive stress: $STRESS ================"
  line="$(cargo run -q --release -p agat-poly --example solve_corpus -- "$STRESS" | tail -1)"
  echo "  $line"
  accepted="$(awk '{print $(NF-2)}' <<<"$line")"
  if [[ "$accepted" != "0" ]]; then
    echo "FAIL: the solver accepted $accepted key(s) on benign binaries"
    RESULT=1
  else
    echo "PASS: no key accepted on benign binaries"
  fi
fi
exit "$RESULT"
