#!/usr/bin/env bash
#
# demo/capabilities-setup.sh — stage the two "today, live" immune-capability
# beats for the showcase video:
#
#   * germinal center : a home where a metamorphic family is ingested,
#     analyzed, and the self-model + repertoire are built, but the family is
#     NOT yet matured — so the tape can scan it (all 'review' — the family
#     evades a confident verdict), mature a couple of variants live, and
#     rescan to watch coverage climb (held-out siblings now caught).
#
#   * herd immunity : reuses the fully-trained demo home (demo/run.sh) to
#     export a signed antibody pack; the tape imports it into a fresh,
#     air-gapped home that never trained, and scans — same verdict.
#
# All fixtures are synthetic, inert and deterministic.
#
#   cargo build --release -p agat-cli
#   demo/run.sh                   # the main trained demo home (for export)
#   demo/capabilities-setup.sh    # the germinal home + signing key
#   vhs demo/showcase.tape

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
AGAT="$REPO_ROOT/target/release/agat"
TOOLS="$REPO_ROOT/tools"
export AGAT_VAULT_PASSWORD="agat-demo"

[[ -x "$AGAT" ]] || { echo "build first: cargo build --release -p agat-cli" >&2; exit 1; }

# ---- germinal-center home (trained, un-matured) ---------------------
G="$REPO_ROOT/demo/.work/germinal"
rm -rf "$G"; mkdir -p "$G/variants"
for k in 0x11 0x42 0x7e 0xa5; do
  python3 "$TOOLS/poly_gen.py" "$G/variants/tool_$k.bin" --key "$k" >/dev/null 2>&1
done
python3 "$TOOLS/meta_gen.py" "$G/variants/strain" --count 6 >/dev/null 2>&1
H="$G/home"
"$AGAT" --home "$H" ingest "$G"/variants/*.bin >/dev/null 2>&1
"$AGAT" --home "$H" analyze >/dev/null 2>&1
ids=$("$AGAT" --home "$H" list 2>/dev/null | awk '/tool_/{print $1}' | tr '\n' ' ')
# shellcheck disable=SC2086
"$AGAT" --home "$H" self build $ids >/dev/null 2>&1
"$AGAT" --home "$H" repertoire generate --seed 1 >/dev/null 2>&1
echo "germinal home ready: $H (family 'strain' ingested, NOT matured)"

# ---- herd-immunity signing key (SOC side) ---------------------------
L="$REPO_ROOT/demo/.work/local"
if [[ -d "$L/home" ]]; then
  mkdir -p "$L/keys"
  [[ -f "$L/keys/soc.key" ]] || "$AGAT" --home "$L/home" key generate "$L/keys/soc" --comment soc >/dev/null 2>&1
  echo "signing key ready: $L/keys/soc.key (+ .pub)"
else
  echo "note: run demo/run.sh first so the export home exists" >&2
fi

echo "ready — render with: vhs demo/showcase.tape"
