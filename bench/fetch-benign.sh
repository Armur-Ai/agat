#!/usr/bin/env bash
#
# fetch-benign.sh — extract a real benign x86-64 ELF corpus for bench/run.sh.
#
# Copies the x86-64 ELF executables out of a Debian image's /usr/bin into
# OUT_DIR (default: bench/corpus/debian-bin, which is git-ignored). This is
# the only bench step that needs the network (to pull the image once);
# everything after it runs offline.
#
# Usage:
#   bench/fetch-benign.sh [OUT_DIR] [--image debian:12-slim]
#   bench/run.sh --benign-dir bench/corpus/debian-bin
#
# Requires: docker (any engine; the image is pulled as linux/amd64 so the
# binaries are x86-64 even on an arm64 host), tar, file.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="$REPO_ROOT/bench/corpus/debian-bin"
IMAGE="debian:12-slim"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --image) IMAGE="$2"; shift 2 ;;
    -h|--help) grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) OUT="$1"; shift ;;
  esac
done

STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"; [[ -n "${CID:-}" ]] && docker rm "$CID" >/dev/null 2>&1 || true' EXIT

CID="$(docker create --platform linux/amd64 "$IMAGE")"
docker cp "$CID:/usr/bin" - | tar -x -C "$STAGE"

mkdir -p "$OUT"
n=0
for f in "$STAGE"/bin/*; do
  [[ -f "$f" && ! -L "$f" ]] || continue
  if file "$f" | grep -q "ELF 64-bit LSB.*x86-64"; then
    cp "$f" "$OUT/"; n=$((n + 1))
  fi
done
echo "extracted $n x86-64 ELF binaries from $IMAGE into $OUT"
