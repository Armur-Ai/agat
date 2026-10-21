#!/usr/bin/env bash
#
# fetch-benign.sh — extract a real benign x86-64 ELF corpus for bench/run.sh.
#
# Copies the x86-64 ELF executables out of a Debian image's /usr/bin into
# OUT_DIR (default: bench/corpus/debian-bin, which is git-ignored). This is
# the only bench step that needs the network (to pull the image once);
# everything after it runs offline.
#
# --macos instead copies this Mac's own system binaries (/bin, /sbin,
# /usr/bin, /usr/sbin) that carry an x86-64 slice into
# bench/corpus/macos-bin: a second, Mach-O benign corpus. No network.
#
# Usage:
#   bench/fetch-benign.sh [OUT_DIR] [--image debian:12-slim]
#   bench/fetch-benign.sh --macos [OUT_DIR]
#   bench/run.sh --benign-dir bench/corpus/debian-bin
#
# Requires: docker (any engine; the image is pulled as linux/amd64 so the
# binaries are x86-64 even on an arm64 host), tar, file.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT=""
IMAGE="debian:12-slim"
MACOS=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --image) IMAGE="$2"; shift 2 ;;
    --macos) MACOS=1; shift ;;
    -h|--help) grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) OUT="$1"; shift ;;
  esac
done

if [[ "$MACOS" -eq 1 ]]; then
  [[ "$(uname -s)" == "Darwin" ]] || { echo "--macos needs a Mac" >&2; exit 2; }
  OUT="${OUT:-$REPO_ROOT/bench/corpus/macos-bin}"
  mkdir -p "$OUT"
  n=0
  for f in /bin/* /sbin/* /usr/bin/* /usr/sbin/*; do
    [[ -f "$f" && ! -L "$f" && -r "$f" ]] || continue
    if file "$f" 2>/dev/null | grep -q "Mach-O.*x86_64"; then
      cp "$f" "$OUT/$(basename "$f")" 2>/dev/null && n=$((n + 1))
    fi
  done
  echo "copied $n Mach-O binaries with an x86-64 slice into $OUT"
  exit 0
fi
OUT="${OUT:-$REPO_ROOT/bench/corpus/debian-bin}"

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
