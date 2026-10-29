#!/usr/bin/env bash
# demo/render_crisp.sh — render a VHS tape to a CRISP mp4 that KEEPS the chrome.
#
# Why: VHS 0.12 encodes its mp4 with a fixed, low-quality ffmpeg setting and
# exposes no CRF/bitrate knob, so motion-heavy, colored-text terminal scenes
# blur (low H.264 bitrate + 4:2:0 chroma subsampling). We can't tell VHS to
# encode better, but VHS *does* render pixel-perfect PNG frames of the terminal
# in a headless browser before it encodes. So:
#
#   1. VHS renders normally  -> a native mp4 that carries the window CHROME
#      (margin fill, colorful window bar, rounded corners) but a blurry terminal.
#   2. We harvest VHS's lossless terminal frames (frame-text + frame-cursor).
#   3. We overlay the crisp terminal back onto the native video, landing it in
#      the exact terminal rectangle so the blurry original is fully covered.
#      Result: VHS's chrome + a razor-sharp terminal, re-encoded at CRF 16.
#
# The terminal rectangle is derived from the tape's own Set values:
#   x = Margin + Padding
#   y = Margin + WindowBarSize + Padding
# and the crisp terminal is scaled to the harvested frame size.
#
# Usage: demo/render_crisp.sh <tape> <out.mp4>
set -euo pipefail

TAPE="${1:?usage: render_crisp.sh <tape> <out.mp4>}"
OUT="${2:?usage: render_crisp.sh <tape> <out.mp4>}"

sv() { # read a `Set <Key> <val>` from the tape, with a default
  local key="$1" def="$2" v
  v="$(grep -iE "^Set +${key} " "$TAPE" | awk '{print $3}' | tr -d '"' | tail -1)"
  [ -n "$v" ] && echo "$v" || echo "$def"
}
MARGIN="$(sv Margin 0)"
PADDING="$(sv Padding 20)"
WBS=0
grep -iqE '^Set +WindowBar ' "$TAPE" && WBS="$(sv WindowBarSize 40)"
FR="$(sv Framerate 24)"
X=$(( MARGIN + PADDING ))
Y=$(( MARGIN + WBS + PADDING ))

TD="${TMPDIR:-/tmp}"
KEEP="$(mktemp -d "${TD%/}/crisp.XXXXXX")"
NATIVE="$KEEP/native.mp4"
trap 'rm -rf "$KEEP"' EXIT

# VHS must write an mp4; point it at our native plate regardless of the tape's
# own Output line by overriding with -o.
echo "[render_crisp] rendering (native chrome + frame capture): $TAPE"
before="$(ls -1 "$TD" 2>/dev/null || true)"
vhs "$TAPE" -q -o "$NATIVE" &
VP=$!

fd=""
while kill -0 "$VP" 2>/dev/null; do
  if [ -z "$fd" ]; then
    for c in $(comm -13 <(printf '%s\n' "$before" | sort) \
                        <(ls -1 "$TD" 2>/dev/null | sort) || true); do
      case "$c" in
        vhs[0-9]*) if ls "$TD/$c"/frame-text-*.png >/dev/null 2>&1; then fd="$TD/$c"; break; fi;;
      esac
    done
  fi
  [ -n "$fd" ] && cp "$fd"/frame-text-*.png "$fd"/frame-cursor-*.png "$KEEP"/ 2>/dev/null || true
  sleep 0.25
done
wait "$VP" 2>/dev/null || true
[ -n "$fd" ] && cp "$fd"/frame-text-*.png "$fd"/frame-cursor-*.png "$KEEP"/ 2>/dev/null || true

N="$(ls -1 "$KEEP"/frame-text-*.png 2>/dev/null | wc -l | tr -d ' ')"
echo "[render_crisp] harvested $N terminal frames; terminal origin = ($X,$Y)"
[ "$N" -gt 0 ] || { echo "[render_crisp] ERROR: no frames captured"; exit 1; }

# Composite crisp terminal = cursor overlaid on text, as an image sequence, then
# overlay that stream onto the native (chrome) video at (X,Y), and re-encode.
echo "[render_crisp] compositing crisp terminal over chrome, encoding $OUT (CRF 16, ${FR}fps)"
mkdir -p "$(dirname "$OUT")"
ffmpeg -y -loglevel error \
  -i "$NATIVE" \
  -framerate "$FR" -pattern_type glob -i "$KEEP/frame-text-*.png" \
  -framerate "$FR" -pattern_type glob -i "$KEEP/frame-cursor-*.png" \
  -filter_complex "[1:v][2:v]overlay=0:0[term]; [0:v][term]overlay=${X}:${Y}:format=auto,format=yuv420p[v]" \
  -map "[v]" \
  -c:v libx264 -preset slow -crf 16 -movflags +faststart \
  "$OUT"

echo "[render_crisp] done:"
ffprobe -v error -show_entries stream=width,height,pix_fmt,bit_rate \
  -show_entries format=duration -of default=nw=1 "$OUT" 2>/dev/null || true
ls -la "$OUT"
