#!/usr/bin/env bash
# X11/Xvfb screenshot helper. Replaces wine-replay/screenshot.sh (macOS Quartz).
# Usage: screenshot-x11.sh /path/to/out.png
# Exits 0 on success, prints output path. dom_driver.py invokes this when
# CV-matching recorded patches against the live wine window.
set -euo pipefail

OUT="${1:?usage: $0 <out.png>}"
export DISPLAY="${DISPLAY:-:99}"

WID=""
for pat in Xenepic XenClient DXRender; do
  found="$(xdotool search --name "$pat" 2>/dev/null | head -n1 || true)"
  if [[ -n "$found" ]]; then
    WID="$found"
    break
  fi
done

if [[ -n "$WID" ]]; then
  import -window "$WID" "$OUT"
else
  # Xvfb hosts only the wine window, so the root framebuffer is fine.
  import -window root "$OUT"
fi

echo "$OUT"
