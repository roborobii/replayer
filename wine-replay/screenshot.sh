#!/bin/bash
# Capture just the wine'd game's client area (no macOS shadow / title bar)
# at native 1440x975 — pixel coords map 1:1 to recorded click coords.
#
# Adapted from ~/proj/server-emulator-python3/tools/screenshot.sh, which
# screenshotted an older client. Differences:
#   - matches title "XenepicOnline" (new client) instead of "Secret"
#   - resizes to 1440x975 (recording cw×ch) instead of 1024x768
#
# Usage: ./screenshot.sh [output_path]
OUT="${1:-/tmp/game_client.png}"

python3 -c "
import Quartz
from PIL import Image
import numpy as np
import subprocess, os, sys

windows = Quartz.CGWindowListCopyWindowInfo(
    Quartz.kCGWindowListOptionOnScreenOnly, Quartz.kCGNullWindowID)

# Match game window: title contains 'XenepicOnline' or 'Xenepic',
# fallback to largest wine-owned window.
wid = None
for w in windows:
    name = str(w.get('kCGWindowName', ''))
    if 'Xenepic' in name and float(w['kCGWindowBounds']['Width']) > 100:
        wid = w['kCGWindowNumber']
        break
if not wid:
    best = None
    for w in windows:
        owner = str(w.get('kCGWindowOwnerName', '')).lower()
        if 'wine' in owner or 'xenclient' in owner or 'dxrender' in owner:
            bounds = w.get('kCGWindowBounds', {})
            ww = float(bounds.get('Width', 0))
            if ww >= 900:
                if best is None or ww > float(best['kCGWindowBounds']['Width']):
                    best = w
    if best:
        wid = best['kCGWindowNumber']

if not wid:
    print('ERROR: game window not found', file=sys.stderr)
    sys.exit(1)

tmp = '/tmp/_raw_xen_window.png'
subprocess.run(['screencapture', '-x', '-l', str(wid), tmp], check=True)

img = Image.open(tmp)
arr = np.array(img)

# Trim macOS shadow: keep only opaque rectangle.
alpha = arr[:, :, 3]
row_opaque = (alpha > 250).sum(axis=1)
col_opaque = (alpha > 250).sum(axis=0)

top = left = 0
for r in range(len(row_opaque)):
    if row_opaque[r] > 1000:
        top = r; break
for c in range(len(col_opaque)):
    if col_opaque[c] > 700:
        left = c; break
right = left
for c in range(len(col_opaque) - 1, left, -1):
    if col_opaque[c] > 700:
        right = c + 1; break
bottom = top
for r in range(len(row_opaque) - 1, top, -1):
    if row_opaque[r] > 1000:
        bottom = r + 1; break

# Skip native title bar (28 logical px, scaled for Retina).
scale_factor = round((right - left) / 1440) or 1
titlebar_px = 28 * scale_factor
client = img.crop((left, top + titlebar_px, right, bottom)).convert('RGB')

# Resize to recording native client size.
client = client.resize((1440, 975), Image.LANCZOS)
client.save('$OUT', 'PNG')
os.remove(tmp)
print(f'Saved {client.size[0]}x{client.size[1]} -> $OUT')
"
echo "$OUT"
