#!/usr/bin/env python3
"""cv_calibrate.py — run the replayer's CV pipeline against the LIVE
XenClient window for a specific recorded click (by seq), annotate the
haystack, and write a PNG.

Imports input_replayer directly so we share screenshot_window,
cv_match_patch, find_window_by_substring, and map_client. What you
see in the output is byte-for-byte what the replayer would see and
decide for that event — the point is calibration, not reproduction.

Usage (run on RC3):
  python cv_calibrate.py --recording <id> --seq <N> [--out cv_calibrate.png]
"""

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import input_replayer as ir  # noqa: E402  (after sys.path tweak)


def find_event(jsonl_path: str, seq: int):
    with open(jsonl_path, encoding="utf-8") as f:
        for line in f:
            try:
                ev = json.loads(line)
            except Exception:
                continue
            if ev.get("seq") == seq:
                return ev
    return None


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--recording", required=True,
                    help="recording id (e.g. mage-v4-aoe-with-chainblock)")
    ap.add_argument("--seq", type=int, required=True,
                    help="event seq to calibrate against (must have cv_patch)")
    ap.add_argument("--window-title", default="XenepicOnline Revo")
    ap.add_argument("--out", default=None,
                    help="output PNG path (default: cv_calibrate_<seq>.png "
                         "next to this script)")
    ap.add_argument("--top-offset", type=int, default=None,
                    help="vmconnect top toolbar px (default: ch - vm_h)")
    ap.add_argument("--left-offset", type=int, default=0)
    ap.add_argument("--cursor-mask-px", type=int, default=None,
                    help="override CV_CURSOR_MASK_PX for this run "
                         "(zero out NxN at template center to ignore cursor)")
    ap.add_argument("--haystack-png", default=None,
                    help="match against this PNG instead of a live "
                         "screenshot — for offline iteration on a frozen "
                         "frame captured by --cv-debug-dir at HALT time. "
                         "Skips Win32 entirely so this also runs on Mac.")
    ap.add_argument("--grayscale", action="store_true",
                    help="convert haystack and template to grayscale "
                         "before matching — more forgiving when recorder "
                         "and replayer DC sources produce slightly "
                         "different color/gamma but same shapes.")
    ap.add_argument("--template-crop-px", type=int, default=None,
                    help="crop the template's CENTER to NxN before "
                         "matching. Click pixel stays at center, but "
                         "noisy outer surroundings are discarded. "
                         "Useful when the recorded 96x96 patch contains "
                         "state-variant context (dialog body, scene bg) "
                         "that drowns out the click-target signal.")
    args = ap.parse_args()

    base = os.path.dirname(os.path.abspath(__file__))
    jsonl = os.path.join(base, f"recording_{args.recording}.jsonl")
    patches_dir = os.path.join(base, f"recording_{args.recording}_patches")
    manifest = os.path.join(base, f"recording_{args.recording}.manifest.json")
    out_path = args.out or os.path.join(base, f"cv_calibrate_{args.seq}.png")

    with open(manifest, encoding="utf-8") as f:
        m = json.load(f)
    vm_res = m.get("vm_res", {})
    vm_w = int(vm_res.get("w", 1440))
    vm_h = int(vm_res.get("h", 900))

    ev = find_event(jsonl, args.seq)
    if ev is None:
        print(f"[cv-calibrate] seq={args.seq} not found in {jsonl}",
              file=sys.stderr)
        return 1
    if not ev.get("cv_patch"):
        print(f"[cv-calibrate] seq={args.seq} has no cv_patch field",
              file=sys.stderr)
        return 1

    cw, ch = int(ev["cw"]), int(ev["ch"])
    top_offset = args.top_offset if args.top_offset is not None else max(0, ch - vm_h)
    left_offset = args.left_offset

    if args.haystack_png:
        # Offline: skip window lookup, infer dimensions from the PNG.
        win_x = win_y = 0
        # win_w/win_h come from the haystack image itself, not the window.
        # Read it now so map_client has the right size.
        cv2_pre, _np_pre = ir._load_cv2()
        haystack = cv2_pre.imread(args.haystack_png, cv2_pre.IMREAD_COLOR)
        if haystack is None:
            print(f"[cv-calibrate] cannot read haystack PNG: "
                  f"{args.haystack_png}", file=sys.stderr)
            return 1
        win_h, win_w = haystack.shape[:2]
        print(f"[cv-calibrate] OFFLINE haystack={args.haystack_png} "
              f"{win_w}x{win_h} vm_res={vm_w}x{vm_h} top_off={top_offset}")
    else:
        hwnd = ir.find_window_by_substring(args.window_title)
        if hwnd is None:
            print(f"[cv-calibrate] window '{args.window_title}' not found",
                  file=sys.stderr)
            ir.log_window_candidates(args.window_title)
            return 1
        win_x, win_y, win_w, win_h = ir.get_window_client_rect_screen(hwnd)
        print(f"[cv-calibrate] hwnd=0x{hwnd:X} client=({win_x},{win_y}) "
              f"{win_w}x{win_h} vm_res={vm_w}x{vm_h} top_off={top_offset}")
        haystack = None  # captured below via screenshot_window

    rec_cx, rec_cy = ir.map_client(
        ev["fx"], ev["fy"], cw, ch,
        vm_w, vm_h, win_w, win_h, top_offset, left_offset,
    )
    patch_path = os.path.join(patches_dir, ev["cv_patch"])
    if not os.path.isfile(patch_path):
        print(f"[cv-calibrate] missing patch: {patch_path}", file=sys.stderr)
        return 1

    cv2, np = ir._load_cv2()

    # Use the replayer's exact decision function — cv_match_in_haystack —
    # so the click target shown is what the replayer would actually use.
    # Re-run matchTemplate ourselves below only to surface the score grid
    # for top-N annotations.
    if haystack is None:
        haystack = ir.screenshot_window(hwnd)
    template = cv2.imread(patch_path, cv2.IMREAD_COLOR)
    if args.grayscale:
        haystack = cv2.cvtColor(haystack, cv2.COLOR_BGR2GRAY)
        template = cv2.cvtColor(template, cv2.COLOR_BGR2GRAY)
        # cv_match_in_haystack expects 3D BGR. Re-stack to 3 channels so
        # matchTemplate sees a consistent format. (Conversion to gray
        # already collapsed any color drift; the 3-channel wrap is just
        # to keep cv_match_in_haystack's mask broadcasting happy.)
        haystack = cv2.cvtColor(haystack, cv2.COLOR_GRAY2BGR)
        template = cv2.cvtColor(template, cv2.COLOR_GRAY2BGR)
    # Default: mirror the replayer's CV_TEMPLATE_CROP_PX so calibration
    # reflects production behavior. Override with --template-crop-px to
    # sweep alternatives.
    crop_px = (args.template_crop_px
               if args.template_crop_px is not None
               else ir.CV_TEMPLATE_CROP_PX)
    if crop_px and crop_px < template.shape[0]:
        crop = max(8, min(crop_px, template.shape[0]))
        c = template.shape[0] // 2
        half = crop // 2
        template = template[c - half:c + half, c - half:c + half].copy()
        if ir.CV_CURSOR_MASK_PX >= crop:
            ir.CV_CURSOR_MASK_PX = max(0, crop - 8)
        print(f"[cv-calibrate] template cropped to {crop}x{crop} "
              f"(cursor_mask={ir.CV_CURSOR_MASK_PX})")
    th, tw = template.shape[:2]
    half_tw, half_th = tw // 2, th // 2
    threshold = ir.CV_MATCH_THRESHOLD

    # Allow per-run override of cursor mask size — for sweeping during
    # calibration without touching the replayer's constant.
    if args.cursor_mask_px is not None:
        ir.CV_CURSOR_MASK_PX = args.cursor_mask_px
    cmpx = ir.CV_CURSOR_MASK_PX

    ok, score, mcx, mcy = ir.cv_match_in_haystack(
        haystack, template, rec_cx, rec_cy, threshold)

    # Build the same score grid for top-5 annotation (uses the override
    # value via cmpx, kept in sync with cv_match_in_haystack).
    mask = np.full((th, tw), 255, dtype=np.uint8)
    mask[half_th - cmpx // 2:half_th + cmpx // 2,
         half_tw - cmpx // 2:half_tw + cmpx // 2] = 0
    res = cv2.matchTemplate(haystack, template, cv2.TM_CCOEFF_NORMED, mask=mask)

    # Annotate ON the same haystack the replayer used.
    ann = haystack.copy()
    # Recorded coord: red 96x96 box + center dot.
    cv2.rectangle(ann, (rec_cx - 48, rec_cy - 48),
                  (rec_cx + 48, rec_cy + 48), (0, 0, 255), 2)
    cv2.circle(ann, (rec_cx, rec_cy), 5, (0, 0, 255), -1)
    cv2.putText(ann, f"recorded ({rec_cx},{rec_cy})",
                (rec_cx + 55, rec_cy + 8),
                cv2.FONT_HERSHEY_SIMPLEX, 0.5, (0, 0, 255), 2)
    # Decided match: green if >=threshold, orange if below.
    color = (0, 255, 0) if ok else (0, 165, 255)
    cv2.rectangle(ann, (mcx - 48, mcy - 48),
                  (mcx + 48, mcy + 48), color, 2)
    cv2.circle(ann, (mcx, mcy), 5, color, -1)
    verdict = "OK" if ok else f"BELOW {threshold:.2f}"
    cv2.putText(ann,
                f"{verdict} score={score:.3f} ({mcx},{mcy}) "
                f"shift=({mcx - rec_cx},{mcy - rec_cy})",
                (mcx + 55, mcy - 50),
                cv2.FONT_HERSHEY_SIMPLEX, 0.5, color, 2)
    # Top-5 peaks for context (yellow circles).
    flat = res.ravel()
    if flat.size:
        topk = min(5, flat.size)
        idx = np.argpartition(flat, -topk)[-topk:]
        idx = idx[np.argsort(-flat[idx])]
        for rank, i_flat in enumerate(idx, start=1):
            y = int(i_flat // res.shape[1])
            x = int(i_flat % res.shape[1])
            s = float(flat[i_flat])
            cx2 = x + half_tw
            cy2 = y + half_th
            cv2.circle(ann, (cx2, cy2), 8, (0, 255, 255), 1)
            cv2.putText(ann, f"#{rank}:{s:.2f}",
                        (cx2 + 10, cy2 + 5),
                        cv2.FONT_HERSHEY_SIMPLEX, 0.4, (0, 255, 255), 1)
    # Header strip: seq, threshold, recording id.
    cv2.putText(ann,
                f"seq={args.seq} rec={args.recording} thr={threshold:.2f} "
                f"client={win_w}x{win_h}",
                (10, 22),
                cv2.FONT_HERSHEY_SIMPLEX, 0.55, (255, 255, 255), 2)

    cv2.imwrite(out_path, ann)
    print(f"[cv-calibrate] ok={ok} score={score:.3f} "
          f"click=({mcx},{mcy}) recorded=({rec_cx},{rec_cy}) "
          f"shift=({mcx - rec_cx},{mcy - rec_cy})")
    print(f"[cv-calibrate] wrote {out_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
