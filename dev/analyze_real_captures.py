"""Frame-quality metrics on REAL enrollment captures (06cb:00a2).

Companion to dev/analyze_frame_quality.py (which uses one real frame +
synthetic degradations). This one mines the gdb capture dumps from real
Wine-driver enrollments in /media/sf_vbox-rw/finger/frida_dumps:

1. f250_raw_tile_<ts>_call<NNN>_<H>x<W>.bin — the raw Q16 working-image
   tiles at the pre-smooth entry. 18 calls per placement (the pre-smooth
   runs twice per tile: DoH chain + descriptor-gradient chain), 9 tiles
   per frame, column-major (i = call%3, j = call//3). 144 calls = one
   real 8-placement enrollment. We run OUR detector front-end per tile
   and report the same metrics as analyze_frame_quality.py — this is the
   real-data answer to "do healthy frames always saturate the 250 cap,
   and what does the pool/score distribution look like?"

2. minutia_table_<ts>_250.bin — the DLL's in-memory 250 x 32-byte
   keypoint table per frame (3 sessions x 8-9 frames). Fields (RE'd):
   +0x8 active flag, +0x9 tile id, +0xa quality byte. We report the
   DLL's own active-count per frame for comparison.

Usage: ./.venv-poc/bin/python dev/analyze_real_captures.py [dump_dir]
"""
import glob
import os
import re
import sys
from collections import defaultdict

import numpy as np

sys.path.insert(0, '.')
from validitysensor.moh_native import FRAME_KP_CAP
from dev.analyze_frame_quality import metrics

from validitysensor.moh_native import (GRID, tile_origin, doh, nms,
                                       subpix_refine_kp,
                                       _a960_passes_global_edge)

DUMPS = '/media/sf_vbox-rw/finger/frida_dumps'


def tile_pool(tile_q16, i, j, h=112, w=112):
    """detect_pool for ONE captured tile (origin-aware edge cull)."""
    _, _, _, resp = doh(tile_q16)
    oy, ox = tile_origin(i, j, h, w)
    out = []
    for score, lx, ly in nms(resp):
        r = subpix_refine_kp(resp, lx, ly)
        if r is None:
            continue
        sx_q16, sy_q16 = r
        if not _a960_passes_global_edge(sx_q16, sy_q16, oy, ox, h, w, i, j):
            continue
        out.append((score, i * GRID + j,
                    ((ox << 16) + sx_q16) >> 16,
                    ((oy << 16) + sy_q16) >> 16))
    return out


def analyze_tiles(dump_dir):
    pat = re.compile(r'f250_raw_tile_(\d+)_call(\d+)_(\d+)x(\d+)\.bin$')
    frames = defaultdict(dict)   # frame_no -> {(i,j): tile}
    for p in sorted(glob.glob(os.path.join(dump_dir, 'f250_raw_tile_*.bin'))):
        m = pat.search(p)
        if not m:
            continue
        _, call, hh, ww = (int(g) for g in m.groups())
        idx = call % 18
        if idx >= 9:            # 2nd pre-smooth invocation: same tile data
            continue
        i, j = idx % 3, idx // 3   # column-major capture order
        tile = np.fromfile(p, dtype=np.int32).reshape(hh, ww)
        frames[call // 18][(i, j)] = tile

    if not frames:
        print('no f250_raw_tile dumps found')
        return
    print(f'== real enrollment tiles: {len(frames)} frames '
          f'({dump_dir}/f250_raw_tile_*)')
    print(f"{'frame':>5} {'n_pool':>6} {'capped':>6} {'cap_score':>9} "
          f"{'med_score':>9} {'tiles':>5}")
    for fno in sorted(frames):
        pool = []
        for (i, j), tile in sorted(frames[fno].items()):
            pool.extend(tile_pool(tile, i, j))
        pool.sort(key=lambda r: -r[0])
        mm = metrics(pool)
        print(f"{fno:>5} {mm['n_pool']:>6} {mm['n_capped']:>6} "
              f"{mm['cap_score']:>9.0f} {mm['med_score']:>9.0f} "
              f"{mm['tiles']:>5}")
    print()


def analyze_minutia_tables(dump_dir):
    files = sorted(glob.glob(os.path.join(dump_dir, 'minutia_table_*_250.bin')))
    if not files:
        print('no minutia_table dumps found')
        return
    print(f'== DLL minutia tables ({len(files)} frames, 3 sessions): '
          'per-frame ACTIVE counts + quality')
    print(f"{'session':>10} {'frame_ts':>13} {'active':>6} "
          f"{'qual med':>8} {'qual max':>8}")
    for p in files:
        ts = int(re.search(r'minutia_table_(\d+)_250', p).group(1))
        recs = np.fromfile(p, dtype=np.uint8).reshape(250, 32)
        active = recs[:, 0x8] == 1
        qual = recs[active, 0xa]
        print(f"{str(ts)[:6]:>10} {ts:>13} {int(active.sum()):>6} "
              f"{float(np.median(qual)) if qual.size else 0:>8.0f} "
              f"{int(qual.max()) if qual.size else 0:>8}")
    print()


if __name__ == '__main__':
    d = sys.argv[1] if len(sys.argv) > 1 else DUMPS
    analyze_minutia_tables(d)
    analyze_tiles(d)
