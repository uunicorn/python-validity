"""Frame-quality metric study for native MoH enrollment (06cb:00a2).

Question: enroll_moh ranks frames by len(extract_frame_native(...)) to pick
the best 4 of N captures, but on real hardware every frame saturates the
250-keypoint cap (FRAME_KP_CAP), so the ranking is a no-op. Is a threshold
(or a different metric) needed?

Method: take a real captured frame (scripts/enroll_moh_chip.py --dry-run
saves one to /tmp/native_capture_112x112.bin) and degrade it the way bad
placements degrade (partial contact, blur/wet, light press, no finger).
For each variant run the detector front-end (tile -> DoH -> NMS -> subpix
-> edge cull, i.e. extract_frame_native minus the descriptor stages) and
report candidate quality metrics:

  n_pool     uncapped keypoint count (pre-250-cap pool size)
  n_capped   min(n_pool, 250) = what enroll_moh ranks by today
  cap_score  |resp| of the 250th-strongest keypoint (0 if n_pool < 250)
             = "how strong is the weakest keypoint we keep"
  med_score  median |resp| of the kept (top-250) keypoints
  tiles      number of 3x3 tiles contributing >= 5 keypoints (coverage)

Usage: ./.venv-poc/bin/python dev/analyze_frame_quality.py [frame.bin ...]
"""
import sys

import numpy as np

sys.path.insert(0, '.')
from validitysensor.moh_native import (FRAME_KP_CAP, GRID, tile_image,
                                       tile_origin, doh, nms,
                                       subpix_refine_kp,
                                       _a960_passes_global_edge)


def detect_pool(image_q16, h=112, w=112):
    """Phases 1-2 of extract_frame_native, uncapped: the scored keypoint pool
    [(|resp|, tile_id, gx, gy)] after subpix refine + global edge cull."""
    pool = []
    for ti, tj, tile in tile_image(np.asarray(image_q16, dtype=np.int64)):
        _, _, _, resp = doh(tile)
        oy, ox = tile_origin(ti, tj, h, w)
        for score, lx, ly in nms(resp):
            r = subpix_refine_kp(resp, lx, ly)
            if r is None:
                continue
            sx_q16, sy_q16 = r
            if not _a960_passes_global_edge(sx_q16, sy_q16, oy, ox, h, w, ti, tj):
                continue
            pool.append((score, ti * GRID + tj,
                         ((ox << 16) + sx_q16) >> 16,
                         ((oy << 16) + sy_q16) >> 16))
    pool.sort(key=lambda r: -r[0])
    return pool


def metrics(pool):
    kept = pool[:FRAME_KP_CAP]
    scores = [s for s, *_ in kept]
    per_tile = np.bincount([t for _, t, *_ in kept], minlength=GRID * GRID)
    return {
        'n_pool': len(pool),
        'n_capped': len(kept),
        'cap_score': scores[FRAME_KP_CAP - 1] if len(pool) >= FRAME_KP_CAP else 0.0,
        'med_score': float(np.median(scores)) if scores else 0.0,
        'tiles': int((per_tile >= 5).sum()),
    }


def degrade(img):
    """Yield (name, variant) uint8 images simulating bad placements."""
    rng = np.random.default_rng(42)
    yield 'original', img

    # Partial contact: region without finger reads near-uniform background.
    bg = float(np.median(img))
    for name, sl in (('half-right-empty', np.s_[:, 56:]),
                     ('two-thirds-empty', np.s_[:, 38:]),
                     ('bottom-half-empty', np.s_[56:, :])):
        v = img.copy().astype(np.float64)
        region = v[sl]
        v[sl] = bg + rng.normal(0, 2, region.shape)
        yield name, np.clip(v, 0, 255).astype(np.uint8)

    # Blur (wet finger / smear): box blur, growing radius.
    for r in (1, 2, 3):
        v = img.astype(np.float64)
        k = 2 * r + 1
        ker = np.ones(k) / k
        for ax in (0, 1):
            v = np.apply_along_axis(
                lambda m: np.convolve(m, ker, mode='same'), ax, v)
        yield f'blur-r{r}', np.clip(v, 0, 255).astype(np.uint8)

    # Light press: contrast collapse around the mean.
    m = img.mean()
    for c in (0.5, 0.25, 0.1):
        v = (img.astype(np.float64) - m) * c + m
        yield f'contrast-{c}', np.clip(v, 0, 255).astype(np.uint8)

    # No finger at all: background + sensor noise.
    yield 'empty', np.clip(
        bg + rng.normal(0, 2, img.shape), 0, 255).astype(np.uint8)


def main():
    paths = sys.argv[1:] or ['/tmp/native_capture_112x112.bin']
    hdr = f"{'variant':>18} {'n_pool':>6} {'capped':>6} {'cap_score':>9} " \
          f"{'med_score':>9} {'tiles':>5}"
    for path in paths:
        img = np.fromfile(path, dtype=np.uint8).reshape(112, 112)
        print(f'== {path} (min={img.min()} max={img.max()} '
              f'mean={img.mean():.1f} std={img.std():.1f})')
        print(hdr)
        for name, v in degrade(img):
            mm = metrics(detect_pool(v.astype(np.int32) << 16))
            print(f"{name:>18} {mm['n_pool']:>6} {mm['n_capped']:>6} "
                  f"{mm['cap_score']:>9.0f} {mm['med_score']:>9.0f} "
                  f"{mm['tiles']:>5}")
        print()


if __name__ == '__main__':
    main()
