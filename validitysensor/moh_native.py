"""Native MoH feature pipeline (06cb:00a2) — image → v30 path.

This is the **float / native-Python** variant of the pipeline. It is the same
algorithm the Windows DLL runs (reverse-engineered from the synaWudfBioUsb
driver DLL), but the bit-exact x86 fixed-point emulation has been replaced
with ordinary floating-point math:

    working image (112²)
      → 3×3 grid of 57×57 tiles (mid-gray pad)          [tile_image]
      → per tile: Determinant-of-Hessian response       [doh]
      → 8-neighbour NMS → keypoints                      [nms]
      → subpixel refine (Hessian-Newton, cull failures) [subpix_refine_kp]
      → orientation (Gaussian-weighted grad histogram)   [orient_d920]
      → oriented BRIEF descriptor                        [_descriptor_at]
      → [16-byte desc][x][y] × 250 → v30                 [serialize_v30_section]

NOTE: the math here is intentionally NOT byte-exact with the DLL. The chip-side
matcher is a Hough geometric-voting / relative-argmax scheme with no fixed
threshold, so small numeric drift in the descriptor pipeline is tolerable
(confirmed on hardware: enroll + recognize work).

The byte-format / framing functions at the bottom (serialize_v30_section,
merge, scaffold, TID, envelope) are pure format/data, not arithmetic — the
chip parses them literally.
"""
from __future__ import annotations

import hashlib
import hmac
import math
from struct import pack

import numpy as np

TWO_PI = 2.0 * math.pi

# ─── geometry (decoded from orchestrator sub_18000AAB0) ─────────────────
GRID = 3                  # 3×3 tiles
GRID_X = 10               # overlap half-width (v13 = 2*GRID_X = 20 total)
FILL = 0x800000           # Q16 mid-gray pad (= 128 << 16). Tiles carry the
                          # image in Q16; padding outside the frame is mid-gray.
                          # Every consumer divides by 65536, so the pad becomes
                          # the natural value 128.0.


def tile_origin(i, j, h, w):
    """Top-left (row, col) of tile (i,j). step = h/GRID; origin = i*step - GRID_X."""
    return i * (h // GRID) - GRID_X, j * (w // GRID) - GRID_X


def tile_size(i, j, h, w):
    """Per-tile (height, width). The last row/col absorbs the dim-vs-GRID
    remainder, so for the 112-px frame the col-2 and row-2 tiles are 58 while
    inner tiles are 57."""
    step_y = h // GRID
    step_x = w // GRID
    th = (h - (GRID - 1) * step_y) + 2 * GRID_X if i == GRID - 1 else step_y + 2 * GRID_X
    tw = (w - (GRID - 1) * step_x) + 2 * GRID_X if j == GRID - 1 else step_x + 2 * GRID_X
    return th, tw


def tile_image(img):
    """Yield (i, j, tile) for the 3×3 grid, mid-gray padded where it falls
    outside the image (matches the DLL's sub_18000A850 blit + pad)."""
    h, w = img.shape
    for i in range(GRID):
        for j in range(GRID):
            oy, ox = tile_origin(i, j, h, w)
            th, tw = tile_size(i, j, h, w)
            tile = np.full((th, tw), FILL, dtype=img.dtype)
            sy0, sx0 = max(0, oy), max(0, ox)
            sy1, sx1 = min(h, oy + th), min(w, ox + tw)
            if sy1 > sy0 and sx1 > sx0:
                tile[sy0 - oy:sy1 - oy, sx0 - ox:sx1 - ox] = img[sy0:sy1, sx0:sx1]
            yield i, j, tile


# ─── orientation weighting (dword_180120C00, dumped from the DLL) ────────
# 7×7 quarter of a 13×13 window; weight[dy][dx] = GAUSS_Q[|dy|][|dx|]. Kept as
# data (it is the DLL's learned spatial weighting, not arithmetic).
GAUSS_Q = np.array([
    [1669, 1541, 1212, 812, 464, 226, 94],
    [1541, 1422, 1119, 750, 428, 208, 86],
    [1212, 1119,  880, 590, 337, 164, 68],
    [ 812,  750,  590, 395, 226, 110, 46],
    [ 464,  428,  337, 226, 129,  63, 26],
    [ 226,  208,  164, 110,  63,  31, 13],
    [  94,   86,   68,  46,  26,  13,  0],
], dtype=np.float64)


# ─── separable convolution kernels (native float) ──────────────────────
# DERIV_3TAP: central difference; SMOOTH_3TAP: unity [1,2,1]/4 smoother. These
# replace the DLL's sub_180010280 magic-constant 3-tap builder.
DERIV_3TAP = [(-1, 1.0), (0, 0.0), (1, -1.0)]
SMOOTH_3TAP = [(-1, 0.25), (0, 0.5), (1, 0.25)]


def build_gaussian(n=5):
    """Unity-normalized 1-D Gaussian as [(offset, tap)]. sigma comes from the
    DLL's size→sigma relation (≈1.10 px for n=5); the bit-exact EXP_TABLE LUT
    is replaced by a real exp()."""
    sigma = (0x26600 * n + 0x59acd) / float(1 << 20)   # ≈ 1.102 for n = 5
    half = n // 2
    xs = np.arange(n) - half
    g = np.exp(-(xs ** 2) / (2.0 * sigma * sigma))
    g = g / g.sum()
    return [(i - half, float(g[i])) for i in range(n)]


def _conv_axis(img, kernel, axis, fill=None):
    """Separable 1-D convolution along `axis`. `kernel` = [(offset, tap), …].
    fill=None → replicate-clamp borders; fill=v → out-of-bounds reads = v
    (the DLL fills off-tile reads with 0 in the descriptor-gradient path)."""
    n = img.shape[axis]
    idx = np.arange(n)
    acc = np.zeros(img.shape, dtype=np.float64)
    for off, tap in kernel:
        if tap == 0:
            continue
        src_idx = idx - off
        clipped = np.clip(src_idx, 0, n - 1)
        vals = np.take(img, clipped, axis=axis).astype(np.float64)
        if fill is not None:
            in_bounds = (src_idx >= 0) & (src_idx < n)
            shape = [1] * img.ndim
            shape[axis] = -1
            vals = np.where(in_bounds.reshape(shape), vals, float(fill))
        acc += vals * tap
    return acc


def apply_sep(img, kx, ky, fill=None):
    """Apply kx along x (axis 1) then ky along y (axis 0)."""
    return _conv_axis(_conv_axis(img, kx, 1, fill=fill), ky, 0, fill=fill)


# ─── DoH detector ───────────────────────────────────────────────────────
# response = Ixx·Iyy − Ixy² of the pre-smoothed image, in natural pixel units,
# rescaled by RESP_SCALE so the NMS thresholds (t_lo/t_hi) — which were tuned
# to the DLL's fixed-point response magnitude — still apply. RESP_SCALE was
# fit by least-squares against the DLL's fixed-point doh() on synthetic tiles
# (median 17.04, std/mean 2.4%).
RESP_SCALE = 17.04


def presmooth(tile_q16, size=5):
    """Gaussian pre-smooth of a Q16 tile → natural-units float image
    (replicate-clamp borders), matching the DoH front-end."""
    img = np.asarray(tile_q16, dtype=np.float64) / 65536.0
    gk = build_gaussian(size)
    return apply_sep(img, gk, gk)


def doh(tile_q16, size=5):
    """Determinant-of-Hessian on a Q16 tile → (Ixx, Iyy, Ixy, response).
    response = (Ixx·Iyy − Ixy²)·RESP_SCALE."""
    sm = presmooth(tile_q16, size)
    Dx = apply_sep(sm, DERIV_3TAP, SMOOTH_3TAP)
    Dy = apply_sep(sm, SMOOTH_3TAP, DERIV_3TAP)
    Ixx = apply_sep(Dx, DERIV_3TAP, SMOOTH_3TAP)
    Iyy = apply_sep(Dy, SMOOTH_3TAP, DERIV_3TAP)
    Ixy = apply_sep(Dx, SMOOTH_3TAP, DERIV_3TAP)
    resp = (Ixx * Iyy - Ixy ** 2) * RESP_SCALE
    return Ixx, Iyy, Ixy, resp


# ─── keypoints — NMS (sub_18000CF90) ─────────────────────────────────────
def nms(resp, t_lo=671, t_hi=168, dedup_q=72064, margin=10):
    """8-neighbour non-maximum suppression on the response map. A pixel is a
    keypoint iff `resp > t_lo`, `resp >= t_hi`, and strictly greater than all 8
    neighbours; score = |resp|. Returns `(score, x, y)` in raster-scan order.

    Both thresholds are kept separate for parity with the DLL's NMS
    (sub_18000CF90), even though t_hi < t_lo makes the second test redundant
    at the default values."""
    h, w = resp.shape
    r2 = ((dedup_q >> 6) ** 2) >> 20
    kps = []   # (score, x, y)
    for y in range(margin, h - margin):
        for x in range(margin, w - margin):
            v = float(resp[y, x])
            if v <= t_lo or v < t_hi:
                continue
            nb = resp[y - 1:y + 2, x - 1:x + 2]
            nbmax = float(nb.max())
            if v <= nbmax and not (v == nbmax and int((nb == v).sum()) == 1):
                continue
            s = abs(v)
            dup = next((i for i, (_, kx, ky) in enumerate(kps)
                        if (kx - x) ** 2 + (ky - y) ** 2 <= r2), None)
            if dup is None:
                kps.append((s, x, y))
            elif s > kps[dup][0]:
                kps[dup] = (s, x, y)
    return kps


# ─── subpixel refinement — Hessian-Newton on the response map ────────────
# Replaces the DLL's bit-exact Cramer/SAR solver (sub_18000D4C0 / D5D0) with a
# standard 2×2 Newton step. The keypoint is dropped if the Hessian is singular
# or the offset exceeds 1 pixel. Coordinates are returned in Q16 — the
# representation the merge / orientation / descriptor stages expect.
def subpix_refine_kp(resp, x_int, y_int):
    """Refine an integer keypoint to subpixel. Returns (x_q16, y_q16) or None
    if the keypoint should be removed."""
    h, w = resp.shape
    if not (1 <= x_int <= w - 2 and 1 <= y_int <= h - 2):
        return None
    C = float(resp[y_int, x_int])
    L = float(resp[y_int, x_int - 1])
    R = float(resp[y_int, x_int + 1])
    T = float(resp[y_int - 1, x_int])
    B = float(resp[y_int + 1, x_int])
    TL = float(resp[y_int - 1, x_int - 1])
    TR = float(resp[y_int - 1, x_int + 1])
    BL = float(resp[y_int + 1, x_int - 1])
    BR = float(resp[y_int + 1, x_int + 1])
    dxx = L + R - 2.0 * C
    dyy = T + B - 2.0 * C
    dxy = (BR - BL - TR + TL) / 4.0
    gx = (R - L) / 2.0
    gy = (B - T) / 2.0
    det = dxx * dyy - dxy * dxy
    if det == 0.0:
        return None
    H = np.array([[dxx, dxy], [dxy, dyy]], dtype=np.float64)
    try:
        dx, dy = np.linalg.solve(H, np.array([-gx, -gy], dtype=np.float64))
    except np.linalg.LinAlgError:
        return None
    if abs(dx) > 1.0 or abs(dy) > 1.0:
        return None
    x_q16 = int(round((x_int + dx) * 65536.0))
    y_q16 = int(round((y_int + dy) * 65536.0))
    return x_q16, y_q16


# ─── descriptor gradient pair ─────────────────────────────────────────────
def descriptor_gradient(tile_q16):
    """Compute (gradX, gradY) float arrays for orientation + BRIEF sampling.
    gradX = d/dx of the smoothed tile, gradY = d/dy. Out-of-bounds reads → 0
    (matches the DLL's descriptor-gradient border handling)."""
    img = np.asarray(tile_q16, dtype=np.float64) / 65536.0
    gk = build_gaussian(5)
    sm = apply_sep(img, gk, gk, fill=0.0)
    gradX = apply_sep(sm, DERIV_3TAP, SMOOTH_3TAP, fill=0.0)
    gradY = apply_sep(sm, SMOOTH_3TAP, DERIV_3TAP, fill=0.0)
    return gradX, gradY


# ─── orientation (sub_18000D920) — dominant gradient angle ────────────────
def orient_d920(gradX, gradY, subpix_x_q16, subpix_y_q16):
    """Dominant-gradient orientation at a keypoint, in radians [0, 2π).

    Samples a 13×13 circular patch (radius 6) centred on the rounded subpixel
    coordinate, weights each gradient by GAUSS_Q, accumulates two 42-bin
    histograms with a 7-bin left-smear, picks the bin of greatest magnitude,
    and returns atan2 of that bin's accumulated (gy, gx)."""
    H, W = gradX.shape
    cx = (subpix_x_q16 + 0x8000) >> 16     # round to nearest pixel
    cy = (subpix_y_q16 + 0x8000) >> 16
    H_gx = np.zeros(42, dtype=np.float64)
    H_gy = np.zeros(42, dtype=np.float64)
    for dy in range(-6, 7):
        for dx in range(-6, 7):
            if dy * dy + dx * dx >= 36:    # circular mask, radius 6
                continue
            y = cy + dy
            x = cx + dx
            if not (0 <= y < H and 0 <= x < W):
                continue
            wgt = float(GAUSS_Q[abs(dy), abs(dx)])
            ggx = float(gradX[y, x]) * wgt
            ggy = float(gradY[y, x]) * wgt
            ang = math.atan2(ggy, ggx) % TWO_PI
            b = int(ang / TWO_PI * 42) % 42
            for k in range(7):             # 7-bin smear: bin-6 .. bin
                sb = (b - 6 + k) % 42
                H_gx[sb] += ggx
                H_gy[sb] += ggy
    mags = H_gx ** 2 + H_gy ** 2
    maxbin = int(np.argmax(mags))
    return math.atan2(H_gy[maxbin], H_gx[maxbin]) % TWO_PI


# ─── E090 oriented-BRIEF descriptor ───────────────────────────────────────
def desc_sample_rotate(grad_x, grad_y, subpix_x_q16, subpix_y_q16, orient, N=7):
    """Rotation + sampling (stage 1). Returns two float arrays of length
    (2N+2)² (= 256 for N=7): the orientation-rotated gradient samples.

    Storage is COLUMN-MAJOR (xL outer, yL inner) to match the aggregation
    table: index = (xL+N)*(2N+2) + (yL+N). `orient` is in radians."""
    H, W = grad_x.shape
    cos_o = math.cos(orient)
    sin_o = math.sin(orient)
    sx = subpix_x_q16 / 65536.0
    sy = subpix_y_q16 / 65536.0
    span = 2 * N + 2                                   # = 16 for N = 7
    rgx = np.zeros(span * span, dtype=np.float64)
    rgy = np.zeros(span * span, dtype=np.float64)
    for xi in range(span):                             # outer = xL
        xL = xi - N
        for yi in range(span):                         # inner = yL
            yL = yi - N
            px = sx + xL * cos_o - yL * sin_o
            py = sy + xL * sin_o + yL * cos_o
            ix = int(math.floor(px))
            iy = int(math.floor(py))
            if 0 <= ix < W and 0 <= iy < H:
                gx = float(grad_x[iy, ix])
                gy = float(grad_y[iy, ix])
            else:
                # Off-tile samples: zero gradient (a flat extension has no
                # gradient). The DLL filled these with mid-gray 0x800000 in
                # its Q16 gradient domain; 0.0 is the natural-units equivalent.
                gx = gy = 0.0
            idx = xi * span + yi
            rgx[idx] = cos_o * gx + sin_o * gy
            rgy[idx] = cos_o * gy - sin_o * gx
    return rgx, rgy


def desc_aggregate(rgx, rgy, aggr_table, win_sizes, N=7):
    """Aggregation (stage 2). For each table entry (size_idx, dx_off, dy_off),
    sum the rotated gradients over a w×w window (w = win_sizes[size_idx]).
    Returns the 2·len(aggr_table) BRIEF input buffer [gx0, gy0, gx1, gy1, …]."""
    span = 2 * N + 2
    out = np.zeros(2 * len(aggr_table), dtype=np.float64)
    for i, (size_idx, dx_off, dy_off) in enumerate(aggr_table):
        w = int(win_sizes[size_idx])
        if w <= 0:
            continue
        x0 = dx_off + N
        y0 = dy_off + N
        sx = sy = 0.0
        for xx in range(w):
            base = (x0 + xx) * span + y0
            sx += float(rgx[base:base + w].sum())
            sy += float(rgy[base:base + w].sum())
        out[2 * i + 0] = sx
        out[2 * i + 1] = sy
    return out


# ─── BRIEF bit-pack — bit[j] = samples[idx1] > samples[idx2] ──────────────
# The index-pair table is the DLL's runtime-generated BRIEF table, snapshotted
# in blobs_a2.BRIEF_TABLE (128 pairs → 16-byte descriptor).
_BRIEF_TABLE = None


def _load_brief_table():
    global _BRIEF_TABLE
    if _BRIEF_TABLE is None:
        from .blobs_a2 import BRIEF_TABLE
        _BRIEF_TABLE = np.array(BRIEF_TABLE, dtype=np.int32).reshape(-1, 2)
    return _BRIEF_TABLE


def brief_pack(samples, table=None, count=128):
    """BRIEF bit-pack: 128 binary comparisons → 16-byte little-endian descriptor."""
    if table is None:
        table = _load_brief_table()
    a = samples[table[:count, 0]]
    b = samples[table[:count, 1]]
    bits = (a > b).astype(np.uint8)
    return np.packbits(bits, bitorder='little')   # → 16-byte descriptor


# ─── tile→global merge + v30 assembly ──────────────────────────────────
def merge_tile_kps_to_global(per_tile_kps, h, w, margin=3):
    """Merge per-tile keypoint lists into one global list, applying the DLL's
    bound check (margin ≤ global_xy < dim-margin).

    `per_tile_kps`: iterable of (i, j, kp_list) where kp_list items have their
    first two fields = (subpix_x_q16, subpix_y_q16). Remaining fields are
    preserved. Returns list of (gx_int, gy_int, *rest); out-of-bounds dropped."""
    out = []
    for i, j, kp_list in per_tile_kps:
        oy, ox = tile_origin(i, j, h, w)
        for kp in kp_list:
            sx_q16, sy_q16 = kp[0], kp[1]
            gx = ox + (sx_q16 >> 16)
            gy = oy + (sy_q16 >> 16)
            if margin <= gx < w - margin and margin <= gy < h - margin:
                out.append((gx, gy, *kp[2:]))
    return out


# ─── WS-body v30 SECTION serializer ──────────────────────────────────────
# A v30 record area of one ws-body section: n_slots × 18-byte records, no
# header/lead-in/trailer. Record layout = [16B descriptor][x:u8][y:u8].
V30_SECTION_RECORDS = 250
V30_SECTION_BYTES = V30_SECTION_RECORDS * 18  # 4500
V30_DESC_LEN = 16   # record = [desc:16][x:u8][y:u8]; (x,y) anchor is +16 in
WS_SIZE = 23056             # chip-view WS body size
DEFAULT_SUBTYPE = 0x00f5    # default WinBio finger subtype (UNSPECIFIED_POS_01)


def serialize_v30_section(records, n_slots=V30_SECTION_RECORDS):
    """Serialize one ws-body section's v30 record area as
    [16B descriptor][x:u8][y:u8] × n_slots. Short tail zero-padded; the buffer
    must be written at (the v30-region anchor − V30_DESC_LEN)."""
    out = bytearray(n_slots * 18)
    for i, rec in enumerate(records):
        if i >= n_slots:
            break
        x, y, desc = rec[0], rec[1], rec[2]
        o = i * 18
        d = bytes(desc[:16])
        out[o:o + len(d)] = d
        out[o + 16] = x & 0xFF
        out[o + 17] = y & 0xFF
    return bytes(out)


# ─── End-to-end frame extraction (single image → kp list with descriptors) ─
_AGGR_TABLE = None
_WIN_SIZES = [7, 5, 3]      # the small local window-size table in E090


def _load_aggr_table():
    global _AGGR_TABLE
    if _AGGR_TABLE is None:
        from .blobs_a2 import AGGR_TABLE
        _AGGR_TABLE = np.array(AGGR_TABLE, dtype=np.int32).reshape(29, 3)
    return _AGGR_TABLE


def _descriptor_at(gradX, gradY, subpix_x_q16, subpix_y_q16, orient):
    """16-byte BRIEF descriptor at a keypoint via the rotate→aggregate→pack
    chain. `orient` is in radians."""
    rgx, rgy = desc_sample_rotate(gradX, gradY, subpix_x_q16, subpix_y_q16,
                                  orient, N=7)
    samples = desc_aggregate(rgx, rgy, _load_aggr_table(), _WIN_SIZES, N=7)
    return brief_pack(samples)


FRAME_KP_CAP = 250
"""sub_18000AAB0 caps the per-frame kp_array to 250 (0xfa)."""


def _a960_passes_global_edge(sx_q16, sy_q16, oy, ox, h, w, ti=None, tj=None):
    """Project (subpix_x_q16, subpix_y_q16) into the global frame via the tile
    origin and return True iff 3 ≤ gx < w-3 and 3 ≤ gy < h-3, with one
    corner-tile tightening observed in captures of the Windows driver's
    enrollment (bottom-right tile caps gy at oy + last-row-step)."""
    gx = ((ox << 16) + sx_q16) >> 16
    gy = ((oy << 16) + sy_q16) >> 16
    gx_hi = w - 3
    gy_hi = h - 3
    if ti is not None and tj is not None:
        if ti == GRID - 1 and tj == GRID - 1:
            step_y = h - (GRID - 1) * (h // GRID)
            gy_hi = oy + step_y  # exclusive
    return 3 <= gx < gx_hi and 3 <= gy < gy_hi


def extract_frame_native(image_q16, h=112, w=112,
                         t_lo=671, t_hi=168, dedup_q=72064, nms_margin=10,
                         subpix_refine=True, frame_kp_cap=FRAME_KP_CAP,
                         stats=None):
    """Single-frame native feature extractor.

    Per-tile: DoH → NMS → subpixel refine → global-edge cull. Then a global
    sort by |resp| descending, cap to 250, re-sort by (tile_id, |resp| desc),
    and run orientation + descriptor per keypoint. Returns a list of
    (gx_int, gy_int, orient_rad, desc_16B) after the global merge.

    `stats`, if a dict, is filled with frame-quality metrics that survive the
    250-cap (the returned list saturates at `frame_kp_cap` on any healthy
    frame, so its length cannot rank frames — see dev/FRAME-QUALITY.md):
      n_pool     uncapped keypoint count (pool size before the cap)
      cap_score  |resp| of the weakest KEPT keypoint if the cap was hit, else 0
      med_score  median |resp| of the kept keypoints

    `image_q16`: (h, w) int array, mid-gray = 0x800000 (uint8 image << 16)."""
    image_q16 = np.asarray(image_q16, dtype=np.int64)
    if image_q16.shape != (h, w):
        raise ValueError(f"expected ({h}, {w}), got {image_q16.shape}")

    # Phase 1: per-tile detect + subpix + edge filter into a tile-tagged pool.
    per_tile_grads = {}
    pool = []   # (score, tile_id, ti, tj, sx_q16, sy_q16)
    for ti, tj, tile in tile_image(image_q16):
        gradX, gradY = descriptor_gradient(tile)
        per_tile_grads[(ti, tj)] = (gradX, gradY)
        _, _, _, resp = doh(tile)
        oy, ox = tile_origin(ti, tj, h, w)
        tile_id = ti * GRID + tj
        for score, lx, ly in nms(resp, t_lo=t_lo, t_hi=t_hi,
                                 dedup_q=dedup_q, margin=nms_margin):
            if subpix_refine:
                r = subpix_refine_kp(resp, lx, ly)
                if r is None:
                    continue
                sx_q16, sy_q16 = r
            else:
                sx_q16 = lx * 65536
                sy_q16 = ly * 65536
            if not _a960_passes_global_edge(sx_q16, sy_q16, oy, ox, h, w, ti, tj):
                continue
            pool.append((score, tile_id, ti, tj, sx_q16, sy_q16))

    # Phase 2: global sort by |resp| desc, cap to frame_kp_cap.
    pool.sort(key=lambda r: -r[0])
    if stats is not None:
        kept_scores = [r[0] for r in pool[:frame_kp_cap]]
        stats['n_pool'] = len(pool)
        stats['cap_score'] = (float(kept_scores[-1])
                              if len(pool) >= frame_kp_cap else 0.0)
        stats['med_score'] = (float(np.median(kept_scores))
                              if kept_scores else 0.0)
    pool = pool[:frame_kp_cap]

    # Phase 3: re-sort by (tile_id asc, |resp| desc).
    pool.sort(key=lambda r: (r[1], -r[0]))

    # Phase 4: per-kp orient + descriptor, grouped back into per-tile lists.
    per_tile_kps = []
    current_key = None
    current_records = None
    current_tij = None
    for score, tile_id, ti, tj, sx_q16, sy_q16 in pool:
        if tile_id != current_key:
            if current_records is not None:
                per_tile_kps.append((current_tij[0], current_tij[1], current_records))
            current_key = tile_id
            current_tij = (ti, tj)
            current_records = []
        gradX, gradY = per_tile_grads[(ti, tj)]
        orient = orient_d920(gradX, gradY, sx_q16, sy_q16)
        desc = _descriptor_at(gradX, gradY, sx_q16, sy_q16, orient)
        current_records.append((sx_q16, sy_q16, orient, bytes(desc)))
    if current_records is not None:
        per_tile_kps.append((current_tij[0], current_tij[1], current_records))

    return merge_tile_kps_to_global(per_tile_kps, h, w)


# ─── Baked WS-body scaffold — makes native enrollment REFERENCE-FREE ───────
# A genuine chip-accepted Windows-driver template with its v30 RECORD areas zeroed —
# i.e. the TLV framing only (header, per-section counts, sec0_pre inter-section
# pose table, section markers, tail). Finger-INDEPENDENT RE-derived constant
# data; we overlay OUR v30 records onto it and recompute the TID.
NATIVE_WS_V30_REGIONS = (309, 4913, 9453, 13993)
_NATIVE_WS_SCAFFOLD = None


_WS_SCAFFOLD_PRE_V30_RECORDS = 6   # sec0_pre inter-section transforms


def _load_ws_scaffold():
    """Return the 23056-byte baked WS-body framing scaffold (v30 zeroed) with
    its sec0_pre inter-section transforms already set to NEAR-identity.

    The patch is applied once here (not per template build) and its record
    count is asserted: the patcher is a heuristic scan, so a scaffold edit
    that broke it would otherwise silently leave pure-identity transforms —
    the matcher's 'unmatched' sentinel — in every template."""
    global _NATIVE_WS_SCAFFOLD
    if _NATIVE_WS_SCAFFOLD is None:
        from .blobs_a2 import build_ws_scaffold
        patched, n = patch_pre_v30_near_identity(build_ws_scaffold(),
                                                 NATIVE_WS_V30_REGIONS)
        if n != _WS_SCAFFOLD_PRE_V30_RECORDS:
            raise RuntimeError(f'WS scaffold: patched {n} sec0_pre records, '
                               f'expected {_WS_SCAFFOLD_PRE_V30_RECORDS}')
        _NATIVE_WS_SCAFFOLD = patched
    return _NATIVE_WS_SCAFFOLD


def patch_pre_v30_near_identity(ws_body, regions):
    """Set the WS body's inter-section rigid transforms to NEAR-identity so a
    single-frame template (same records in every section) is self-consistent.

    The matcher's candidate-validity filter (sub_18000bfb0) skips pure-identity
    {0x10000,0,0,0} as the 'unmatched' sentinel, so we write near-identity
    a=0x10000, b=0, tx=1, ty=1: geometrically identity yet tx != 0.
    Returns (patched_ws_body_bytes, n_records_patched)."""
    import struct as _struct
    ONE = 0x10000
    ws = bytearray(ws_body)
    span = V30_SECTION_BYTES
    zones, prev = [], 0
    for b in sorted(regions):
        zones.append((prev, b))
        prev = b + span
    zones.append((prev, len(ws)))

    def rigid(a, b):
        return abs(a * a + b * b - ONE * ONE) < ONE * ONE * 0.05

    ident = _struct.pack('<4i', ONE, 0, 1, 1)   # a, b, tx, ty (near-identity)
    patched = 0
    for z0, z1 in zones:
        best = (0, 0)
        for start in range(z0, z1):
            o, n = start, 0
            while o + 18 <= z1:
                a, b, tx, ty = _struct.unpack_from('<4i', ws, o + 2)
                if not rigid(a, b):
                    break
                n += 1
                o += 18
            if n > best[0]:
                best = (n, start)
        n, start = best
        if n >= 2:
            o = start
            for _ in range(n):
                ws[o + 2:o + 18] = ident          # keep [x][y] at o, o+1
                o += 18
                patched += 1
    return bytes(ws), patched


def assemble_template(per_section_kps, subtype):
    """Assemble the chip-ready envelope from per-section keypoint lists.

    `per_section_kps[i % len]` fills v30 section i of the baked WS-body
    scaffold as [16B desc][x][y] records (one list → every section gets the
    same frame); the TID is recomputed over the new body and the result is
    wrapped in the type-6 envelope (chip cmd 0x47). Items are
    (gx, gy, orient, desc) as returned by extract_frame_native()."""
    ws_body = bytearray(_load_ws_scaffold())
    assert len(ws_body) == WS_SIZE, f"WS body must be {WS_SIZE}B, got {len(ws_body)}"
    for idx, base in enumerate(NATIVE_WS_V30_REGIONS):
        kps = per_section_kps[idx % len(per_section_kps)]
        # The record area starts V30_DESC_LEN before the (x,y) anchor. The
        # per-section trailer is enroll-only bookkeeping the matcher ignores.
        section = serialize_v30_section(
            [(gx, gy, desc) for (gx, gy, _orient, desc) in kps])
        start = base - V30_DESC_LEN
        ws_body[start:start + len(section)] = section
    ws_body_bytes = bytes(ws_body)
    return build_envelope(subtype, ws_body_bytes, compute_tid(ws_body_bytes))


def native_template(image_q16, subtype=None):
    """End-to-end REFERENCE-FREE single-frame enrollment template: detect
    keypoints in `image_q16` with the native pipeline and fill every v30
    section with them (see assemble_template).

    `image_q16`: (h, w) int Q16 image (mid-gray = 0x800000). The sensor returns
    uint8; convert via `img.astype(np.int32) << 16`."""
    if subtype is None:
        subtype = DEFAULT_SUBTYPE
    kps = extract_frame_native(image_q16, h=image_q16.shape[0],
                               w=image_q16.shape[1])
    return assemble_template([kps], subtype)


# ══════════════════════════════════════════════════════════════════════
# Envelope + TID (byte-format; shared with Sensor.make_finger_data)
# ══════════════════════════════════════════════════════════════════════

def build_envelope(subtype, ws_body, template_id, version=3):
    """Wire-exact finger-template envelope for new_record type=6 (byte-identical
    to the DLL's sub_180036840). Layout: 8-byte outer header, TLV1 (tag=1)
    ws_body, TLV2 (tag=2) template_id, 32 trailing zeros. Caller passes the
    chip-view WS body (NOT including the TLV2 header). Also the format the
    legacy 0x68/0x6b enrollment stores (Sensor.make_finger_data)."""
    assert len(template_id) == 32
    ws_size = len(ws_body)
    tid_size = len(template_id)
    trailing = 32
    payload_size = 4 + ws_size + 4 + tid_size   # TLV1 hdr + ws + TLV2 hdr + TID
    total = 8 + payload_size + trailing

    buf = bytearray(total)
    buf[0:2] = pack('<H', subtype)
    buf[2:4] = pack('<H', version)
    buf[4:6] = pack('<H', payload_size & 0xffff)
    buf[6:8] = pack('<H', trailing)
    buf[8:10] = pack('<H', 1)
    buf[10:12] = pack('<H', ws_size & 0xffff)
    buf[12:12 + ws_size] = ws_body
    off = 12 + ws_size
    buf[off:off + 2] = pack('<H', 2)
    buf[off + 2:off + 4] = pack('<H', tid_size & 0xffff)
    buf[off + 4:off + 4 + tid_size] = template_id
    return bytes(buf)


# The literal context string the DLL feeds to its TID HMAC, padded to 43 bytes.
_TID_INFO = b'Template ID' + b'\x00' * 32
assert len(_TID_INFO) == 43


def compute_tid(ws_body):
    """Compute the 32-byte TemplateId for a Match-on-Host finger template:

        K   = SHA-256(ws_body)
        T1  = HMAC-SHA256(K, "Template ID" ‖ 32×0x00)
        TID = HMAC-SHA256(K, T1 ‖ "Template ID" ‖ 32×0x00)

    `ws_body`: 23056-byte chip-view WS body (envelope slice [12:12+23056])."""
    if len(ws_body) != 23056:
        raise ValueError(f"ws_body must be 23056 bytes, got {len(ws_body)}")
    K = hashlib.sha256(ws_body).digest()
    T1 = hmac.new(K, _TID_INFO, hashlib.sha256).digest()
    return hmac.new(K, T1 + _TID_INFO, hashlib.sha256).digest()
