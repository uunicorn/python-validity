"""Image quality checks for GetPrint images (144x56 8bpp)."""

from __future__ import annotations

import numpy as np

# Mean block coherence of real prints vs. no-finger frames, measured on
# 06cb:00a8 captures: prints 0.63-0.73, blank sensor noise 0.28.
MIN_RIDGE_COHERENCE = 0.45


# Per-8x8-block pixel std: finger 45-98, uncovered sensor 4-35 (streaky
# fixed-pattern background), measured on 06cb:00a8.
MIN_FOREGROUND_STD = 40.0


def foreground_mask(img: np.ndarray, block: int = 8, min_std: float = MIN_FOREGROUND_STD) -> np.ndarray:
    """Boolean per-pixel mask of the part of the sensor the finger covers.

    Partial touches are common on a sensor this small, and the uncovered part
    carries horizontal fixed-pattern streaks that look alike in every capture,
    so matchers have to ignore it. Pixels past the last whole block inherit
    the nearest block's decision.
    """
    a = np.asarray(img, dtype=np.float64)
    h, w = a.shape
    bh, bw = -(-h // block), -(-w // block)
    p = np.pad(a, ((0, bh * block - h), (0, bw * block - w)), mode="edge")
    fg = p.reshape(bh, block, bw, block).std(axis=(1, 3)) >= min_std
    return np.kron(fg, np.ones((block, block), dtype=bool))[:h, :w]


def ridge_coherence(img: np.ndarray, block: int = 8) -> float:
    """Mean orientation coherence over ``block``x``block`` tiles, 0..1.

    Per tile, from the gradient structure tensor:
    sqrt((Gxx - Gyy)^2 + 4 Gxy^2) / (Gxx + Gyy). Parallel ridges score near 1,
    and sensor noise with no dominant direction scores low. Mean brightness and
    contrast don't separate the two on this sensor; coherence does.
    """
    a = np.asarray(img, dtype=np.float64)
    gy, gx = (np.asarray(g) for g in np.gradient(a))
    h, w = a.shape
    h -= h % block
    w -= w % block

    def tiles(x: np.ndarray) -> np.ndarray:
        return x[:h, :w].reshape(h // block, block, w // block, block).sum(axis=(1, 3))

    xx, yy, xy = tiles(gx * gx), tiles(gy * gy), tiles(gx * gy)
    coh = np.sqrt((xx - yy) ** 2 + 4 * xy ** 2) / np.maximum(xx + yy, 1e-9)
    return float(coh.mean())
