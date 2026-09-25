"""Host-side fingerprint matcher.

Masked SIFT keypoints on a 2x upscaled, CLAHE-equalised image. A pair's score
is the number of RANSAC inliers of a similarity transform between matched
keypoints, taken in both directions and combined with ``min``. A probe's score
against an enrolled finger is the max over the finger's enrolled touches.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

import numpy as np

from .quality import foreground_mask

# Bumped whenever a change here would change the features or scores, so stored
# templates can be recognised as stale and rebuilt from their raw images.
MATCHER_VERSION = 1

# The highest impostor score in the 06cb:00a8 evaluation (see ops.py) was 4, so 5
# has no margin.
ACCEPT_THRESHOLD = 6

RATIO = 0.8
RANSAC_REPROJ_PX = 6.0
MIN_SCALE, MAX_SCALE = 0.8, 1.25
MAX_ROTATION_DEG = 30.0
MASK_ERODE = 13  # at 2x


def _cv2():
    import cv2  # imported lazily: heavy, and only matching needs it

    return cv2


@dataclass
class Features:
    """Keypoint positions (n, 2) float32 at 2x scale, and SIFT descriptors (n, 128) float32."""

    pts: np.ndarray
    desc: np.ndarray

    def __len__(self) -> int:
        return len(self.pts)


class FeatureMatcher(Protocol):
    """What enroll/verify and the template store need from a matcher."""

    def extract(self, img: np.ndarray) -> Features: ...

    def score(self, probe: Features, touches: list[Features]) -> float: ...


def preprocess(img: np.ndarray, masked: bool = True) -> tuple[np.ndarray, np.ndarray | None]:
    """2x cubic upscale + CLAHE; with ``masked``, also the eroded foreground mask."""
    cv2 = _cv2()
    clahe = cv2.createCLAHE(clipLimit=2.0, tileGridSize=(4, 8))
    im = clahe.apply(cv2.resize(img, None, fx=2, fy=2, interpolation=cv2.INTER_CUBIC))
    mask = None
    if masked:
        fg = np.kron(foreground_mask(img), np.ones((2, 2), dtype=bool)).astype(np.uint8) * 255
        mask = cv2.erode(fg, np.ones((MASK_ERODE, MASK_ERODE), np.uint8))
    return im, mask


def inlier_score(p1: np.ndarray, d1: np.ndarray | None, p2: np.ndarray, d2: np.ndarray | None,
                 norm: int, ratio: float = RATIO) -> float:
    """One-way score: ratio-test matches from 1 to 2, then RANSAC similarity inliers.

    Transforms a finger can't produce (scale outside 0.8-1.25, rotation beyond
    30 degrees) score 0."""
    cv2 = _cv2()
    if d1 is None or d2 is None or len(d1) < 2 or len(d2) < 2:
        return 0.0
    knn = cv2.BFMatcher(norm).knnMatch(d1, d2, k=2)
    good = [m for m, n in (x for x in knn if len(x) == 2) if m.distance < ratio * n.distance]
    if len(good) < 3:
        return float(len(good))
    src = p1[[m.queryIdx for m in good]]
    dst = p2[[m.trainIdx for m in good]]
    t, inl = cv2.estimateAffinePartial2D(src, dst, method=cv2.RANSAC,
                                         ransacReprojThreshold=RANSAC_REPROJ_PX)
    if t is None or inl is None:
        return 0.0
    scale = float(np.hypot(t[0, 0], t[1, 0]))
    angle = float(np.degrees(np.arctan2(t[1, 0], t[0, 0])))
    if not MIN_SCALE <= scale <= MAX_SCALE or abs(angle) > MAX_ROTATION_DEG:
        return 0.0
    return float(np.count_nonzero(inl))


class Matcher:
    def __init__(self) -> None:
        cv2 = _cv2()
        self._sift = cv2.SIFT_create()  # pyright: ignore[reportAttributeAccessIssue]
        self._norm = cv2.NORM_L2

    def extract(self, img: np.ndarray) -> Features:
        """Features of one 144x56 capture."""
        im, mask = preprocess(img)
        kps, desc = self._sift.detectAndCompute(im, mask)
        pts = np.array([k.pt for k in kps], dtype=np.float32).reshape(-1, 2)
        if desc is None:
            desc = np.zeros((0, 128), dtype=np.float32)
        return Features(pts, desc.astype(np.float32, copy=False))

    def one_way(self, a: Features, b: Features) -> float:
        return inlier_score(a.pts, a.desc, b.pts, b.desc, self._norm)

    def pair_score(self, a: Features, b: Features) -> float:
        """Symmetric score: one-way scores reached 7 for impostors, min brings it to 4."""
        return min(self.one_way(a, b), self.one_way(b, a))

    def score(self, probe: Features, touches: list[Features]) -> float:
        """Max-fused score of a probe against one finger's enrolled touches."""
        return max((self.pair_score(probe, t) for t in touches), default=0.0)
