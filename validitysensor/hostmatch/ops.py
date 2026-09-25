"""Host-side enroll and verify, for sensors without an on-chip template database.

Both run on a sensor the caller has already opened (``init.open_flashless()``) and
report progress with fprintd's result strings, so the D-Bus service can pass them
straight through. Neither holds anything open afterwards: the caller closes the
session, one per operation.

``source`` is anything with ``Sensor2449.get_print()``'s signature, so tests can
replay saved images instead of touching hardware.

The numbers below come from an evaluation on 06cb:00a8: 145 captures of 5 fingers
over 2 days (issue #179).
"""

from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass
from typing import Callable, Protocol

import numpy as np

from .matcher import ACCEPT_THRESHOLD, FeatureMatcher, Features
from .quality import MIN_RIDGE_COHERENCE, foreground_mask, ridge_coherence
from ..sensor_2449 import Cancelled, CaptureFailed
from .store import IMAGE_SHAPE, Template, check_finger, check_user

log = logging.getLogger(__name__)

# FRR 2.1% at 18 touches, 3.2% at 15, 7.6% at 10. Windows also takes 18.
ENROLL_STAGES = 18
MIN_ENROLL_STAGES = 15

# The evaluation's smallest touches cover 27% of the sensor and have 76
# keypoints; below these a touch adds little and matches unreliably.
MIN_FOREGROUND = 0.25
MIN_KEYPOINTS = 50

# Pixel correlation above which a touch is a copy of an earlier one: a finger
# left resting fires the next capture at once.
DUPLICATE_CORR = 0.97

# Pause after an accepted touch, so the finger can lift before re-arming.
LIFT_DELAY_S = 1.0

StatusCallback = Callable[[str], None]


class _PrintResult(Protocol):
    @property
    def image(self) -> bytes | None: ...


class PrintSource(Protocol):
    def get_print(self, *, touch_timeout: float = ..., on_armed: Callable[[], None] | None = ...,
                  cancel: threading.Event | None = ...,
                  on_touch: Callable[[], None] | None = ...) -> _PrintResult: ...


@dataclass
class Capture:
    image: np.ndarray
    features: Features


@dataclass
class VerifyResult:
    matched: bool
    finger: str | None  # best-scoring finger, or None if nothing was enrolled
    score: float


def _correlation(a: np.ndarray, b: np.ndarray) -> float:
    x = a.astype(np.float64) - a.mean()
    y = b.astype(np.float64) - b.mean()
    den = np.sqrt((x * x).sum() * (y * y).sum())
    return float((x * y).sum() / den) if den else 0.0


def _capture(source: PrintSource, matcher: FeatureMatcher, prefix: str, on_status: StatusCallback,
             cancel: threading.Event, deadline: float | None, touch_timeout: float,
             on_armed: Callable[[], None] | None) -> Capture | None:
    """One touch. Returns None (after reporting a ``<prefix>-*`` retry status) when
    the touch is unusable. Raises ``Cancelled`` or ``TimeoutError`` (past ``deadline``)."""
    while True:
        if cancel.is_set():
            raise Cancelled()
        wait = touch_timeout
        if deadline is not None:
            wait = min(wait, deadline - time.monotonic())
            if wait <= 0:
                raise TimeoutError("no usable touch before the operation timed out")
        try:
            result = source.get_print(touch_timeout=wait, on_armed=on_armed, cancel=cancel)
            break
        except TimeoutError:
            continue  # nobody touched yet; re-arm
        except CaptureFailed as e:
            log.warning("rejected touch: %s", e)
            on_status(f"{prefix}-retry-scan")
            return None
    if result.image is None or len(result.image) != IMAGE_SHAPE[0] * IMAGE_SHAPE[1]:
        on_status(f"{prefix}-retry-scan")
        return None
    img = np.frombuffer(result.image, dtype=np.uint8).reshape(IMAGE_SHAPE)
    coherence = ridge_coherence(img)
    if coherence < MIN_RIDGE_COHERENCE:
        log.info("rejected touch: ridge coherence %.2f", coherence)
        on_status(f"{prefix}-retry-scan")
        return None
    coverage = float(foreground_mask(img).mean())
    if coverage < MIN_FOREGROUND:
        log.info("rejected touch: covers %.0f%% of the sensor", 100 * coverage)
        on_status(f"{prefix}-finger-not-centered")
        return None
    features = matcher.extract(img)
    if len(features) < MIN_KEYPOINTS:
        log.info("rejected touch: %d keypoints", len(features))
        on_status(f"{prefix}-retry-scan")
        return None
    return Capture(img, features)


def enroll(source: PrintSource, matcher: FeatureMatcher, user: str, finger: str, *,
           on_status: StatusCallback = lambda s: None,
           on_armed: Callable[[], None] | None = None,
           cancel: threading.Event | None = None,
           stages: int = ENROLL_STAGES,
           timeout: float | None = None,
           touch_timeout: float = 15.0,
           lift_delay: float = LIFT_DELAY_S) -> Template:
    """Collect ``stages`` distinct touches of one finger.

    Reports ``enroll-stage-passed`` per accepted touch and
    ``enroll-retry-scan`` / ``enroll-finger-not-centered`` /
    ``enroll-remove-and-retry`` for rejected ones. The caller saves the
    returned template and reports ``enroll-completed``. Raises ``Cancelled``, or
    ``TimeoutError`` after ``timeout`` seconds in total.
    """
    check_user(user)
    check_finger(finger)
    if stages < 1:
        raise ValueError("stages must be at least 1")
    cancel = cancel or threading.Event()
    deadline = None if timeout is None else time.monotonic() + timeout
    t = Template(user, finger, [])
    while len(t.images) < stages:
        c = _capture(source, matcher, "enroll", on_status, cancel, deadline, touch_timeout, on_armed)
        if c is None:
            continue
        # Checking every accepted touch, not just the last, also stops a
        # near-identical placement from counting twice towards coverage.
        corr = max((_correlation(c.image, im) for im in t.images), default=0.0)
        if corr > DUPLICATE_CORR:
            log.info("rejected touch: duplicate (correlation %.3f)", corr)
            on_status("enroll-remove-and-retry")
        else:
            t.images.append(c.image)
            t.features.append(c.features)
            log.info("enroll stage %d/%d", len(t.images), stages)
            on_status("enroll-stage-passed")
            if len(t.images) == stages:
                break
        if cancel.wait(lift_delay):
            raise Cancelled()
    return t


def verify(source: PrintSource, matcher: FeatureMatcher, templates: list[Template], *,
           on_status: StatusCallback = lambda s: None,
           on_armed: Callable[[], None] | None = None,
           cancel: threading.Event | None = None,
           timeout: float | None = None,
           touch_timeout: float = 15.0,
           threshold: float = ACCEPT_THRESHOLD) -> VerifyResult:
    """Wait for one usable touch and score it against ``templates``.

    Unusable touches report ``verify-retry-scan`` or
    ``verify-finger-not-centered`` and wait for another. The caller reports
    ``verify-match`` / ``verify-no-match`` from the result. Raises
    ``Cancelled``, or ``TimeoutError`` after ``timeout`` seconds in total.
    """
    cancel = cancel or threading.Event()
    deadline = None if timeout is None else time.monotonic() + timeout
    while True:
        c = _capture(source, matcher, "verify", on_status, cancel, deadline, touch_timeout, on_armed)
        if c is not None:
            break
    best = VerifyResult(False, None, 0.0)
    for t in templates:
        score = matcher.score(c.features, t.features)
        log.info("verify: %s/%s score %g", t.user, t.finger, score)
        if best.finger is None or score > best.score:
            best = VerifyResult(False, t.finger, score)
    best.matched = best.finger is not None and best.score >= threshold
    return best
