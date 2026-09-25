"""validitysensor.hostmatch store and enroll/verify, without hardware.

The enroll/verify tests replay images through a fake ``get_print()`` and a fake matcher.
"""

import os
import stat
import threading
from typing import Callable
from dataclasses import dataclass

import numpy as np
import pytest

from validitysensor.hostmatch import ops, store
from validitysensor.hostmatch.matcher import Features
from validitysensor.hostmatch.store import Template, TemplateStore, StoreError
from validitysensor.sensor_2449 import Cancelled, CaptureFailed


def _ridges(angle=0.3, period=7.0, phase=0.0, h=56, w=144):
    yy, xx = np.mgrid[0:h, 0:w]
    t = xx * np.cos(angle) + yy * np.sin(angle)
    return (127.5 + 100 * np.sin(2 * np.pi * t / period + phase)).astype(np.uint8)


def _touch(finger: int, i: int) -> np.ndarray:
    """Distinct, print-quality synthetic touch ``i`` of ``finger``."""
    return _ridges(angle=0.2 + 0.4 * finger + 0.03 * i, period=6.0 + finger, phase=0.7 * i)


class FakeMatcher:
    """Features carry the finger id; score is 10 for the same finger, else 1."""

    def __init__(self, finger_of):
        self.finger_of = finger_of

    def extract(self, img: np.ndarray) -> Features:
        fid = self.finger_of(img)
        return Features(np.zeros((100, 2), np.float32), np.full((100, 128), fid, np.float32))

    def score(self, probe: Features, touches: list[Features]) -> float:
        return max((10.0 if t.desc[0, 0] == probe.desc[0, 0] else 1.0 for t in touches), default=0.0)


@dataclass
class _Result:
    image: bytes | None


class ReplaySource:
    """get_print() that hands out queued items: an image, None (no image in the
    reply) or an exception to raise."""

    def __init__(self, items):
        self.items = list(items)
        self.calls = 0

    def get_print(self, *, touch_timeout: float = 15.0, on_armed: Callable[[], None] | None = None,
                  cancel: threading.Event | None = None,
                  on_touch: Callable[[], None] | None = None) -> _Result:
        self.calls += 1
        if cancel is not None and cancel.is_set():
            raise Cancelled()
        if not self.items:
            raise TimeoutError("no touch")
        item = self.items.pop(0)
        if isinstance(item, BaseException):
            raise item
        if on_armed:
            on_armed()
        if on_touch:
            on_touch()
        return _Result(None if item is None else item.tobytes())


def _fake_matcher():
    lookup = {}
    for f in range(3):
        for i in range(30):
            lookup[_touch(f, i).tobytes()] = f
    return FakeMatcher(lambda img: lookup.get(img.tobytes(), -1))


# -- store ----------------------------------------------------------------------


def _template(user="alice", finger="right-index-finger", n=3):
    m = _fake_matcher()
    imgs = [_touch(0, i) for i in range(n)]
    return Template(user, finger, imgs, [m.extract(im) for im in imgs])


def test_store_round_trip_and_permissions(tmp_path):
    root = tmp_path / "store"
    s = TemplateStore(str(root))
    path = s.save(_template())
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
    assert stat.S_IMODE(os.stat(root / "alice").st_mode) == 0o700
    assert stat.S_IMODE(os.stat(root).st_mode) == 0o700
    t = s.load("alice", "right-index-finger")
    assert len(t.images) == 3 and all(np.array_equal(a, _touch(0, i)) for i, a in enumerate(t.images))
    assert [len(f) for f in t.features] == [100, 100, 100]
    assert s.users() == ["alice"] and s.fingers("alice") == ["right-index-finger"]
    assert not [n for n in os.listdir(root / "alice") if n.startswith(".tmp")]


def test_store_rejects_bad_names(tmp_path):
    s = TemplateStore(str(tmp_path))
    for user in ("../etc", "a/b", "", ".hidden", "x" * 300):
        with pytest.raises(StoreError):
            s.save(_template(user=user))
    with pytest.raises(StoreError):
        s.save(_template(finger="right-toe"))
    with pytest.raises(StoreError):
        s.load("alice", "right-index-finger")


def test_store_delete(tmp_path):
    s = TemplateStore(str(tmp_path))
    s.save(_template(finger="right-index-finger"))
    s.save(_template(finger="left-thumb"))
    assert s.delete("alice", "left-thumb") == ["left-thumb"]
    assert s.fingers("alice") == ["right-index-finger"]
    assert s.delete("alice") == ["right-index-finger"]
    assert not (tmp_path / "alice").exists() and s.users() == []
    assert s.delete("nobody") == []


def test_store_rebuilds_stale_features(tmp_path, monkeypatch):
    s = TemplateStore(str(tmp_path))
    monkeypatch.setattr(store, "MATCHER_VERSION", 0)
    s.save(_template())
    monkeypatch.setattr(store, "MATCHER_VERSION", 1)
    with pytest.raises(StoreError, match="matcher v0"):
        s.load("alice", "right-index-finger")
    t = s.load("alice", "right-index-finger", _fake_matcher())
    assert len(t.features) == 3
    s.load("alice", "right-index-finger")  # re-saved with the current version


def test_store_refuses_pickled_content(tmp_path):
    s = TemplateStore(str(tmp_path))
    path = s.save(_template())
    np.savez(path, meta=np.array([{"format": 1}], dtype=object))  # object array => pickle
    with pytest.raises(StoreError, match="unreadable"):
        s.load("alice", "right-index-finger")


# -- ops ------------------------------------------------------------------------


def test_enroll_collects_distinct_touches_and_rejects_bad_ones():
    noise = np.random.default_rng(0).integers(0, 256, (56, 144), dtype=np.uint8)
    partial = _touch(0, 3).copy()
    # finger covers ~20% of the sensor; the rest has the uncovered sensor's
    # faint horizontal fixed-pattern streaks
    partial[:, 30:] = _ridges(angle=np.pi / 2, period=4.0)[:, 30:] // 8 + 110
    items = [_touch(0, 0), None, noise, CaptureFailed(7), _touch(0, 0), TimeoutError(), partial] + \
        [_touch(0, i) for i in range(1, 5)]
    statuses = []
    t = ops.enroll(ReplaySource(items), _fake_matcher(), "alice", "right-index-finger",
                   on_status=statuses.append, stages=5, lift_delay=0)
    assert len(t.images) == 5 and len(t.features) == 5
    assert statuses == ["enroll-stage-passed", "enroll-retry-scan", "enroll-retry-scan", "enroll-retry-scan",
                        "enroll-remove-and-retry", "enroll-finger-not-centered"] + ["enroll-stage-passed"] * 4


def test_enroll_cancel_and_timeout():
    cancel = threading.Event()
    src = ReplaySource([_touch(0, 0)])

    def on_status(s):
        cancel.set()

    with pytest.raises(Cancelled):
        ops.enroll(src, _fake_matcher(), "alice", "left-thumb", on_status=on_status, cancel=cancel,
                   stages=3, lift_delay=0)
    with pytest.raises(TimeoutError):
        ops.enroll(ReplaySource([]), _fake_matcher(), "alice", "left-thumb", timeout=0.05, touch_timeout=0.01)


def test_verify_picks_best_finger():
    m = _fake_matcher()
    t0 = Template("alice", "right-index-finger", [], [m.extract(_touch(0, i)) for i in range(3)])
    t1 = Template("alice", "left-thumb", [], [m.extract(_touch(1, i)) for i in range(3)])
    statuses = []
    r = ops.verify(ReplaySource([None, _touch(1, 20)]), m, [t0, t1], on_status=statuses.append)
    assert (r.matched, r.finger, r.score) == (True, "left-thumb", 10.0)
    assert statuses == ["verify-retry-scan"]
    r = ops.verify(ReplaySource([_touch(2, 0)]), m, [t0, t1])
    assert not r.matched and r.score == 1.0
    r = ops.verify(ReplaySource([_touch(2, 0)]), m, [])
    assert (r.matched, r.finger) == (False, None)
