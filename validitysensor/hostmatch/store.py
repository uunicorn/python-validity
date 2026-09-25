"""Enrolled-template store for the host-side matcher.

Layout: ``ROOT/<user>/<finger>.npz``, one file per user and finger, root-only
(directories 0700, files 0600). Each file holds the raw 144x56 touches and
the matcher's features for them. The raw images are the real template: if
``matcher.MATCHER_VERSION`` changes, features are rebuilt from them on load.

Files are ``numpy.savez`` archives read with ``allow_pickle=False``, so a
tampered file can't run code. Writes go to a temp file that is fsynced and
renamed over the old one.
"""

from __future__ import annotations

import json
import os
import re
import tempfile
from dataclasses import dataclass, field

import numpy as np

from ..init_data_dir import PYTHON_VALIDITY_STATE_DIR
from .matcher import MATCHER_VERSION, FeatureMatcher, Features

DEFAULT_ROOT = PYTHON_VALIDITY_STATE_DIR + "prints"
FORMAT_VERSION = 1
IMAGE_SHAPE = (56, 144)

# fprintd finger names (net.reactivated.Fprint.Device docs), which is what
# open-fprintd passes through.
FINGERS = (
    "left-thumb", "left-index-finger", "left-middle-finger", "left-ring-finger", "left-little-finger",
    "right-thumb", "right-index-finger", "right-middle-finger", "right-ring-finger", "right-little-finger",
)

# POSIX portable user names, plus the trailing $ Samba machine accounts use.
_USER_RE = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]*\$?")


class StoreError(Exception):
    pass


def check_user(user: str) -> str:
    if not _USER_RE.fullmatch(user) or len(user) > 256:
        raise StoreError(f"invalid user name {user!r}")
    return user


def check_finger(finger: str) -> str:
    if finger not in FINGERS:
        raise StoreError(f"unknown finger {finger!r}; expected one of: {', '.join(FINGERS)}")
    return finger


@dataclass
class Template:
    user: str
    finger: str
    images: list[np.ndarray]
    features: list[Features] = field(default_factory=list)


class TemplateStore:
    def __init__(self, root: str = DEFAULT_ROOT) -> None:
        self.root = root

    def _path(self, user: str, finger: str | None = None) -> str:
        d = os.path.join(self.root, check_user(user))
        return d if finger is None else os.path.join(d, check_finger(finger) + ".npz")

    # -- queries -----------------------------------------------------------------

    def users(self) -> list[str]:
        try:
            names = os.listdir(self.root)
        except FileNotFoundError:
            return []
        return sorted(u for u in names if _USER_RE.fullmatch(u) and self.fingers(u))

    def fingers(self, user: str) -> list[str]:
        try:
            names = os.listdir(self._path(user))
        except FileNotFoundError:
            return []
        return [f for f in FINGERS if f + ".npz" in names]

    def load(self, user: str, finger: str, matcher: FeatureMatcher | None = None) -> Template:
        """Read a template. Features are rebuilt (and re-saved) if they came from
        another matcher version; that needs ``matcher``."""
        path = self._path(user, finger)
        try:
            with np.load(path, allow_pickle=False) as z:
                meta = json.loads(str(z["meta"]))
                if meta.get("format") != FORMAT_VERSION:
                    raise StoreError(f"{path}: unsupported format {meta.get('format')!r}")
                images = list(z["images"])
                counts = z["counts"]
                pts, desc = z["pts"], z["desc"]
        except FileNotFoundError:
            raise StoreError(f"no template for {user}/{finger}") from None
        except (KeyError, ValueError, OSError) as e:
            raise StoreError(f"{path}: unreadable template ({e})") from e
        if len(counts) != len(images) or int(counts.sum()) != len(pts) or len(pts) != len(desc):
            raise StoreError(f"{path}: inconsistent template arrays")
        t = Template(user, finger, images)
        if meta.get("matcher") == MATCHER_VERSION:
            ends = np.cumsum(counts)
            t.features = [Features(pts[e - n:e], desc[e - n:e]) for e, n in zip(ends, counts)]
        elif matcher is not None:
            t.features = [matcher.extract(im) for im in images]
            self.save(t)
        else:
            raise StoreError(f"{path}: features are from matcher v{meta.get('matcher')}, "
                             f"need v{MATCHER_VERSION}; pass a Matcher to rebuild them")
        return t

    # -- changes -----------------------------------------------------------------

    def save(self, t: Template) -> str:
        if not t.images or len(t.features) != len(t.images):
            raise StoreError("template needs one feature set per image")
        for im in t.images:
            if im.shape != IMAGE_SHAPE or im.dtype != np.uint8:
                raise StoreError(f"image must be {IMAGE_SHAPE} uint8, got {im.shape} {im.dtype}")
        path = self._path(t.user, t.finger)
        _makedirs_private(os.path.dirname(path))
        meta = {"format": FORMAT_VERSION, "matcher": MATCHER_VERSION, "user": t.user, "finger": t.finger}
        fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path), prefix=".tmp-", suffix=".npz")
        try:
            with os.fdopen(fd, "wb") as f:
                np.savez(
                    f,
                    meta=np.array(json.dumps(meta)),
                    images=np.stack(t.images),
                    counts=np.array([len(x) for x in t.features], dtype=np.int32),
                    pts=np.concatenate([x.pts for x in t.features]).astype(np.float32),
                    desc=np.concatenate([x.desc for x in t.features]).astype(np.float32),
                )
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, path)  # mkstemp already made it 0600
        except BaseException:
            os.unlink(tmp)
            raise
        return path

    def delete(self, user: str, finger: str | None = None) -> list[str]:
        """Delete one finger, or all of a user's fingers. Returns what was deleted."""
        fingers = [check_finger(finger)] if finger is not None else self.fingers(user)
        gone = []
        for f in fingers:
            try:
                os.unlink(self._path(user, f))
                gone.append(f)
            except FileNotFoundError:
                pass
        try:
            os.rmdir(self._path(user))
        except OSError:
            pass  # not empty, or already gone
        return gone


def _makedirs_private(d: str) -> None:
    os.makedirs(d, mode=0o700, exist_ok=True)
    os.chmod(d, 0o700)
    parent = os.path.dirname(d)
    if parent and os.path.isdir(parent):
        os.chmod(parent, 0o700)
