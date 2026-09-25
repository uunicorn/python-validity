"""The D-Bus device logic for sensors matched on the host, without D-Bus.

dbus-service puts this behind ``io.github.uunicorn.Fprint.Device``; keeping it
separate lets the tests drive it with a fake session and matcher.

Each enroll or verify runs on a worker thread with its own session (stored
pairing resume, about 1 s) that is closed with ``05 02 00`` when the operation
ends, so nothing holds the device between operations. Only one operation runs
at a time: the TLS and USB state are process-wide singletons.

Status strings are fprintd's. A cancelled operation reports nothing, as fprintd
does after ``VerifyStop``/``EnrollStop``. fprintd's ``finger-needed`` and
``finger-present`` properties follow the sensor: needed from arming a capture,
present from the finger-detect, both cleared when the capture ends.
"""

from __future__ import annotations

import logging
import threading
from typing import Callable, Protocol

from ..sensor_2449 import Cancelled
from . import ops
from .matcher import FeatureMatcher
from .store import FINGERS, StoreError, Template, TemplateStore, check_finger, check_user

log = logging.getLogger(__name__)

# emit(signal name, *args): VerifyStatus(result, done), VerifyFingerSelected(finger),
# EnrollStatus(result, done) or PropertiesChanged({name: value}). Called from the
# worker thread.
Emit = Callable[..., None]


class Busy(Exception):
    """Another enroll or verify is running."""


class NoEnrolledPrints(Exception):
    pass


class InvalidFinger(Exception):
    pass


class _Session(Protocol):
    @property
    def sensor(self) -> ops.PrintSource | None: ...

    def close(self) -> None: ...


class DeviceSession:
    """A session with a flashless sensor, open until close()."""

    def __init__(self, vendor: int, product: int) -> None:
        from .. import init
        from ..usb import usb

        self._init = init
        usb.open(vendor, product)
        try:
            self.sensor = init.open_flashless()
        except BaseException:
            init.close_flashless()
            raise

    def close(self) -> None:
        self._init.close_flashless()


class _FingerTracking:
    """A print source that reports finger-needed / finger-present as it goes."""

    def __init__(self, source: ops.PrintSource, set_finger: Callable[[bool, bool], None]) -> None:
        self.source = source
        self.set_finger = set_finger

    def get_print(self, *, touch_timeout: float = 15.0, on_armed: Callable[[], None] | None = None,
                  cancel: threading.Event | None = None,
                  on_touch: Callable[[], None] | None = None) -> ops._PrintResult:
        def armed() -> None:
            self.set_finger(True, False)
            if on_armed is not None:
                on_armed()

        def touched() -> None:
            self.set_finger(True, True)
            if on_touch is not None:
                on_touch()

        try:
            result = self.source.get_print(touch_timeout=touch_timeout, on_armed=armed,
                                           cancel=cancel, on_touch=touched)
        except TimeoutError:
            raise  # nobody touched: ops re-arms at once, so the finger is still needed
        except BaseException:
            self.set_finger(False, False)
            raise
        self.set_finger(False, False)
        return result


def _is_disconnect(e: BaseException) -> bool:
    from usb.core import USBError

    from ..usb import DeviceNotFound

    return isinstance(e, (USBError, DeviceNotFound))


class Backend:
    def __init__(self, store: TemplateStore, matcher: FeatureMatcher, emit: Emit, *,
                 open_session: Callable[[], _Session],
                 stages: int = ops.ENROLL_STAGES,
                 lift_delay: float = ops.LIFT_DELAY_S) -> None:
        self.store = store
        self.matcher = matcher
        self.emit = emit
        self.open_session = open_session
        self.stages = stages
        self.lift_delay = lift_delay
        self._lock = threading.Lock()
        self._worker: threading.Thread | None = None
        self._cancel = threading.Event()
        self._finger = {"finger-needed": False, "finger-present": False}

    @property
    def properties(self) -> dict[str, object]:
        return {"name": "Synaptics 06cb:00a8", "num-enroll-stages": self.stages,
                "scan-type": "press", **self._finger}

    # -- template database ---------------------------------------------------------

    def list_enrolled_fingers(self, user: str) -> list[str]:
        return self.store.fingers(check_user(user))

    def delete_enrolled_fingers(self, user: str) -> None:
        gone = self.store.delete(check_user(user))
        log.info("deleted %s for %s", ", ".join(gone) or "nothing", user)

    def delete_enrolled_finger(self, user: str, finger: str) -> None:
        gone = self.store.delete(check_user(user), _finger(finger))
        log.info("deleted %s for %s", ", ".join(gone) or "nothing", user)

    # -- operations -----------------------------------------------------------------

    def enroll_start(self, user: str, finger: str) -> None:
        check_user(user)
        _finger(finger)

        def run(session: _Session, cancel: threading.Event) -> None:
            t = ops.enroll(self._tracking(session), self.matcher, user, finger, stages=self.stages,
                           lift_delay=self.lift_delay, cancel=cancel,
                           on_status=lambda s: self.emit("EnrollStatus", s, False))
            path = self.store.save(t)
            log.info("enrolled %s/%s -> %s", user, finger, path)
            self.emit("EnrollStatus", "enroll-completed", True)

        self._start("enroll", run)

    def verify_start(self, user: str, finger: str) -> None:
        """``finger`` is a finger name, or ``any`` (or empty) for all of the user's."""
        check_user(user)
        if finger in ("", "any"):
            fingers, selected = self.store.fingers(user), "any"
        else:
            fingers, selected = [_finger(finger)], finger
            if finger not in self.store.fingers(user):
                fingers = []
        templates = self._load(user, fingers)
        if not templates:
            raise NoEnrolledPrints(f"no enrolled prints for {user}")

        def run(session: _Session, cancel: threading.Event) -> None:
            r = ops.verify(self._tracking(session), self.matcher, templates, cancel=cancel,
                           on_status=lambda s: self.emit("VerifyStatus", s, False))
            log.info("verify %s: %s (best %s, score %g)", user, "match" if r.matched else "no match",
                     r.finger, r.score)
            self.emit("VerifyStatus", "verify-match" if r.matched else "verify-no-match", True)

        self._start("verify", run, announce=lambda: self.emit("VerifyFingerSelected", selected))

    def cancel(self) -> None:
        """Stop the running operation, if any. Returns at once; the worker closes its
        session in the background and the next operation waits for that."""
        with self._lock:
            self._cancel.set()

    def join(self, timeout: float | None = None) -> None:
        w = self._worker
        if w is not None:
            w.join(timeout)

    # -- internals ------------------------------------------------------------------

    def _tracking(self, session: _Session) -> _FingerTracking:
        assert session.sensor is not None
        return _FingerTracking(session.sensor, self._set_finger)

    def _set_finger(self, needed: bool, present: bool) -> None:
        """Worker thread only."""
        new = {"finger-needed": needed, "finger-present": present}
        changed = {k: v for k, v in new.items() if self._finger[k] != v}
        if changed:
            self._finger = new
            self.emit("PropertiesChanged", changed)

    def _load(self, user: str, fingers: list[str]) -> list[Template]:
        templates = []
        for f in fingers:
            try:
                templates.append(self.store.load(user, f, self.matcher))
            except StoreError as e:
                log.error("skipping %s/%s: %s", user, f, e)
        return templates

    def _start(self, kind: str, fn: Callable[[_Session, threading.Event], None],
               announce: Callable[[], None] | None = None) -> None:
        with self._lock:
            prev = self._worker
            if prev is not None and prev.is_alive() and not self._cancel.is_set():
                raise Busy(f"an operation is already running ({prev.name})")
            cancel = self._cancel = threading.Event()
            self._worker = threading.Thread(target=self._run, args=(kind, fn, cancel, prev),
                                            name=kind, daemon=True)
            if announce is not None:
                announce()  # before the worker can report anything
            self._worker.start()

    def _run(self, kind: str, fn: Callable[[_Session, threading.Event], None],
             cancel: threading.Event, prev: threading.Thread | None) -> None:
        signal = "EnrollStatus" if kind == "enroll" else "VerifyStatus"
        if prev is not None:
            prev.join()  # a cancelled operation still closing its session
        if cancel.is_set():
            return
        session = None
        try:
            session = self.open_session()
            if cancel.is_set():
                raise Cancelled()
            fn(session, cancel)
        except Cancelled:
            log.info("%s cancelled", kind)
        except Exception as e:
            if cancel.is_set():
                log.info("%s cancelled (%s)", kind, e)
            elif _is_disconnect(e):
                log.error("%s: device error: %s", kind, e)
                self.emit(signal, f"{kind}-disconnected", True)
            else:
                log.exception("%s failed", kind)
                self.emit(signal, "enroll-failed" if kind == "enroll" else "verify-unknown-error", True)
        finally:
            self._set_finger(False, False)
            if session is not None:
                try:
                    session.close()
                except Exception:
                    log.exception("closing the session failed")


def _finger(finger: str) -> str:
    try:
        return check_finger(finger)
    except StoreError:
        raise InvalidFinger(f"unknown finger {finger!r}; expected one of: {', '.join(FINGERS)}") from None
