"""hostmatch.backend and dbus-service's HostDevice, without hardware.

The backend tests use a fake session whose sensor replays synthetic touches. The D-Bus
test runs a private dbus-daemon and drives the exported device the way open-fprintd does.
"""

import importlib.machinery
import importlib.util
import os
import shutil
import subprocess
import threading
import time
from typing import Any

import pytest

from validitysensor.hostmatch.backend import Backend, Busy, InvalidFinger, NoEnrolledPrints
from validitysensor.hostmatch.store import TemplateStore
from validitysensor.sensor_2449 import Cancelled
from validitysensor.usb import DeviceNotFound
from test_hostmatch import ReplaySource, _fake_matcher, _touch

FINGER = "right-index-finger"


class FakeSession:
    def __init__(self, source):
        self.sensor = source
        self.closed = 0

    def close(self):
        self.closed += 1


class BlockingSource:
    """get_print() that waits until cancelled."""

    def __init__(self):
        self.waiting = threading.Event()

    def get_print(self, *, touch_timeout=15.0, on_armed=None, cancel=None, on_touch=None):
        if on_armed:
            on_armed()
        self.waiting.set()
        assert cancel is not None
        cancel.wait()
        raise Cancelled()


class Harness:
    def __init__(self, tmp_path, sources, stages=3):
        self.events = []
        self.finger = []  # PropertiesChanged payloads, kept apart from the statuses
        self.sessions = []
        self._sources = list(sources)
        self.store = TemplateStore(str(tmp_path / "store"))
        self.backend = Backend(self.store, _fake_matcher(), self._emit, open_session=self._open,
                               stages=stages, lift_delay=0)

    def _emit(self, name, *args):
        if name == "PropertiesChanged":
            self.finger.append(args[0])
        else:
            self.events.append((name, *args))

    def _open(self):
        src = self._sources.pop(0)
        if isinstance(src, BaseException):
            raise src
        s = FakeSession(src)
        self.sessions.append(s)
        return s

    def finish(self):
        self.backend.join(timeout=10)
        assert self.backend._worker is None or not self.backend._worker.is_alive()


def _enroll_source(finger=0, n=3):
    return ReplaySource([_touch(finger, i) for i in range(n)])


def test_enroll_saves_template_and_reports_stages(tmp_path):
    h = Harness(tmp_path, [_enroll_source()])
    h.backend.enroll_start("alice", FINGER)
    h.finish()
    assert h.events == [("EnrollStatus", "enroll-stage-passed", False)] * 3 + [
        ("EnrollStatus", "enroll-completed", True)]
    assert h.backend.list_enrolled_fingers("alice") == [FINGER]
    assert [s.closed for s in h.sessions] == [1]


NEEDED = {"finger-needed": True}
PRESENT = {"finger-present": True}
DONE = {"finger-needed": False, "finger-present": False}


def test_finger_needed_and_present_follow_each_capture(tmp_path):
    h = Harness(tmp_path, [_enroll_source()])
    h.backend.enroll_start("alice", FINGER)
    h.finish()
    assert h.finger == [NEEDED, PRESENT, DONE] * 3
    assert h.backend.properties["finger-needed"] is False


def test_finger_needed_cleared_on_cancel(tmp_path):
    src = BlockingSource()
    h = Harness(tmp_path, [src])
    h.backend.enroll_start("alice", FINGER)
    assert src.waiting.wait(5)
    assert h.backend.properties["finger-needed"] is True
    h.backend.cancel()
    h.finish()
    assert h.finger == [NEEDED, {"finger-needed": False}]


def test_verify_match_no_match_and_finger_selection(tmp_path):
    h = Harness(tmp_path, [_enroll_source(), ReplaySource([_touch(0, 10)]), ReplaySource([_touch(1, 0)])])
    h.backend.enroll_start("alice", FINGER)
    h.finish()
    h.events.clear()
    h.backend.verify_start("alice", "any")
    h.finish()
    h.backend.verify_start("alice", FINGER)
    h.finish()
    assert h.events == [
        ("VerifyFingerSelected", "any"), ("VerifyStatus", "verify-match", True),
        ("VerifyFingerSelected", FINGER), ("VerifyStatus", "verify-no-match", True)]
    assert all(s.closed == 1 for s in h.sessions)


def test_verify_without_prints_and_bad_names(tmp_path):
    h = Harness(tmp_path, [_enroll_source()])
    with pytest.raises(NoEnrolledPrints):
        h.backend.verify_start("alice", "any")
    h.backend.enroll_start("alice", FINGER)
    h.finish()
    with pytest.raises(NoEnrolledPrints):
        h.backend.verify_start("alice", "left-thumb")
    with pytest.raises(InvalidFinger):
        h.backend.verify_start("alice", "tentacle")
    with pytest.raises(InvalidFinger):
        h.backend.enroll_start("alice", "tentacle")
    assert not h.sessions[1:]  # none of these opened a session


def test_delete(tmp_path):
    h = Harness(tmp_path, [_enroll_source(), _enroll_source(1)])
    h.backend.enroll_start("alice", FINGER)
    h.finish()
    h.backend.enroll_start("alice", "left-thumb")
    h.finish()
    h.backend.delete_enrolled_finger("alice", FINGER)
    assert h.backend.list_enrolled_fingers("alice") == ["left-thumb"]
    h.backend.delete_enrolled_fingers("alice")
    assert h.backend.list_enrolled_fingers("alice") == []


def test_busy_cancel_and_restart(tmp_path):
    blocking = BlockingSource()
    h = Harness(tmp_path, [blocking, _enroll_source()])
    h.backend.enroll_start("alice", FINGER)
    assert blocking.waiting.wait(5)
    with pytest.raises(Busy):
        h.backend.enroll_start("alice", FINGER)
    h.backend.cancel()
    # A start straight after Cancel is accepted and waits for the old session to close.
    h.backend.enroll_start("alice", FINGER)
    h.finish()
    assert [s.closed for s in h.sessions] == [1, 1]
    assert h.events[-1] == ("EnrollStatus", "enroll-completed", True)
    assert ("EnrollStatus", "enroll-failed", True) not in h.events  # cancel reports nothing


def test_cancel_while_opening_session(tmp_path):
    h = Harness(tmp_path, [])
    opened = threading.Event()
    release = threading.Event()
    session = FakeSession(BlockingSource())

    def slow_open():
        opened.set()
        release.wait(5)
        return session

    h.backend.open_session = slow_open
    h.backend.enroll_start("alice", FINGER)
    assert opened.wait(5)
    h.backend.cancel()
    release.set()
    h.finish()
    assert h.events == [] and session.closed == 1


@pytest.mark.parametrize("error,enroll_status,verify_status", [
    (DeviceNotFound("gone"), "enroll-disconnected", "verify-disconnected"),
    (RuntimeError("boom"), "enroll-failed", "verify-unknown-error"),
])
def test_session_errors(tmp_path, error, enroll_status, verify_status):
    h = Harness(tmp_path, [_enroll_source(), error, error])
    h.backend.enroll_start("alice", FINGER)
    h.finish()
    h.events.clear()
    h.backend.enroll_start("alice", FINGER)
    h.finish()
    h.backend.verify_start("alice", "any")
    h.finish()
    assert h.events == [("EnrollStatus", enroll_status, True),
                        ("VerifyFingerSelected", "any"), ("VerifyStatus", verify_status, True)]


# -- over D-Bus -----------------------------------------------------------------------

@pytest.fixture
def bus_address():
    daemon = shutil.which("dbus-daemon")
    if daemon is None:
        pytest.skip("dbus-daemon not installed")
    p = subprocess.Popen([daemon, "--session", "--nofork", "--print-address=1"],
                         stdout=subprocess.PIPE, text=True)
    try:
        assert p.stdout is not None
        yield p.stdout.readline().strip()
    finally:
        p.terminate()
        p.wait(5)


def load_dbus_service():
    path = os.path.join(os.path.dirname(__file__), '..', 'dbus_service', 'dbus-service')
    loader = importlib.machinery.SourceFileLoader('dbus_service', path)
    spec = importlib.util.spec_from_loader('dbus_service', loader)
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


def test_host_device_over_dbus(tmp_path, bus_address):
    dbus = pytest.importorskip("dbus")
    pytest.importorskip("gi")
    import dbus.bus
    import dbus.service
    from gi.repository import GLib  # pyright: ignore[reportAttributeAccessIssue]

    ds = load_dbus_service()
    ctx = GLib.MainContext.default()

    def spin(cond, timeout=10.0):
        end = time.monotonic() + timeout
        while not cond():
            assert time.monotonic() < end, "timed out"
            ctx.iteration(False)
            time.sleep(0.001)

    client = dbus.bus.BusConnection(bus_address)
    dev_conn = dbus.bus.BusConnection(bus_address)

    h = Harness(tmp_path, [_enroll_source(), ReplaySource([_touch(0, 10)])])
    device = ds.HostDevice(dev_conn, lambda emit: Backend(h.store, _fake_matcher(), emit,
                                                          open_session=h._open, stages=3, lift_delay=0))
    path = "/io/github/uunicorn/Fprint/Device"

    signals = []
    client.add_signal_receiver(lambda *a, **kw: signals.append((kw["member"], *map(_plain, a))),
                               dbus_interface=ds.INTERFACE_NAME, member_keyword="member")
    changes = []
    client.add_signal_receiver(lambda i, c, inv: changes.append((str(i), _plain(c))),
                               "PropertiesChanged", dbus.PROPERTIES_IFACE)
    proxy = client.get_object(dev_conn.get_unique_name(), path, introspect=False)

    def call(method, *args, iface=ds.INTERFACE_NAME) -> Any:
        out = []
        getattr(proxy, method)(*args, dbus_interface=iface, reply_handler=lambda *r: out.append(("ok", r)),
                               error_handler=lambda e: out.append(("err", e.get_dbus_name())))
        spin(lambda: out)
        kind, value = out[0]
        return value if kind == "err" else (_plain(value[0]) if value else None)

    props = call("GetAll", ds.INTERFACE_NAME, iface=dbus.PROPERTIES_IFACE)
    assert props["num-enroll-stages"] == 3 and props["scan-type"] == "press"
    assert props["finger-needed"] is False and props["finger-present"] is False
    assert call("Get", ds.INTERFACE_NAME, "name", iface=dbus.PROPERTIES_IFACE) == "Synaptics 06cb:00a8"
    assert call("ListEnrolledFingers", "alice") == []
    assert call("VerifyStart", "alice", "any") == "net.reactivated.Fprint.Error.NoEnrolledPrints"
    assert call("EnrollStart", "alice", "tentacle") == "net.reactivated.Fprint.Error.InvalidFingername"
    assert call("RunCmd", "00") == "org.freedesktop.DBus.Error.UnknownMethod"

    call("EnrollStart", "alice", FINGER)
    spin(lambda: ("EnrollStatus", "enroll-completed", True) in signals)
    assert signals.count(("EnrollStatus", "enroll-stage-passed", False)) == 3
    spin(lambda: len(changes) == 9)
    assert changes == [(ds.INTERFACE_NAME, c) for c in [NEEDED, PRESENT, DONE] * 3]
    assert call("ListEnrolledFingers", "alice") == [FINGER]

    call("VerifyStart", "alice", "any")
    spin(lambda: ("VerifyStatus", "verify-match", True) in signals)
    assert ("VerifyFingerSelected", "any") in signals

    call("DeleteEnrolledFinger", "alice", FINGER)
    assert call("ListEnrolledFingers", "alice") == []
    device.backend.join(timeout=10)


def _plain(v):
    if isinstance(v, (list, tuple)) and not isinstance(v, str):
        return [_plain(x) for x in v]
    if isinstance(v, dict):
        return {str(k): _plain(x) for k, x in v.items()}
    if isinstance(v, bool) or type(v).__name__ == "Boolean":
        return bool(v)
    if isinstance(v, int):
        return int(v)
    if isinstance(v, str):
        return str(v)
    return v
