"""Behavioural tests for the MoH enrollment driver and the streamed capture.

The chip/USB layer is stubbed; the feature pipeline runs for real on a
synthetic frame.  Run: PYTHONPATH=. python -m pytest tests/test_moh_enrollment.py
"""
from struct import pack, unpack

import numpy as np
import pytest

from validitysensor import db as db_mod
from validitysensor import moh_enrollment as me
from validitysensor import sensor as sensor_mod
from validitysensor.usb import usb, CancelledException


def _frame_bytes(seed=7):
    rng = np.random.default_rng(seed)
    yy, xx = np.mgrid[0:112, 0:112]
    img = np.full((112, 112), 128.0)
    for _ in range(60):
        cy, cx = rng.integers(8, 104, 2)
        img += rng.uniform(-90, 90) * np.exp(
            -((yy - cy) ** 2 + (xx - cx) ** 2) / (2 * rng.uniform(2, 6) ** 2))
    return np.clip(img + rng.normal(0, 8, img.shape), 0, 255).astype(np.uint8).tobytes()


FRAME = _frame_bytes()


class FakeSensor:
    """capture() replays `script`: an Exception is raised, a callable is run
    as a side effect (then a frame is returned), anything else → a frame."""

    def __init__(self, script):
        self.script = list(script)
        self.calls = 0

    def capture(self, mode):
        self.calls += 1
        item = self.script.pop(0)
        if isinstance(item, Exception):
            raise item
        if callable(item):
            item()
        return 112, 112, 0, 0, FRAME


@pytest.fixture
def chip(monkeypatch):
    """Silence LED/flash/tls side effects; record 0x47 stores."""
    monkeypatch.setattr(sensor_mod, 'glow_start_scan', lambda: None)
    monkeypatch.setattr(sensor_mod, 'glow_end_scan', lambda: None)
    monkeypatch.setattr(me, 'sleep', lambda s: None)
    monkeypatch.setattr(me.db, 'db_info',
                        lambda: db_mod.Db.Info(524288, 0, 523520, 1, [4]))
    monkeypatch.setattr(db_mod, 'call_cleanups', lambda: None)
    usb.cancel = False
    state = {'status': 0, 'msgs': []}

    def cmd(msg):
        state['msgs'].append(msg)
        return pack('<HH', state['status'], 0x2a)

    monkeypatch.setattr(db_mod.tls, 'cmd', cmd)
    return state


def _enroll(sensor, chip, parent=5, num_frames=2, update_cb=None):
    return me.enroll_moh(sensor, parent, 0xf5,
                         update_cb=update_cb or (lambda *a: None),
                         num_frames=num_frames, min_frame_pool=0)


def test_store_rejection_fails_without_recapturing(chip):
    chip['status'] = 0x04b3
    sensor = FakeSensor(['ok'] * 12)
    with pytest.raises(Exception, match='04b3'):
        _enroll(sensor, chip, num_frames=2)
    assert sensor.calls == 2


def test_store_uses_uncounted_one_byte_trailer(chip):
    _enroll(FakeSensor(['ok']), chip, num_frames=1)
    msg = chip['msgs'][-1]
    _, _, _, _, size = unpack('<BHHHH', msg[:9])
    assert size == 23136
    assert len(msg) == 9 + size + 1 and msg[-1] == 0


def test_failed_capture_reports_retry_to_update_cb(chip):
    sensor = FakeSensor([Exception('Scanning problem: 8080000'), 'ok', 'ok'])
    events = []
    _enroll(sensor, chip, num_frames=2, update_cb=lambda rsp, e: events.append(e))
    errors = [e for e in events if e is not None]
    assert len(errors) == 1
    assert 'Scanning problem' in str(errors[0])


def test_cancel_during_extraction_aborts_before_next_capture(chip):
    # Cancel lands after capture returned, while features are being extracted.
    sensor = FakeSensor([lambda: setattr(usb, 'cancel', True), 'ok'])
    with pytest.raises(CancelledException):
        _enroll(sensor, chip, num_frames=2)
    assert sensor.calls == 1


def test_parent_is_resolved_only_after_all_captures(chip):
    events = []

    class S(FakeSensor):
        def capture(self, mode):
            events.append('capture')
            return super().capture(mode)

    def resolve():
        events.append('resolve')
        return 7

    _enroll(S(['ok', 'ok']), chip, parent=resolve, num_frames=2)
    assert events == ['capture', 'capture', 'resolve']
    _, parent, typ, storage, _ = unpack('<BHHHH', chip['msgs'][-1][:9])
    assert (parent, typ, storage) == (7, 6, 3)


# ─── Sensor.capture() capture-stop handling ─────────────────────────────

def _prg_status(x, y, img):
    hdr = pack('<HHHHL', x, y, 0, 0, 0)
    return b'\x00\x00' + pack('<L', len(hdr) + len(img)) + hdr + img


@pytest.fixture
def cap(monkeypatch):
    s = sensor_mod.Sensor()
    app_calls = []
    monkeypatch.setattr(s, 'build_cmd_02', lambda mode: b'\x02', raising=False)
    monkeypatch.setattr(sensor_mod.tls, 'app', lambda c: app_calls.append(c) or b'\x00\x00')
    monkeypatch.setattr(sensor_mod, 'assert_status', lambda r: None)
    return s, app_calls


def _wait_int_seq(monkeypatch, seq):
    it = iter(seq)

    def wait_int():
        v = next(it)
        if isinstance(v, Exception):
            raise v
        return v

    monkeypatch.setattr(sensor_mod.usb, 'wait_int', wait_int)


def test_capture_sends_stop_when_moh_capture_is_interrupted(cap, monkeypatch):
    s, app_calls = cap
    monkeypatch.setattr(sensor_mod, 'moh_enroll', lambda: True)
    _wait_int_seq(monkeypatch, [b'\x00', CancelledException()])
    with pytest.raises(CancelledException):
        s.capture(sensor_mod.CaptureMode.ENROLL)
    assert b'\x04' in app_calls


def test_capture_skips_stop_after_completed_moh_capture(cap, monkeypatch):
    s, app_calls = cap
    monkeypatch.setattr(sensor_mod, 'moh_enroll', lambda: True)
    _wait_int_seq(monkeypatch, [b'\x00', b'\x02', bytes([3, 0, 4])])
    monkeypatch.setattr(sensor_mod, 'get_prg_status2', lambda: _prg_status(2, 2, b'abcd'))
    x, y, _, _, img = s.capture(sensor_mod.CaptureMode.ENROLL)
    assert (x, y, img) == (2, 2, b'abcd')
    assert b'\x04' not in app_calls


def test_capture_always_sends_stop_on_legacy_devices(cap, monkeypatch):
    s, app_calls = cap
    monkeypatch.setattr(sensor_mod, 'moh_enroll', lambda: False)
    _wait_int_seq(monkeypatch, [b'\x00', b'\x02', bytes([3, 0, 4])])
    monkeypatch.setattr(sensor_mod, 'get_prg_status2', lambda: _prg_status(2, 2, b''))
    s.capture(sensor_mod.CaptureMode.IDENTIFY)
    assert b'\x04' in app_calls


def test_capture_size_mismatch_message_contains_lengths(cap, monkeypatch):
    s, _ = cap
    monkeypatch.setattr(sensor_mod, 'moh_enroll', lambda: False)
    _wait_int_seq(monkeypatch, [b'\x00', b'\x02', bytes([3, 0, 4])])
    bad = b'\x00\x00' + pack('<L', 99) + pack('<HHHHL', 2, 2, 0, 0, 0)
    monkeypatch.setattr(sensor_mod, 'get_prg_status2', lambda: bad)
    with pytest.raises(Exception, match='99 != 12'):
        s.capture(sensor_mod.CaptureMode.ENROLL)


# ─── Sensor.enroll(): user record must not be created before a capture ──

def test_enroll_creates_user_only_after_moh_captures(chip, monkeypatch):
    events = []
    s = sensor_mod.Sensor()
    monkeypatch.setattr(s, 'capture', lambda mode: events.append('capture') or (112, 112, 0, 0, FRAME),
                        raising=False)
    monkeypatch.setattr(sensor_mod, 'moh_enroll', lambda: True)
    monkeypatch.setattr(sensor_mod.db, 'lookup_user', lambda i: events.append('lookup') or None)
    monkeypatch.setattr(sensor_mod.db, 'new_user', lambda i: events.append('new_user') or 9)
    real_enroll_moh = me.enroll_moh
    monkeypatch.setattr(me, 'enroll_moh',
                        lambda sensor, parent, subtype, **kw: real_enroll_moh(
                            sensor, parent, subtype, num_frames=1, min_frame_pool=0, **kw))
    s.enroll('S-1-5-21-1', 0xf5, lambda *a: None)
    assert events == ['capture', 'lookup', 'new_user']


def test_stale_cancel_from_previous_operation_is_ignored(chip):
    # open-fprintd sends Cancel after each verify and enrollment; nothing
    # clears the flag until the next wait_int(), so it is still set when the
    # next enrollment starts.
    usb.cancel = True
    _enroll(FakeSensor(['ok', 'ok']), chip, num_frames=2)
    assert chip['msgs']


def test_store_fails_clearly_when_template_partition_is_full(chip, monkeypatch):
    monkeypatch.setattr(me.db, 'db_info',
                        lambda: db_mod.Db.Info(524288, 1536, 21248, 31, [4]))
    with pytest.raises(Exception, match='storage full'):
        _enroll(FakeSensor(['ok']), chip, num_frames=1)
    assert chip['msgs'] == []
