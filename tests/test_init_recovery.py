"""Tests for bounded init recovery (USB reset/re-open) in validitysensor.init."""
import pytest

import validitysensor.init as init


class FakeUsb:
    def __init__(self, events):
        self._events = events

    def reset(self):
        self._events.append('reset')

    def reopen(self):
        self._events.append('reopen')


def test_open_with_recovery_resets_and_retries(monkeypatch):
    monkeypatch.setattr(init, 'INIT_RETRY_DELAY', 0)
    attempts = {'n': 0}
    events = []
    monkeypatch.setattr(init, 'usb', FakeUsb(events))

    def fake_open_common():
        attempts['n'] += 1
        if attempts['n'] < 3:
            raise RuntimeError('USBTimeoutError: [Errno 110] Operation timed out')

    monkeypatch.setattr(init, 'open_common', fake_open_common)

    init._open_with_recovery(lambda: events.append('open'))

    assert attempts['n'] == 3
    assert events.count('reopen') == 2


def test_open_with_recovery_gives_up_bounded(monkeypatch):
    monkeypatch.setattr(init, 'INIT_RETRY_DELAY', 0)
    monkeypatch.setattr(init, 'INIT_ATTEMPTS', 3)
    attempts = {'n': 0}
    events = []
    monkeypatch.setattr(init, 'usb', FakeUsb(events))

    def always_fail():
        attempts['n'] += 1
        raise RuntimeError('stuck sensor')

    monkeypatch.setattr(init, 'open_common', always_fail)

    with pytest.raises(RuntimeError, match='stuck sensor'):
        init._open_with_recovery(lambda: events.append('open'))

    assert attempts['n'] == 3
    # No reset after the final attempt.
    assert events.count('reopen') == 2


def test_reboot_exception_is_not_retried(monkeypatch):
    monkeypatch.setattr(init, 'INIT_RETRY_DELAY', 0)
    events = []
    monkeypatch.setattr(init, 'usb', FakeUsb(events))

    def rebooted():
        raise init.RebootException()

    monkeypatch.setattr(init, 'open_common', rebooted)

    with pytest.raises(init.RebootException):
        init._open_with_recovery(lambda: events.append('open'))

    assert 'reopen' not in events


def test_open_common_loads_firmware_before_flash(monkeypatch):
    order = []
    monkeypatch.setattr(init, 'init_data_dir', lambda: order.append('init_data_dir'))
    monkeypatch.setattr(init.usb, 'send_init', lambda: order.append('send_init'))
    monkeypatch.setattr(init, 'init_flash', lambda: order.append('init_flash'))
    monkeypatch.setattr(init, 'read_tls_flash', lambda: b'')
    monkeypatch.setattr(init.tls, 'parse_tls_flash', lambda b: order.append('parse_tls_flash'))
    monkeypatch.setattr(init.tls, 'open', lambda: order.append('tls_open'))
    monkeypatch.setattr(init, 'upload_fwext', lambda: order.append('upload_fwext'))
    monkeypatch.setattr(init.sensor, 'open', lambda: order.append('sensor_open'))
    monkeypatch.setattr(init, 'init_db', lambda: order.append('init_db'))
    monkeypatch.setattr(init.atexit, 'register', lambda fn: None)
    monkeypatch.setattr(init, '_close_registered', False)

    init.open_common()

    assert order.index('send_init') < order.index('init_flash')
    assert order[-1] == 'init_db'


def test_close_ignores_unexpected_reboot_errors(monkeypatch):
    events = []

    class FakeUsb:
        dev = object()

        def close(self):
            events.append('close')

    monkeypatch.setattr(init, 'usb', FakeUsb())

    def failing_reboot():
        raise RuntimeError('device already gone')

    monkeypatch.setattr(init, 'reboot', failing_reboot)

    # Must not propagate: this runs from atexit during shutdown/suspend.
    init.close()

    assert events == ['close']


def test_close_handles_reboot_exception(monkeypatch):
    events = []

    class FakeUsb:
        dev = object()

        def close(self):
            events.append('close')

    monkeypatch.setattr(init, 'usb', FakeUsb())

    def reboot_exc():
        raise init.RebootException()

    monkeypatch.setattr(init, 'reboot', reboot_exc)

    init.close()

    assert events == ['close']
