"""Tests for the transient-busy command retry helper in validitysensor.usb."""
import errno

from usb.core import USBError

from validitysensor.usb import Usb


def _no_sleep(monkeypatch):
    import validitysensor.usb as usbmod

    monkeypatch.setattr(usbmod, 'CMD_RETRY_DELAY', 0)


def test_retries_transient_busy_status(monkeypatch):
    _no_sleep(monkeypatch)
    usb = Usb()
    responses = iter([b'\x04\x01', b'\x04\x01', b'\x00\x00payload'])
    usb.cmd = lambda out: next(responses)

    assert usb.cmd_retry_busy(b'\x01') == b'\x00\x00payload'


def test_retries_transient_usb_timeout(monkeypatch):
    _no_sleep(monkeypatch)
    usb = Usb()
    calls = []

    def cmd(out):
        calls.append(out)
        if len(calls) == 1:
            raise USBError('Operation timed out', errno=errno.ETIMEDOUT)
        return b'\x00\x00ok'

    usb.cmd = cmd

    assert usb.cmd_retry_busy(b'\x01') == b'\x00\x00ok'
    assert len(calls) == 2


def test_non_timeout_usb_error_is_not_retried(monkeypatch):
    _no_sleep(monkeypatch)
    usb = Usb()
    calls = []

    def cmd(out):
        calls.append(out)
        raise USBError('No such device', errno=errno.ENODEV)

    usb.cmd = cmd

    try:
        usb.cmd_retry_busy(b'\x01')
    except USBError:
        pass
    else:
        raise AssertionError('USBError should propagate')

    assert len(calls) == 1


def test_bounded_when_sensor_stays_busy(monkeypatch):
    import validitysensor.usb as usbmod

    _no_sleep(monkeypatch)
    monkeypatch.setattr(usbmod, 'CMD_RETRY_ATTEMPTS', 3)
    usb = Usb()
    calls = []

    def cmd(out):
        calls.append(out)
        return b'\x04\x01'

    usb.cmd = cmd

    assert usb.cmd_retry_busy(b'\x01') == b'\x04\x01'
    assert len(calls) == 3
