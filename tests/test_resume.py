"""Tests for post-suspend re-initialization in validitysensor.init."""
import validitysensor.init as init


class FakeUsb:
    def __init__(self, events, reopen_fails=False):
        self._events = events
        self._reopen_fails = reopen_fails

    def reopen(self):
        self._events.append('reopen')
        if self._reopen_fails:
            raise Exception('USB device was never opened; cannot reopen')

    def open(self):
        self._events.append('open')


def test_resume_reopens_usb_and_reinitializes(monkeypatch):
    monkeypatch.setattr(init, 'INIT_RETRY_DELAY', 0)
    events = []
    monkeypatch.setattr(init, 'usb', FakeUsb(events))
    monkeypatch.setattr(init, 'open_common', lambda: events.append('open_common'))
    monkeypatch.setattr(init.tls, 'reset', lambda: events.append('tls_reset'))

    init.resume()

    assert events[0] == 'tls_reset'
    assert 'reopen' in events
    assert events[-1] == 'open_common'


def test_resume_falls_back_to_fresh_open(monkeypatch):
    monkeypatch.setattr(init, 'INIT_RETRY_DELAY', 0)
    events = []
    monkeypatch.setattr(init, 'usb', FakeUsb(events, reopen_fails=True))
    monkeypatch.setattr(init, 'open_common', lambda: events.append('open_common'))
    monkeypatch.setattr(init.tls, 'reset', lambda: events.append('tls_reset'))

    init.resume()

    assert 'open' in events
    assert events[-1] == 'open_common'
