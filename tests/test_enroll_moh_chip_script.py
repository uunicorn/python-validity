"""Tests for scripts/enroll_moh_chip.py argument handling (no hardware)."""
import importlib.util
import os

import pytest

from validitysensor.db import db
from validitysensor.sid import SidIdentity

_PATH = os.path.join(os.path.dirname(__file__), '..', 'scripts', 'enroll_moh_chip.py')
spec = importlib.util.spec_from_file_location('enroll_moh_chip', _PATH)
script = importlib.util.module_from_spec(spec)
spec.loader.exec_module(script)


class Rec:
    def __init__(self, type):
        self.type = type


def test_user_sid_is_parsed_into_sid_identity(monkeypatch):
    seen = {}

    def lookup_user(identity):
        seen['identity'] = identity
        return None

    monkeypatch.setattr(db, 'lookup_user', lookup_user)
    monkeypatch.setattr(db, 'new_user', lambda identity: 11)
    assert script.resolve_parent(None, 'S-1-5-21-1-2-3') == 11
    assert isinstance(seen['identity'], SidIdentity)


def test_parent_dbid_must_be_a_user_record(monkeypatch):
    monkeypatch.setattr(db, 'get_record_value', lambda dbid: Rec(6))
    with pytest.raises(ValueError, match='type 6'):
        script.resolve_parent(5, None)


def test_valid_parent_dbid_is_returned(monkeypatch):
    monkeypatch.setattr(db, 'get_record_value', lambda dbid: Rec(5))
    assert script.resolve_parent(6, None) == 6


def test_parent_or_user_sid_is_required():
    with pytest.raises(ValueError):
        script.resolve_parent(None, None)


def test_try_match_waits_for_finger_lift_before_identify(monkeypatch):
    import logging
    from validitysensor import sensor as sensor_mod
    events = []
    monkeypatch.setattr(script, 'sleep', lambda s: events.append(('sleep', s)))
    monkeypatch.setattr(sensor_mod.sensor, 'identify',
                        lambda cb: events.append('identify') or (1, 0xf5, b''))
    assert script._try_match(logging.getLogger('t'), settle=2.5) is True
    assert events == [('sleep', 2.5), 'identify']
