"""Tests for the packaged systemd unit.

The unit must not enable debug logging by default and must throttle restarts
so a stuck sensor can never produce an unbounded restart loop.
"""
from configparser import ConfigParser
from pathlib import Path


def _unit():
    unit_path = Path(__file__).resolve().parents[1] / 'debian' / 'python3-validity.service'
    parser = ConfigParser()
    parser.read(unit_path)
    return parser


def test_debug_is_not_enabled_by_default():
    exec_start = _unit().get('Service', 'ExecStart')
    assert '--debug' not in exec_start


def test_restart_is_throttled():
    parser = _unit()
    assert parser.get('Service', 'Restart') == 'on-failure'
    assert parser.getint('Service', 'RestartSec') >= 1
    assert parser.getint('Unit', 'StartLimitBurst') >= 1
    assert parser.getint('Unit', 'StartLimitIntervalSec') >= 60
