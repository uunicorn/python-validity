"""Tests for flash-info parsing and safe handling of an unidentified flash IC.

These tests do not need the fingerprint sensor; they stub the USB/TLS layer.
"""
import pytest

from validitysensor.flash import FlashInfo, get_flash_info


def test_get_flash_info_parses_full_reply(monkeypatch):
    import validitysensor.flash as flash

    # status 0000 + header (jid0=0xef, jid1=0x40 -> W25Q80B, 0x100 * 0x1000 = 1 MiB, pcnt=0)
    header = (0x00EF, 0x0040, 0x0100, 0x0000, 0x1000, 0x0000, 0x0000)
    reply = b'\x00\x00' + b''.join(int(v).to_bytes(2, 'little') for v in header)
    monkeypatch.setattr(flash.tls, 'cmd', lambda cmd: reply)

    info = get_flash_info()

    assert info.ic is not None
    assert info.ic.name == 'W25Q80B'
    assert info.partitions == []


def test_get_flash_info_short_reply_returns_empty_flashinfo(monkeypatch):
    import validitysensor.flash as flash

    # Uninitialized 06cb:009a replies with only the 2-byte status word.
    monkeypatch.setattr(flash.tls, 'cmd', lambda cmd: b'\x00\x00')

    info = get_flash_info()

    assert isinstance(info, FlashInfo)
    assert info.ic is None
    assert info.partitions == []


def test_init_flash_refuses_to_format_without_identified_ic(monkeypatch):
    import validitysensor.init_flash as init_flash

    monkeypatch.setattr(init_flash, 'get_flash_info', lambda: FlashInfo(None, 0, 0, 0, 0, []))
    monkeypatch.setattr(init_flash.usb, 'cmd', lambda cmd: b'\x00\x00')

    with pytest.raises(Exception, match='flash IC could not be identified'):
        init_flash.init_flash()
