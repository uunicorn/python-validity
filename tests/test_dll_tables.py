"""Firmware module extraction. The real DLL can't be shipped: set PV_DLL to a copy of
synaWudfBioUsb.dll 5.5.2707.1073 to run the extraction test."""

import hashlib
import os

import pytest

from validitysensor import dll_tables

# sha256 of each module, as sent by the Windows driver
MODULE_SHA256 = {
    'pair': '82b331568eccbced10cfada519d20fee6c96b6533b8be4a604969f7500e40237',
    'calibrate': '5a0799c9c90738f3f06c9e9f03db6299bf3096e481c0f17c9735c4a5087cc669',
    'capture': 'd39f049706df23087d123da9d8b94073272f55555d71878394ef44d296215f56',
}


@pytest.mark.skipif(not os.environ.get('PV_DLL'), reason='set PV_DLL to synaWudfBioUsb.dll')
def test_extract_known_dll():
    with open(os.environ['PV_DLL'], 'rb') as f:
        modules = dll_tables.extract(f.read())
    assert {k: hashlib.sha256(v).hexdigest() for k, v in modules.items()} == MODULE_SHA256


def test_extract_rejects_unknown_build():
    with pytest.raises(ValueError, match='Unknown synaWudfBioUsb.dll build'):
        dll_tables.extract(b'MZ' + b'\0' * 1000)


def test_save_and_load(tmp_path, monkeypatch):
    monkeypatch.setattr(dll_tables, '_cache', {})
    path = str(tmp_path / 'sub' / 'modules.json')
    dll_tables.save({'pair': b'\x01\x02', 'calibrate': b'\x03'}, path)
    assert dll_tables.module('pair', path) == b'\x01\x02'
    assert dll_tables.module('calibrate', path) == b'\x03'


def test_missing_modules_say_how_to_get_them(tmp_path, monkeypatch):
    monkeypatch.setattr(dll_tables, '_cache', {})
    with pytest.raises(dll_tables.MissingModules, match='validity-sensors-firmware --driver-dll'):
        dll_tables.module('pair', str(tmp_path / 'nothing.json'))
    path = str(tmp_path / 'modules.json')
    dll_tables.save({'pair': b'\x01'}, path)
    with pytest.raises(dll_tables.MissingModules, match='no "capture" module'):
        dll_tables.module('capture', path)
