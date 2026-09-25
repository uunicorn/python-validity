"""Firmware modules for the flashless 06cb:00a8, taken from the Windows driver.

The flash-based sensors get their firmware extension from a .xpfwext file. 06cb:00a8 has
no flash to put one in; instead the host loads small modules into its RAM with command
0x06 as it goes (at pairing, before calibrating and before each capture). The modules
live in tables inside synaWudfBioUsb.dll, which we can't redistribute, so
validity-sensors-firmware extracts them from a copy of the DLL the user supplies and saves
them in PYTHON_VALIDITY_STATE_DIR.

The table offsets are specific to one build of the DLL, identified by its SHA-256.
"""

import hashlib
import json
import os
import typing
from struct import unpack_from

from .init_data_dir import PYTHON_VALIDITY_STATE_DIR

MODULES_PATH = PYTHON_VALIDITY_STATE_DIR + '06cb_00a8-modules.json'

# sha256 -> (version, module table file offset, number of records)
KNOWN_DLLS = {
    '7376e20f2be62bcdc3a92580766a7d006c976b28bff7450f25c3b3a3af4e28a3': ('5.5.2707.1073', 0x15e004, 66),
}

MODULE_RECORD_LEN = 80

# name -> (kind bitmask, table half, ROM). Each was matched byte for byte against a USB
# capture of the Windows driver talking to 06cb:00a8 (issue #179).
MODULES = {
    # 0x06 at pairing, before 0x4f/0x50. The device reports ROM 6/0x14 but this
    # module is tagged 6/0x15.
    'pair': (0x000004, 2, (6, 0x15)),
    # 0x06 before the first CALIBRATE
    'calibrate': (0x000080, 2, (6, 0x14)),
    # 0x06 before the first IDENTIFY capture of a session
    'capture': (0x400080, 2, (6, 0x14)),
}


class MissingModules(Exception):
    def __init__(self, detail: str):
        super().__init__('%s. Run validity-sensors-firmware --driver-dll /path/to/synaWudfBioUsb.dll '
                         'as root to extract the firmware modules from the Windows driver.' % detail)


class _PE:
    """Just enough of a PE parser to map a virtual address to a file offset."""

    def __init__(self, data: bytes):
        self.data = data
        e, = unpack_from('<I', data, 0x3c)
        if data[e:e + 4] != b'PE\0\0':
            raise ValueError('Not a PE file')
        nsec, = unpack_from('<H', data, e + 6)
        opt, = unpack_from('<H', data, e + 20)
        self.image_base, = unpack_from('<Q', data, e + 24 + 24)
        self.sections = []
        for i in range(nsec):
            vsize, vaddr, rawsize, rawptr = unpack_from('<IIII', data, e + 24 + opt + i * 40 + 8)
            self.sections.append((vaddr, vsize, rawptr, rawsize))

    def read(self, va: int, length: int) -> bytes:
        rva = va - self.image_base
        for vaddr, vsize, rawptr, rawsize in self.sections:
            if vaddr <= rva < vaddr + max(vsize, rawsize):
                off = rawptr + rva - vaddr
                return self.data[off:off + length]
        raise ValueError('VA 0x%x is outside every section' % va)


def extract(dll: bytes) -> typing.Dict[str, bytes]:
    """The MODULES from a copy of synaWudfBioUsb.dll."""
    digest = hashlib.sha256(dll).hexdigest()
    if digest not in KNOWN_DLLS:
        raise ValueError('Unknown synaWudfBioUsb.dll build (sha256 %s). Known builds: %s' %
                         (digest, ', '.join('%s (%s)' % (v[0], k) for k, v in KNOWN_DLLS.items())))
    _, table, count = KNOWN_DLLS[digest]
    pe = _PE(dll)

    found = {}
    for i in range(count):
        r = table + i * MODULE_RECORD_LEN
        kind, = unpack_from('<I', dll, r + 0x08)
        half, = unpack_from('<I', dll, r + 0x10)
        length, = unpack_from('<I', dll, r + 0x20)
        va, = unpack_from('<Q', dll, r + 0x24)
        rom = unpack_from('<II', dll, r + 0x3c)
        for name, want in MODULES.items():
            if (kind, half, rom) == want and name not in found:
                found[name] = pe.read(va, length)

    missing = set(MODULES) - set(found)
    if missing:
        raise ValueError('Modules not found in the DLL: %s' % ', '.join(sorted(missing)))
    return found


def save(modules: typing.Dict[str, bytes], path: str = MODULES_PATH):
    os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
    tmp = path + '.tmp'
    with open(tmp, 'w') as f:
        json.dump({k: v.hex() for k, v in modules.items()}, f)
    os.replace(tmp, path)


_cache: typing.Dict[str, bytes] = {}


def module(name: str, path: str = MODULES_PATH) -> bytes:
    """A module's 0x06 payload, as saved by validity-sensors-firmware."""
    if name not in _cache:
        try:
            with open(path) as f:
                saved = json.load(f)
        except FileNotFoundError:
            raise MissingModules('%s not found' % path)
        if name not in saved:
            raise MissingModules('%s has no "%s" module' % (path, name))
        _cache.update((k, bytes.fromhex(v)) for k, v in saved.items())
    return _cache[name]
