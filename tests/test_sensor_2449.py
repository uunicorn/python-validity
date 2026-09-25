"""Sensor2449's requests, against what the Windows driver sends (USB captures from
issue #179, decrypted). No hardware and no DLL needed."""

from struct import pack, unpack
from typing import Any

import pytest

from validitysensor import sensor_2449
from validitysensor import timeslot as prg
from validitysensor.sensor import CaptureMode, RomInfo, bitpack
from validitysensor.sensor_2449 import Sensor2449, rescale_pixel
from validitysensor.table_types import SensorCaptureProg, SensorTypeInfo

BYTES_PER_LINE = 0x98
LINE_WIDTH = 144
LINES = 56
ROM_INFO = RomInfo(timestamp=0, build=0xffff, major=6, minor=0x14, product=0x33, u1=0xffff)

# (mask, flags) of the six lines ahead of the per-column data in the real chunk 0x30
EXPECTED_FIXED_LINES = [
    (0xff, 0x072000ad),  # calibration_blob
    (0xff, 0x073000b5),  # 0x8000203c write
    (0xff, 0x074000b8),  # 0x80002040 write
    (0xffff, 0x4750012f),  # 3rd Enable Rx
    (0xffff, 0x4760019c),  # 4th Enable Rx
    (0xff, 0x17700374),  # fixed
]

EXPECTED_AGC_REGISTERS = {
    0x8000206c: 0x0070,
    0x80002070: 0x0070,
    0x80002074: 0x0000,
    0x80002078: 0x0000,
}

# Real factory calibration values, and the chunk 0x43 the Windows driver built from them.
# They bitpack to 35 bytes, so chunk 0x43 needs padding.
REAL_FACTORY_CALIBRATION_VALUES = bytes.fromhex(
    '7c85908c8c8e8d8a898b8987868a89868689888586878684838586808186868484'
    '868a8487888b86898a8c888a8a8e888e8c908a8c8b8177')
REAL_CHUNK_43 = bytes.fromhex(
    '0f0000000c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728'
    '292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142430c770000c5e5'
    '5aaf9d924af8a67c4f46f7e06bccbda4de6bedcd06237d72d638e78db7e659a902'
    '0c770000c5e55aaf9d924af8a67c4f46f7e06bccbda4de6bedcd06237d72d638e7'
    '8db7e659a9020000000000000000000c00000000')


def make_sensor() -> Any:
    s: Any = Sensor2449.__new__(Sensor2449)
    s.device_info = type('DeviceInfo', (), {'type': 0x2449})()
    s.type_info = SensorTypeInfo.get_by_type(0x2449)
    s.rom_info = ROM_INFO
    s.hardcoded_prog = SensorCaptureProg.get(ROM_INFO, 0x2449, 0x18, 0x19)
    s.key_calibration_line = LINES // 2
    s.bytes_per_line = BYTES_PER_LINE
    s.lines_per_frame = 112
    s.calibration_frames = 3
    s.calibration_iterations = 1
    rows = []
    for i in range(LINES):
        header = pack('<BBHHBB', 0x01, 0xfe, 513 + 2 * i, 0xf7f0, 0x01, 0x00)
        rows.append(header + bytes((i + j) % 256 for j in range(LINE_WIDTH)))
    s.calib_data = b''.join(rows)
    s.factory_calibration_values = bytes(range(128))
    return s


def chunks_of(s, mode=CaptureMode.IDENTIFY):
    return s.line_update_type_1(mode, list(prg.split_chunks(s.hardcoded_prog)))


def chunk(chunks, tag) -> bytes:
    v = next(v for k, v in chunks if k == tag)
    assert isinstance(v, bytes)
    return v


def test_tables():
    assert SensorTypeInfo.get_by_type(0x2449).bytes_per_line == BYTES_PER_LINE
    prog = SensorCaptureProg.get(ROM_INFO, 0x2449, 0x18, 0x19)
    assert prog == SensorCaptureProg.get(ROM_INFO, 0xb4d, 0x18, 0x19)
    assert len(prog) == 224 + 872 + 592


def test_chunk_30_line_array():
    c30 = chunk(chunks_of(make_sensor()), 0x30)
    n, = unpack('<L', c30[:4])
    assert n == 42
    assert len(c30) == 4 + 42 * 8 + 36 * LINES * 4 == 8404
    got = [unpack('<LL', c30[4 + i * 8:12 + i * 8]) for i in range(n)]
    assert got[:6] == EXPECTED_FIXED_LINES
    assert got[6:] == [(0xffffffff, 0x85000000 | 4 * k) for k in range(36)]


def test_chunk_43_matches_real_capture():
    s = make_sensor()
    s.factory_calibration_values = REAL_FACTORY_CALIBRATION_VALUES
    assert chunk(chunks_of(s), 0x43) == REAL_CHUNK_43


def test_chunk_43_carries_factory_values_twice():
    s = make_sensor()
    c43 = chunk(chunks_of(s), 0x43)
    u, m, packed = bitpack(s.factory_calibration_values)
    off = 4 + len(s.type_info.calibration_blob)
    for _ in range(2):
        assert unpack('<BBH', c43[off:off + 4]) == ((u - 1) | 8, m, 0)
        assert c43[off + 4:off + 4 + len(packed)] == packed
        off += 4 + len(packed)


def test_chunk_32_agc_registers():
    s = make_sensor()
    raw = [v for k, v in prg.split_chunks(s.hardcoded_prog) if k == 0x32]
    patched = [v for k, v in chunks_of(s) if k == 0x32]
    assert len(raw) == len(patched) == 3
    seen = {}
    for r, p in zip(raw, patched):
        base, = unpack('<L', r[:4])
        for i in range(4, len(r), 4):
            off, rv = unpack('<HH', r[i:i + 4])
            _, pv = unpack('<HH', p[i:i + 4])
            if base + off in EXPECTED_AGC_REGISTERS:
                seen[base + off] = pv
            else:
                assert pv == rv
    assert seen == EXPECTED_AGC_REGISTERS


@pytest.mark.parametrize('mode', [CaptureMode.IDENTIFY, CaptureMode.CALIBRATE])
def test_chunk_34_register_writes(mode):
    c34 = chunk(chunks_of(make_sensor(), mode), 0x34)
    writes = {}
    pc = LINE_WIDTH
    while pc < len(c34):
        opcode, length, *operands = prg.decode_insn(c34[pc:])
        if opcode == 4:
            break
        if opcode == 13:
            writes.setdefault(operands[0], operands[1])
        pc += length
    assert writes[0x80002074] == 0 and writes[0x80002078] == 0
    assert writes[0x8000203c] == 0x80


def test_key_line_is_three_rescaled_bands():
    s = make_sensor()
    key = s.get_key_line()
    assert len(key) == LINE_WIDTH
    for band, row in enumerate((18, 28, 38)):
        src = s.calib_data[row * BYTES_PER_LINE + 8:(row + 1) * BYTES_PER_LINE]
        cols = range(band * 48, band * 48 + 48)
        assert key[cols.start:cols.stop] == bytes(rescale_pixel(src[c]) & 0xff for c in cols)
    s.calib_data = b''
    assert s.get_key_line() == b'\0' * LINE_WIDTH


def test_chunk_30_columns_skip_five_to_four_quirk():
    s = make_sensor()
    s.calib_data = b''.join(s.calib_data[r * BYTES_PER_LINE:r * BYTES_PER_LINE + 8] + bytes([130]) * LINE_WIDTH
                            for r in range(LINES))
    c30 = chunk(chunks_of(s), 0x30)
    assert set(c30[4 + 42 * 8:]) == {5}


def test_calibrate_request_chunks():
    s = make_sensor()
    tags = [k for k, _ in chunks_of(s, CaptureMode.CALIBRATE)]
    assert tags[-4:] == [0x17, 0x44, 0x30, 0x43]
    assert not {0x26, 0x2e, 0x47, 0x48} & set(tags)
    s.calib_data = b''
    assert len(chunk(chunks_of(s, CaptureMode.CALIBRATE), 0x30)) == 4 + 6 * 8
    req = s.build_cmd_02(CaptureMode.CALIBRATE)
    assert unpack('<BHH', req[:5]) == (2, BYTES_PER_LINE, 3 * 112 + 1)


def test_chunk_48_is_the_blank_frame_once_calibrated():
    s = make_sensor()
    s.blank_data = bytes([0x80]) * len(s.calib_data)
    assert 0x48 not in [k for k, _ in chunks_of(s)]
    s.firmware_calibrated = True
    assert chunk(chunks_of(s), 0x48) == pack('<HH', BYTES_PER_LINE, LINES) + s.blank_data
    assert 0x48 not in [k for k, _ in chunks_of(s, CaptureMode.CALIBRATE)]


def test_enroll_captures_are_refused():
    with pytest.raises(Exception, match='enrolls on the host'):
        chunks_of(make_sensor(), CaptureMode.ENROLL)


def test_cached_calibration_sends_nothing(state_dir, monkeypatch):
    s = make_sensor()
    (state_dir / 'calib-6.20-2449.bin').write_bytes(s.calib_data)
    (state_dir / 'blank-6.20-2449.bin').write_bytes(b'blank')
    sent = []
    monkeypatch.setattr(sensor_2449.tls, 'app', lambda req: sent.append(req) or b'\0\0')
    s.calib_data = b''
    s.calibrate()
    assert sent == []
    assert s.blank_data == b'blank' and s.firmware_calibrated


def test_live_calibration_and_cache(state_dir, monkeypatch):
    s = make_sensor()
    s.calib_data = b''
    sent = []
    monkeypatch.setattr(sensor_2449.tls, 'app', lambda req: sent.append(req) or b'\0\0')
    monkeypatch.setattr(sensor_2449.dll_tables, 'module', lambda name: {'calibrate': b'MOD'}[name])
    frame = bytes(range(256)) * (337 * BYTES_PER_LINE // 256) + bytes(337 * BYTES_PER_LINE % 256)
    monkeypatch.setattr(sensor_2449.usb, 'read_82', lambda: frame)
    s.calibrate()
    assert sent[0] == b'\x06MOD'
    assert [r[0] for r in sent[1:3]] == [2, 2] and sent[3] == b'\x1a'
    assert s.calib_data == s.average(frame) == s.blank_data
    assert (state_dir / 'calib-6.20-2449.bin').read_bytes() == s.calib_data
    assert s.firmware_calibrated


def test_factory_bits_read_once_then_cached(state_dir, monkeypatch):
    reads = []

    def fake_get(tag):
        reads.append(tag)
        return {3: b'\0' * 4 + bytes(range(128)), 7: b'seven'}

    monkeypatch.setattr(sensor_2449, 'get_factory_bits', fake_get)
    s = make_sensor()
    first = s.factory_bits()
    assert s.factory_bits() == first
    assert reads == [0x0e00]
    s.factory_bits(refresh=True)
    assert reads == [0x0e00, 0x0e00]


def test_parse_image():
    pixels = bytes(range(256)) * 31 + bytes(range(128))
    body = pack('<HHHHL', 56, 144, 333, 8, 0) + pixels
    status2 = b'\0\0' + pack('<L', len(body)) + body
    assert Sensor2449.parse_image(status2) == pixels
    assert Sensor2449.parse_image(status2[:-1]) is None
    bad = b'\0\0' + pack('<L', len(body)) + pack('<HHHHL', 56, 144, 333, 8, 1) + pixels
    assert Sensor2449.parse_image(bad) is None
