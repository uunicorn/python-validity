import logging
import os.path
import typing
from binascii import hexlify, unhexlify
from enum import Enum
from hashlib import sha256
from struct import pack, unpack
import time
from time import sleep

from usb import core as usb_core

from . import timeslot as prg
from .blobs import reset_blob, cmd_02_chunk_30, cmd_02_chunk_43, cmd_06
from .db import db, SidIdentity
from .flash import write_enable, call_cleanups, read_flash, erase_flash, write_flash_all, read_flash_all
from .hw_tables import dev_info_lookup
from .init_data_dir import PYTHON_VALIDITY_DATA_DIR
from .table_types import SensorTypeInfo, SensorCaptureProg
from .tls import tls
from .usb import usb, CancelledException
from .util import assert_status, unhex

# TODO: this should be specific to an individual device (system may have more than one sensor)
calib_data_path = PYTHON_VALIDITY_DATA_DIR + 'calib-data.bin'

line_update_type1_devices = [
    0xB5, 0x885, 0xB3, 0x143B, 0x1055, 0xE1, 0x8B1, 0xEA, 0xE4, 0xED, 0x1825, 0x1FF5, 0x199,
    0x2449, 0x121
]


# TODO use more sophisticated glow patters in different cases
def glow_start_scan():
    cmd = unhexlify(
        '3920bf0200ffff0000019900200000000099990000000000000000000000000020000000000000000000000000ffff000000990020000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'
    )
    assert_status(tls.app(cmd))


def glow_end_scan():
    cmd = unhexlify(
        '39f4010000f401000001ff002000000000ffff0000000000000000000000000020000000000000000000000000f401000000ff0020000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'
    )
    assert_status(tls.app(cmd))


def get_prg_status():
    return tls.app(unhexlify('5100000000'))


def wait_till_finished():
    while True:
        status = get_prg_status()

        if status[0] in [0, 7]:
            break

        sleep(0.2)


def get_prg_status2():
    return tls.app(unhexlify('5100200000'))


def read_hw_reg32(addr: int):
    rsp = tls.cmd(pack('<BLB', 7, addr, 4))
    assert_status(rsp)
    rsp, = unpack('<L', rsp[2:])
    return rsp


def write_hw_reg32(addr: int, val: int):
    rsp = tls.cmd(pack('<BLLB', 8, addr, val, 4))
    assert_status(rsp)


class RebootException(Exception):
    pass


def reboot():
    assert_status(tls.cmd(unhex('050200')))
    raise RebootException()


def factory_reset():
    assert_status(usb.cmd(reset_blob))
    assert_status(usb.cmd(b'\x10' + b'\0' * 0x61))
    reboot()


class RomInfo:
    @classmethod
    def get(cls):
        rsp = tls.cmd(b'\x01')
        assert_status(rsp)
        rsp = rsp[2:]
        return cls(*unpack('<LLBBxBxxxB', rsp[0:0x10]))

    def __init__(self, timestamp: int, build: int, major: int, minor: int, product: int, u1: int):
        self.timestamp, self.build, self.major, self.minor, self.product, self.u1 = timestamp, build, major, minor, product, u1

    def __repr__(self):
        return 'RomInfo(timestamp=%d, build=%d, major=%d, minor=%d, product=%d, u1=%d)' % (
            self.timestamp, self.build, self.major, self.minor, self.product, self.u1)


def identify_sensor():
    rsp = tls.cmd(b'\x75')
    assert_status(rsp)
    rsp = rsp[2:]

    zeroes, minor, major = unpack('<LHH', rsp)

    if zeroes != 0:
        raise Exception('This was not expected')

    return dev_info_lookup(major, minor)


# <<< 0000 880d 0000 07000000
#      08000000 9400 0e00 0300 0080 07000000 7e7f807f808080808080808080808080808080808080818081808180818080808080818081808080818081808180
#      a4000000 0800 0e00 0200 0000 00000000 0d007100
#      b4000000 0800 0e00 0800 0080 db000000 00000000
#      c4000000 0400 0e00 0500 0080 1c6f0400
#      d0000000 9400 0e00 0700 0080 07000000 2b23203c2d182e1e30182e1c321d341d341e321c301e1e241e201f201d1c321a301e1c211e21341f1e202024201f
#      6c010000 1400 0e00 0f00 0080 05550007 7701002805720000080100020811e107
#      88010000 0c00 0e00 1200 0080 07000000 7002 7800 7002 7800
def get_factory_bits(tag: int):
    rsp = tls.cmd(pack('<B H HL', 0x6f, tag, 0, 0))
    assert_status(rsp)
    rsp = rsp[2:]

    wtf, entries = unpack('<LL', rsp[:8])
    rsp = rsp[8:]

    rc = {}
    for x in range(0, entries):
        hdr, rsp = rsp[:12], rsp[12:]
        ptr, l, tag, subtag, flags = unpack('<LHHHH', hdr)
        value = rsp[:l]

        if len(value) != l:
            raise Exception('Truncated response %d != %d' % (len(value), l))

        rc[subtag] = value
        rsp = rsp[l:]

    if len(rsp) > 0:
        raise Exception('Garbage at the end of reply')

    return rc


def bitpack(b):
    l = len(b)
    m = min(b)
    x = max(b)

    # maximum delta which we must encode
    x -= m

    # count useful bits
    u = 0
    while x > 0:
        x >>= 1
        u += 1

    # convert to array of binary strings with each element exactly u characters long
    b = [bin(i - m + 0x100)[-u:] for i in b]

    # combine chunks into one long text number with u*l binary digits and parse it as integer
    b = int(''.join(b[::-1]), 2)

    # convert back to bytes
    b = b.to_bytes((u * l + 7) // 8, 'little')

    return u, m, b


class Line:
    def __init__(self):
        self.mask: typing.Optional[int] = None
        self.flags: typing.Optional[int] = None
        self.data: typing.Optional[bytes] = None
        self.v0 = 0
        self.v1 = 0
        self.v2 = 0


def clip(x: int):
    if x < -128:
        x = -128

    if x > 127:
        x = 127

    return x & 0xff


def scale(x: int):
    x -= 0x80
    x = int(x * 10 / 0x22)  # TODO: scaling factor depends on a device
    return clip(x)


def add(l: int, r: int):
    # Make signed
    l, r = unpack('bb', pack('BB', l, r))
    return clip(l + r)


def chunks(b: bytes, l: int):
    return [b[i:i + l] for i in range(0, len(b), l)]


class CaptureMode(Enum):
    CALIBRATE = 1
    IDENTIFY = 2
    ENROLL = 3


def get_templates_dir():
    candidates = ['/var/lib/python-validity/templates', PYTHON_VALIDITY_DATA_DIR + 'templates', os.path.expanduser('~/.cache/python-validity/templates')]
    for c in candidates:
        try:
            os.makedirs(c, exist_ok=True)
            return c
        except:
            continue
    return '/tmp/python-validity/templates'


HANN_WINDOW_56_144 = None

def get_hann_window():
    global HANN_WINDOW_56_144
    if HANN_WINDOW_56_144 is None:
        import numpy as np
        HANN_WINDOW_56_144 = (np.hanning(56)[:, None] * np.hanning(144)).astype(np.float32)
    return HANN_WINDOW_56_144


def host_match_score(img1_bytes: bytes, img2_bytes: bytes) -> float:
    import numpy as np
    from PIL import Image

    a = np.frombuffer(img1_bytes, dtype=np.uint8).reshape((56, 144)).astype(np.float32)
    b_raw = np.frombuffer(img2_bytes, dtype=np.uint8).reshape((56, 144))

    hann = get_hann_window()
    a_norm = (a - a.mean()) * hann
    fa = np.fft.fft2(a_norm)
    conj_fa = np.conj(fa)

    b_pil = Image.fromarray(b_raw)
    max_peak = 0.0

    # Search rotation angles [-12..12] degrees to accommodate natural finger tilt
    for angle in [0, -3, 3, -6, 6, -9, 9, -12, 12]:
        if angle != 0:
            b_rot = np.array(b_pil.rotate(angle, resample=Image.BILINEAR)).astype(np.float32)
        else:
            b_rot = b_raw.astype(np.float32)

        b_norm = (b_rot - b_rot.mean()) * hann
        fb = np.fft.fft2(b_norm)

        cross_power = (fb * conj_fa) / (np.abs(fb * conj_fa) + 1e-9)
        corr = np.fft.ifft2(cross_power)
        peak = float(np.max(np.abs(corr)))
        if peak > max_peak:
            max_peak = peak
            if max_peak >= 0.18:
                break

    return max_peak


class Sensor:
    calib_data = b''

    def open(self):
        self.capture_initialized = False
        self.device_info = identify_sensor()

        logging.info('Opening sensor: %s' % self.device_info.name)
        self.type_info = SensorTypeInfo.get_by_type(self.device_info.type)

        if self.device_info.type == 0x199:
            self.key_calibration_line = 0x38  # (lines_per_calibration_data/2), but hardcoded for sensor type 0x199
            self.calibration_frames = 3  # TODO: workout where it's really comming from
            self.calibration_iterations = 3  # hardcoded for type
        elif self.device_info.type == 0xdb:
            self.key_calibration_line = 0x48  # TODO 48 is just a guess -- find it
            self.calibration_frames = 6  # TODO: workout where it's really comming from
            self.calibration_iterations = 0
        elif self.device_info.type in [0x121, 0x2449]:
            self.key_calibration_line = 0x1c  # lines_per_calibration_data // 2 (56 // 2 = 28)
            self.calibration_frames = 6
            self.calibration_iterations = 0
        else:
            raise Exception('Device %s is not supported (sensor type 0x%x)' %
                            (self.device_info.name, self.device_info.type))

        self.rom_info = RomInfo.get()
        self.hardcoded_prog = SensorCaptureProg.get(self.rom_info, self.device_info.type, 0x18,
                                                    0x19)  # TODO: find where 0x18, 0x19 coming from
        if self.hardcoded_prog is None:
            raise Exception('Can\'t find initial capture program for rom %s and sensor type %x' %
                            (repr(self.rom_info), self.device_info.type))

        # Look for a "2D" chunk. It must have a 32 bit integer which represent the number of lines per frame
        lines_2d = [
            unpack('<L', v)[0] for [k, v] in prg.split_chunks(self.hardcoded_prog) if k == 0x2f
        ][0]
        self.lines_per_frame = lines_2d * self.type_info.repeat_multiplier
        self.bytes_per_line = self.type_info.bytes_per_line

        factory_bits = get_factory_bits(0x0e00)
        self.factory_calibration_values = factory_bits[3][4:]

        if 7 in factory_bits:
            self.factory_calib_data = factory_bits[7][4:]

        self.calibrate()

    def save(self):
        with open(calib_data_path, 'wb') as f:
            f.write(self.calib_data)

    # This is the exact logic from the DLL.
    # If it looks broken that was probably intended.
    def patch_timeslot_table(self, b: bytes, inc_address: bool, mult: int):
        b = bytearray(b)
        i = 0
        while i + 3 < len(b):
            if b[i] & 0xf8 == 0x10:
                if b[i + 2] > 1:
                    b[i + 2] *= mult
                    if inc_address:
                        b[i + 1] += 1
                i += 3
                continue

            if b[i] == 0:
                i += 1
                continue

            if b[i] == 7:
                i += 2
                continue

            break

        return bytes(b)

    def patch_timeslot_again(self, b: bytes):
        b = bytearray(b)

        pc = 0
        match = None
        # Look for the last Call in the script
        while pc < len(b):
            opcode, l, *operands = prg.decode_insn(b[pc:])

            # End of Table, Return, End of Data
            if opcode == 1 or opcode == 2 or opcode == 4:
                break

            # Call
            if opcode == 11:
                match = operands[1]  # destination address

            pc += l

        if match is None:
            return bytes(b)

        pc = match
        match = None
        # Look for the last Register Write to 0x8000203C
        while pc < len(b):
            opcode, l, *operands = prg.decode_insn(b[pc:])

            # End of Table, Return, End of Data
            if opcode == 1 or opcode == 2 or opcode == 4:
                break

            # Write Register
            if opcode == 13 and operands[0] == 0x8000203c:
                match = pc

            pc += l

        if match is None:
            return bytes(b)

        # Hack the value to be taken from the factory calibration table right in the middle of a sensor
        b[match + 1] = self.factory_calibration_values[self.key_calibration_line]

        return bytes(b)

    def average(self, raw_calib_data: bytes):
        frame_size = self.lines_per_frame * self.bytes_per_line
        interleave_lines = self.lines_per_frame // self.type_info.lines_per_calibration_data  # 2, TODO: algo is quite different when it is 1
        input_frames = self.calibration_frames

        if interleave_lines > 1:
            if input_frames > 1:
                # skip the first frame
                input_frames -= 1
                base_address = frame_size

            frame = raw_calib_data[base_address:base_address + frame_size]

            # split into groups of lines
            frame = chunks(frame, interleave_lines * self.bytes_per_line)

            # split group of lines into lines
            frame = [chunks(f, self.bytes_per_line) for f in frame]

            # calculate averages across interleaved lines
            frame = [bytes([sum(i) // len(f) for i in zip(*f)]) for f in frame]
            frame = b''.join(frame)
        else:
            if input_frames > 1:
                # skip the first frame
                input_frames -= 2
                base_address = frame_size * 2

            frames = raw_calib_data[base_address:base_address + frame_size * input_frames]
            frames = chunks(frames, frame_size)
            frame = [int(sum(i) / input_frames) for i in zip(*frames)]
            frame = bytes(frame)

        return frame

    def process_calibration_results(self, cooked_data: bytes):
        frame = chunks(cooked_data, self.bytes_per_line)

        # apply scaling factors
        frame = [f[:8] + bytes(map(scale, f[8:])) for f in frame]
        frame = b''.join(frame)

        if len(self.calib_data) > 0:
            # Not the first calibration run. Combine results
            # split previous calibration info into lines
            lll = chunks(self.calib_data, self.bytes_per_line)

            # split next calibration info into lines
            rrr = chunks(frame, self.bytes_per_line)

            # Don't touch the first 8 bytes of each line, add everything else as signed characters, clipping the values
            combined = [
                ll[:8] + bytes([add(l, r) for l, r in zip(ll[8:], rr[8:])])
                for ll, rr in zip(lll, rrr)
            ]
            self.calib_data = bytes(b''.join(combined))
        else:
            self.calib_data = frame

    def get_key_line(self):
        if len(self.calib_data) > 0:
            bytes_per_calibration_line = len(
                self.calib_data) // self.type_info.lines_per_calibration_data
            key_line_offset = 8 + bytes_per_calibration_line * self.key_calibration_line
            key_line = self.calib_data[key_line_offset:key_line_offset + self.type_info.line_width]
            key_line = bytes([i - 1 if i == 5 else i for i in key_line])
        else:
            key_line = b'\0' * self.type_info.line_width

        return key_line

    def line_update_type_1(self, mode: CaptureMode,
                           chunks: typing.List[typing.List[typing.Union[int, bytes]]]):
        if self.device_info.type not in [0x121, 0x2449]:
            for c in chunks:
                # Timeslot Table 2D
                if c[0] == 0x34:
                    # TODO: figure out when to use address increment
                    tst = self.patch_timeslot_table(c[1], True, self.type_info.repeat_multiplier)
                    if mode != CaptureMode.CALIBRATE:
                        tst = self.patch_timeslot_again(tst)
                    c[1] = self.get_key_line() + tst[self.type_info.line_width:]

        # ---------------- Reply Configuration ---------------
        chunks += [[0x17, b'']]

        if self.device_info.type in [0x121, 0x2449]:
            if mode in [CaptureMode.IDENTIFY, CaptureMode.ENROLL]:
                chunks += [[
                    0x26,
                    unhexlify(
                        'fbb20f0000000f00300000006001020040010a00018000000a0200000b190000102760ea01091000'
                    )
                ]]
                chunks += [[
                    0x2e, unhexlify('0200180023000000900038004d01000090017c013c323232640a0202')
                ]]
            elif mode == CaptureMode.CALIBRATE:
                chunks += [[
                    0x2e, unhexlify('0200180008000000900038004d01000058027c013c323232640a0202')
                ]]
            chunks += [[0x44, pack('<L', 1)]]
            chunks += [[0x30, cmd_02_chunk_30()]]
            chunks += [[0x43, cmd_02_chunk_43()]]
            return chunks
        else:
            if mode == CaptureMode.IDENTIFY:
                chunks += [[
                    0x4e,
                    unhexlify(
                        'fbb20f0000000f00300000008700020067000a00018000000a0200000b1900008813b80b01091000'
                    )
                ]]
                chunks += [[
                    0x2e, unhexlify('0200180002000000700070004d010000a0008c003c32321e3c0a0202')
                ]]
            elif mode == CaptureMode.ENROLL:
                chunks += [[
                    0x26,
                    unhexlify(
                        'fbb20f0000000f00300000008700020067000a00018000000a0200000b19000050c360ea01091000'
                    )
                ]]
                chunks += [[
                    0x2e, unhexlify('0200180023000000700070004d010000a0008c003c32321e3c0a0202')
                ]]

        # ---------------- Interleave ---------------
        chunks += [[0x44, pack('<L', 1)]]

        lines: typing.List[Line] = []
        cnt = 2  # TODO figure out why 2

        l = Line()
        lines += [l]
        l.mask = 0xff
        # Find 2nd "Enable Rx" instruction
        pc, _ = prg.find_nth_insn(tst, 6, 2)
        l.flags = (pc + 1) | (cnt << 0x14) | 0x7000000
        l.data = self.type_info.calibration_blob
        l.v0 = 0xf
        cnt += 1

        l = Line()
        lines += [l]
        l.mask = 0xff
        # Find 1st "Write Register" instruction to the 0x8000203C port
        pc, _ = prg.find_nth_regwrite(tst, 0x8000203C, 1)
        l.flags = (pc + 1) | (cnt << 0x14) | 0x7000000
        l.v0, l.v1, l.data = bitpack(self.factory_calibration_values)
        l.v0 = (l.v0 - 1) | 8
        cnt += 1

        if len(self.calib_data) > 0:
            bytes_per_calibration_line = len(
                self.calib_data) // self.type_info.lines_per_calibration_data

            for i in range(0, 112, 4):
                l = Line()
                lines += [l]
                l.mask = 0xffffffff
                l.flags = i | (0x85 << 24)
                l.data = b''
                for j in range(0, 112):
                    p = 8 + j * bytes_per_calibration_line + i
                    l.data += self.calib_data[p:p + 4]

        # Align to dwords, as the sensor demands it
        for l in lines:
            pad = len(l.data) % 4
            if pad > 0:
                l.data += b'\0' * (4 - pad)

        # ---------------- Line Update ---------------
        line_update = pack('<L', len(lines))
        line_update += b''.join([pack('<LL', l.mask, l.flags) for l in lines])

        line_update += b''.join([l.data for l in lines if ((l.flags & 0x00f00000) >> 0x14) <= 1])
        chunks += [[0x30, line_update]]

        # ---------------- Line Update Transform ---------------
        update_transform = b''.join([
            pack('<BBH', l.v0, l.v1, l.v2) + l.data for l in lines
            if ((l.flags & 0x00f00000) >> 0x14) > 1
        ])
        chunks += [[0x43, update_transform]]

        return chunks

    def line_update_type_2(self, mode: CaptureMode,
                           chunks: typing.List[typing.List[typing.Union[int, bytes]]]):
        for c in chunks:
            # patch the 2D params.
            # The following is only needed on some rom versions below 6.5 as reported by cmd_01
            # if c[0] == 0x2f:
            #    c[1] = pack('<L', unpack('<L', c[1])[0]*mult)

            # Timeslot Table 2D
            if c[0] == 0x34:
                # TODO: figure out when to use address increment
                tst = self.patch_timeslot_table(c[1], True, self.type_info.repeat_multiplier)
                if mode != CaptureMode.CALIBRATE:
                    tst = self.patch_timeslot_again(tst)
                c[1] = tst

        # ---------------- Reply Configuration ---------------
        chunks += [[0x17, b'']]

        if mode == CaptureMode.IDENTIFY:
            # This type of fragment is not present in the debugging dump routine.
            # It seems to be only used for identification and it looks almost identical to Finger Detect (0x26)
            # Seems to be the same all the time for a given sensor and mostly hardcoded
            # TODO: analyse construct_wtf_4e @0000000180090BF0
            chunks += [[
                0x4e,
                unhexlify(
                    'fbb20f0000000f00300000006001020040010a00018000000a0200000b1900008813b80b01091000'
                )
            ]]
            # Image Reconstruction.
            # TODO: analyse add_image_reconstruction_cmd_02_buff_list_item @000000018008EA70
            chunks += [[
                0x2e, unhexlify('0200180002000000900090004d01000090017c013c323232640a0201')
            ]]
        elif mode == CaptureMode.ENROLL:
            chunks += [[
                0x26,
                unhexlify(
                    'fbb20f0000000f00300000006001020040010a00018000000a0200000b19000050c360ea01091000'
                )
            ]]
            # Image Reconstruction. There is only one byte difference with the "identify" version. (same is true for 0097)
            chunks += [[
                0x2e, unhexlify('0200180023000000900090004d01000090017c013c323232640a0201')
            ]]

        lines = []

        l = Line()
        lines += [l]
        l.mask = 0xff
        # Find 2nd "Enable Rx" instruction
        pc, _ = prg.find_nth_insn(tst, 6, 2)
        l.flags = (pc + 1) | 0x3000000
        l.data = self.type_info.calibration_blob

        l = Line()
        lines += [l]
        l.mask = 0xff
        # Find 1st "Write Register" instruction to the 0x8000203C port
        pc, _ = prg.find_nth_regwrite(tst, 0x800020fc, 1)
        l.flags = (pc + 1) | 0x3000000
        l.data = self.factory_calib_data

        l = Line()
        lines += [l]
        l.mask = 0xff
        # Find 1st "Write Register" instruction to the 0x8000203C port
        pc, _ = prg.find_nth_regwrite(tst, 0x8000203c, 1)
        l.flags = (pc + 1) | 0x3000000
        l.data = self.factory_calibration_values

        # Align to dwords, as the sensor demands it
        for l in lines:
            pad = len(l.data) % 4
            if pad > 0:
                l.data += b'\0' * (4 - pad)

        # ---------------- Line Update ---------------
        line_update = pack('<L', len(lines))
        line_update += b''.join([pack('<LL', l.mask, l.flags) for l in lines])

        line_update += b''.join([l.data for l in lines])
        chunks += [[0x30, line_update]]

        return chunks

    def build_cmd_02(self, mode: CaptureMode):
        chunks = list(prg.split_chunks(self.hardcoded_prog))

        if self.rom_info.product not in [0x30, 0x33]:
            raise Exception('Product %d not implemented' % self.rom_info.product)

        if self.device_info.type in line_update_type1_devices:
            chunks = self.line_update_type_1(mode, chunks)
        else:
            chunks = self.line_update_type_2(mode, chunks)

        if mode == CaptureMode.CALIBRATE:
            req_lines = self.calibration_frames * self.lines_per_frame + 1  # TODO: figure out how this is actually calculated
        else:
            req_lines = 0

        return pack('<BHH', 2, self.bytes_per_line, req_lines) + prg.merge_chunks(chunks)

    def persist_clean_slate(self, clean_slate: bytes):
        start = read_flash(6, 0, 0x44)

        if start != b'\xff' * 0x44:
            if clean_slate[:0x44] == start:
                logging.info('Calibration data already matches the data on the flash.')
                return
            else:
                logging.info('Calibration flash already written. Erasing.')
                erase_flash(6)

        write_flash_all(6, 0, clean_slate)

    def check_clean_slate(self):
        start = read_flash(6, 0, 0x44)
        magic, l = unpack('<HH', start[:4])
        start = start[4:]

        if magic != 0x5002:
            return False

        hs, zeroes = start[0:0x20], start[0x20:0x40]

        if zeroes != b'\0' * 0x20:
            logging.warning('Unexpected contents in calibration flash partition')
            return False

        img = read_flash_all(6, 0x44, l)
        if hs != sha256(img).digest():
            logging.warning('Calibration flash hash mismatch')
            return False

        return True

    def calibrate(self):
        if self.device_info.type in [0x121, 0x2449]:
            return

        if os.path.isfile(calib_data_path):
            with open(calib_data_path, 'rb') as f:
                self.calib_data = f.read()
                logging.info('Calibration data loaded from a file.')

            if self.check_clean_slate():
                return
            else:
                logging.info('No calibration data on the flash. Calibrating...')
        else:
            self.calib_data = b''
            logging.info('No calibration data was loaded. Calibrating...')

        for i in range(0, self.calibration_iterations):
            logging.debug('Calibration iteration %d...' % i)
            rsp = tls.cmd(self.build_cmd_02(CaptureMode.CALIBRATE))
            assert_status(rsp)
            self.process_calibration_results(self.average(usb.read_82()))

        logging.debug('Requesting a blank image...')

        # Get the "clean slate" image to store on the flash for fine-grained after-capture adjustments
        rsp = tls.cmd(self.build_cmd_02(CaptureMode.CALIBRATE))
        assert_status(rsp)

        clean_slate = self.average(usb.read_82())
        clean_slate = pack('<H', len(clean_slate)) + clean_slate
        clean_slate = clean_slate + pack('<H', 0)  # TODO: still don't know what this zero is for
        clean_slate = pack(
            '<H', len(clean_slate)) + sha256(clean_slate).digest() + b'\0' * 0x20 + clean_slate
        clean_slate = pack('<H', 0x5002) + clean_slate

        self.persist_clean_slate(clean_slate)
        self.save()

    def cancel(self):
        usb.cancel = True

    def capture(self, mode: CaptureMode) -> typing.Tuple[int, int, int, int]:
        success = False
        try:
            if self.device_info.type in [0x121, 0x2449] and not getattr(self, 'capture_initialized', False):
                assert_status(tls.app(cmd_06()))
                self.capture_initialized = True

            assert_status(tls.app(self.build_cmd_02(mode)))

            # start
            b = usb.wait_int()
            if b[0] != 0:
                raise Exception('wait_start: Unexpected interrupt type %s' % hexlify(b).decode())

            # wait for finger
            while True:
                b = usb.wait_int()
                if b[0] == 2:
                    break

            if self.device_info.type in [0x121, 0x2449]:
                # On Viper 008a (0x2449) / 0x121:
                # Do NOT poll 5100000000 while capturing. Doing so crashes the sensor array.
                # Instead, wait on interrupt pipe until scan complete (interrupt 0x03 with b[2] & 4)
                while True:
                    b = usb.wait_int()
                    if b[0] == 3 and (b[2] & 4):
                        break

                get_prg_status()
                res = get_prg_status2()
                assert_status(tls.app(b'\x52'))

                assert_status(res)
                res = res[2:]
                l, res = res[:4], res[4:]
                l, = unpack('<L', l)

                if l != len(res):
                    raise Exception('Response size does not match %d != %d', l, len(res))

                x, y, w1, w2, error = unpack('<HHHHL', res[:12])
                if error != 0:
                    raise Exception('Scanning problem: %04x' % error)

                self.last_image = res[12:]
                success = True
                return x, y, w1, w2
            else:
                # wait capture complete
                while True:
                    b = usb.wait_int()
                    if b[0] != 3:
                        raise Exception('Unexpected interrupt type %s' % hexlify(b).decode())

                    if b[2] & 4:
                        break

                res = get_prg_status2()

                assert_status(res)
                res = res[2:]

                l, res = res[:4], res[4:]
                l, = unpack('<L', l)

                if l != len(res):
                    raise Exception('Response size does not match %d != %d', l, len(res))

                x, y, w1, w2, error = unpack('<HHHHL', res)

                if error != 0:
                    raise Exception('Scanning problem: %04x' % error)

                success = True
                return x, y, w1, w2

        finally:
            if not success:
                try:
                    tls.app(unhexlify('04'))  # capture stop if still running, cleanup
                except:
                    pass

    def enrollment_update_start(self, key: int) -> int:
        rsp = tls.app(pack('<BLL', 0x68, key, 0))
        assert_status(rsp)
        new_key, = unpack('<L', rsp[2:])

        usb.wait_int()

        return new_key

    def create_enrollment(self):
        if self.device_info.type in [0x121, 0x2449]:
            return
        assert_status(tls.app(pack('<BL', 0x69, 1)))

    def enrollment_update_end(self):
        assert_status(tls.app(pack('<BL', 0x69, 0)))

    # Generates interrupt
    def enrollment_update(self, prev: bytes):
        write_enable()
        try:
            rsp = tls.app(b'\x6b' + prev)
            assert_status(rsp)
        finally:
            call_cleanups()

        return rsp[2:]

    def append_new_image(self, prev: bytes):
        self.enrollment_update(prev)

        usb.wait_int()

        res = self.enrollment_update(prev)

        l, res = res[:2], res[2:]
        l, = unpack('<H', l)
        if l != len(res):
            raise Exception('Response size does not match %d != %d', l, len(res))

        magic_len = 0x38  # hardcoded in the DLL
        template = header = tid = None

        while len(res) > 0:
            tag, l = unpack('<HH', res[:4])

            if tag == 0:
                template = res[:magic_len + l]
            elif tag == 1:
                header = res[magic_len:magic_len + l]
            elif tag == 3:
                tid = res[magic_len:magic_len + l]
            else:
                logging.warning('Ignoring unknown tag %x' % tag)

            res = res[magic_len + l:]

        return header, template, tid

    def make_finger_data(self, subtype: int, template: bytes, tid: bytes):
        template = pack('<HH', 1, len(template)) + template
        tid = pack('<HH', 2, len(tid)) + tid

        tinfo = template + tid

        tinfo = pack('<HHHH', subtype, 3, len(tinfo), 0x20) + tinfo
        tinfo += b'\0' * 0x20

        return tinfo

    # TODO: Better typing information needed.
    def match_host_finger(self, verify_img: bytes) -> typing.Tuple[int, int, bytes]:
        import hashlib, glob, time
        import numpy as np
        from PIL import Image

        t0 = time.time()
        tdir = get_templates_dir()
        best_match = None
        best_score = 0.0

        # Precompute verify image FFT once
        a = np.frombuffer(verify_img, dtype=np.uint8).reshape((56, 144)).astype(np.float32)
        hann = get_hann_window()
        a_norm = (a - a.mean()) * hann
        conj_fa = np.conj(np.fft.fft2(a_norm))

        loaded_templates = []
        for tpl_path in glob.glob(os.path.join(tdir, "*.dat")):
            fname = os.path.basename(tpl_path)[:-4]
            parts = fname.rsplit('_', 1)
            if len(parts) != 2:
                continue
            u_ident, sub_str = parts
            try:
                subtype = int(sub_str)
            except ValueError:
                subtype = 2

            try:
                if '-' in u_ident:
                    uid_int = int(u_ident.split('-')[-1])
                else:
                    uid_int = int(u_ident)
            except ValueError:
                uid_int = 1000

            try:
                with open(tpl_path, 'rb') as fp:
                    raw = fp.read()
                raw_samples = [raw[i:i+8064] for i in range(0, len(raw), 8064) if i+8064 <= len(raw)]
                if raw_samples:
                    loaded_templates.append((uid_int, subtype, raw_samples))
            except Exception:
                continue

        matched_early = False

        # Pass 1: Quick direct check (0° rotation across all template samples)
        for uid_int, subtype, samples in loaded_templates:
            for sample in samples:
                b_raw = np.frombuffer(sample, dtype=np.uint8).reshape((56, 144)).astype(np.float32)
                b_norm = (b_raw - b_raw.mean()) * hann
                fb = np.fft.fft2(b_norm)
                cross_power = (fb * conj_fa) / (np.abs(fb * conj_fa) + 1e-9)
                peak = float(np.max(np.abs(np.fft.ifft2(cross_power))))
                if peak > best_score:
                    best_score = peak
                    best_match = (uid_int, subtype)
                if peak >= 0.18:
                    matched_early = True
                    break
            if matched_early:
                break

        # Pass 2: Angular tilt sweep if Pass 1 didn't reach high confidence
        if not matched_early:
            for uid_int, subtype, samples in loaded_templates:
                for sample in samples:
                    b_raw = np.frombuffer(sample, dtype=np.uint8).reshape((56, 144))
                    b_pil = Image.fromarray(b_raw)
                    for angle in [-3, 3, -6, 6, -9, 9, -12, 12]:
                        b_rot = np.array(b_pil.rotate(angle, resample=Image.BILINEAR)).astype(np.float32)
                        b_norm = (b_rot - b_rot.mean()) * hann
                        fb = np.fft.fft2(b_norm)
                        cross_power = (fb * conj_fa) / (np.abs(fb * conj_fa) + 1e-9)
                        peak = float(np.max(np.abs(np.fft.ifft2(cross_power))))
                        if peak > best_score:
                            best_score = peak
                            best_match = (uid_int, subtype)
                        if peak >= 0.18:
                            matched_early = True
                            break
                    if matched_early:
                        break
                if matched_early:
                    break

        elapsed_ms = (time.time() - t0) * 1000.0
        logging.info(f"Host match evaluation: best_score={best_score:.4f}, threshold=0.11, matched={best_score >= 0.11}, best_match={best_match}, elapsed={elapsed_ms:.1f}ms")
        if best_match and best_score >= 0.11:
            hsh = hashlib.sha256(verify_img).digest()
            return best_match[0], best_match[1], hsh
        else:
            return 0, 0, b''

    def enroll(self, identity: SidIdentity, subtype: int,
               update_cb: typing.Callable[[typing.Any, typing.Optional[Exception]], None]):
        if self.device_info.type in [0x121, 0x2449]:
            tdir = get_templates_dir()
            ident_str = getattr(identity, 'value', str(identity))
            uid_str = None
            if hasattr(identity, 'subauth') and len(identity.subauth) > 0:
                uid_str = str(identity.subauth[-1])
            elif hasattr(identity, 'subauthorities') and len(identity.subauthorities) > 0:
                uid_str = str(identity.subauthorities[-1])
            elif '-' in str(identity):
                try:
                    uid_str = str(identity).split('-')[-1]
                except:
                    pass

            samples = []
            for stage in range(5):
                while True:
                    try:
                        glow_start_scan()
                        self.capture(CaptureMode.ENROLL)
                        img = self.last_image
                        glow_end_scan()

                        # Finger-lift check: if identical to previous sample, user didn't lift finger
                        if len(samples) > 0 and host_match_score(img, samples[-1]) > 0.95:
                            logging.info("Same finger touch detected; please lift finger and touch again...")
                            time.sleep(0.8)
                            continue

                        samples.append(img)
                        # Emit enroll-stage-passed for stages 0..3 (stages 1 to 4)
                        # Stage 4 completion will naturally trigger enroll-completed when enroll() returns
                        if stage < 4:
                            update_cb(b'\x01', None)
                        time.sleep(0.8)
                        break
                    except CancelledException as e:
                        glow_end_scan()
                        raise e
                    except Exception as e:
                        update_cb(None, e)
                        time.sleep(1)

            tpl_data = b''.join(samples)
            tpl_path = os.path.join(tdir, f"{ident_str}_{subtype}.dat")
            with open(tpl_path, 'wb') as fp:
                fp.write(tpl_data)

            if uid_str and uid_str != ident_str:
                uid_path = os.path.join(tdir, f"{uid_str}_{subtype}.dat")
                with open(uid_path, 'wb') as fp:
                    fp.write(tpl_data)

            glow_end_scan()
            return 1

        def do_create_finger(final_template: bytes, tid: bytes):
            tinfo = self.make_finger_data(subtype, final_template, tid)

            usr = db.lookup_user(identity)
            if usr is None:
                usr = db.new_user(identity)
            else:
                usr = usr.dbid

            recid = db.new_finger(usr, tinfo)
            usb.wait_int()

            glow_end_scan()

            return recid

        key = 0
        template = b''
        self.create_enrollment()
        while True:
            try:
                glow_start_scan()
                self.capture(CaptureMode.ENROLL)
                key = self.enrollment_update_start(key)
                rsp = self.append_new_image(template)
                header, template, tid = rsp
                update_cb(header, None)
                if tid:
                    break

            except usb_core.USBError as e:
                raise e
            except CancelledException as e:
                glow_end_scan()
                raise e
            except Exception as e:
                print(e)
                update_cb(None, e)
                # sleep, so we don't end up in a busy loop spaming the sensor with requests in case of unrecoverable error
            finally:
                self.enrollment_update_end()

        self.enrollment_update_end()  # done twice for some reason
        return do_create_finger(template, tid)

    def parse_dict(self, x: bytes):
        rc = {}

        while len(x) > 0:
            (t, l), x = unpack('<HH', x[:4]), x[4:]
            rc[t], x = x[:l], x[l:]

        return rc

    def match_finger(self) -> typing.Tuple[int, int, bytes]:
        try:
            stg_id = 0  # match against any storage
            usr_id = 0  # match against any user
            cmd = pack('<BBBHHHHH', 0x5e, 2, 0xff, stg_id, usr_id, 1, 0, 0)
            rsp = tls.app(cmd)
            assert_status(rsp)

            b = usb.wait_int()
            if b[0] != 3:
                raise Exception('Finger not recognized: %s' % hexlify(b).decode())

            # get results
            rsp = tls.app(unhexlify('6000000000'))
            assert_status(rsp)
            rsp = rsp[2:]

            (l, ), rsp = unpack('<H', rsp[:2]), rsp[2:]
            if l != len(rsp):
                raise Exception('Response size does not match')

            rsp = self.parse_dict(rsp)

            usrid, subtype, hsh = rsp[1], rsp[3], rsp[4]
            usrid, = unpack('<L', usrid)
            subtype, = unpack('<H', subtype)

            return usrid, subtype, hsh
        finally:
            # cleanup, ignore any errors
            tls.app(unhexlify('6200000000'))

    def identify(self, update_cb: typing.Callable[[Exception], None]):
        if self.device_info.type in [0x121, 0x2449]:
            while True:
                try:
                    glow_start_scan()
                    self.capture(CaptureMode.IDENTIFY)
                    glow_end_scan()
                    break
                except CancelledException as e:
                    glow_end_scan()
                    raise e
                except Exception as e:
                    update_cb(e)
                    time.sleep(1)

            verify_img = self.last_image
            return self.match_host_finger(verify_img)

        while True:
            try:
                glow_start_scan()
                self.capture(CaptureMode.IDENTIFY)
                break
            except usb_core.USBError as e:
                raise e
            except CancelledException as e:
                glow_end_scan()
                raise e
            except Exception as e:
                # Capture failed, retry
                update_cb(e)
                sleep(1)

        return self.match_finger()

    def get_finger_blobs(self, usrid: int, subtype: int):
        usr = db.get_user(usrid)
        fingerids = [f['dbid'] for f in usr.fingers if f['subtype'] == subtype]

        if len(fingerids) != 1:
            raise Exception('Unexpected matching finger count')

        finger_record = db.get_record_children(fingerids[0])

        ids = [r['dbid'] for r in finger_record.children if r['type'] == 8]
        return [db.get_record_value(id).value for id in ids]


sensor = Sensor()
