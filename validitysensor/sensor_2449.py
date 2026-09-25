"""Sensor type 0x2449, the flashless 06cb:00a8 ("USB 073").

The capture protocol is the same as the other sensors', with these differences, all
matched against USB captures of the Windows driver (issue #179):

- The session opens with 0x08, 0x07, 0x75, 0x01, 0x19, 0x75.
- Calibration loads a firmware module first, uses one iteration, keeps the raw average
  (no scale()) and ends with 0x1a. The host caches the result, and the factory bits,
  like the Windows driver keeps them in the registry; later sessions calibrate nothing.
- The IDENTIFY request carries real 0x26 (finger-detect threshold) and 0x2e (image
  format) chunks for this sensor, patched AGC registers, a longer 0x30 line array and a
  0x48 chunk with the averaged blank frame from calibration.
- The image comes back in the 0x51 reply: a 12-byte header and 144x56 8-bit pixels.
- There's no on-chip template database: get_print() returns the image and matching is
  done on the host (validitysensor.hostmatch).
"""

import errno
import logging
import os
import threading
import time
import typing
from struct import pack, unpack

from usb.core import USBError

from . import dll_tables
from . import timeslot as prg
from .init_data_dir import PYTHON_VALIDITY_STATE_DIR, init_state_dir
from .sensor import CaptureMode, Line, RomInfo, Sensor, bitpack, get_factory_bits, get_prg_status2, \
    identify_sensor
from .table_types import SensorCaptureProg, SensorTypeInfo
from .tls import tls
from .usb import usb
from .util import assert_status

SENSOR_TYPE = 0x2449

LINE_WIDTH = 144
LINES_PER_CALIBRATION_DATA = 56

# Chunk 0x34's key line is three 48-column bands, each from a different calibration row
# around the middle one.
KEY_CALIBRATION_LINE = LINES_PER_CALIBRATION_DATA // 2
KEY_LINE_BAND_ROWS = (-10, 0, 10)
KEY_LINE_BAND_WIDTH = LINE_WIDTH // len(KEY_LINE_BAND_ROWS)

# The Windows driver treats these RomInfo.product codes alike
PRODUCT_CODES = (0x2b, 0x2d, 0x30, 0x32, 0x33)

# Windsor config record for 0x2449 in synaWudfBioUsb.dll
WINDSOR_CAL_LOW = 0xa0
WINDSOR_CAL_HIGH = 0x104
RECORD_0X32 = 0x90
RECORD_0X12 = 0x38
RECORD_0XE = 0x14d
RECORD_0X9C = 0
RECORD_0X14_LOW = 2
IMAGE_WIDTH = 0x190
IMAGE_HEIGHT = 0x17c
IMAGE_FMT_BYTE4 = 50
IMAGE_FMT_BYTE5 = 100

# Image quality percentage the Windows capture request passes down (feeds chunk 0x26)
QUALITY_PCT = 100

# captureFlags of a plain identify capture: 0x840 for captureType 2, plus the 0xc0b0
# baseline when the caller sets no flags of its own
CAPTURE_FLAGS = 0xc8f0

# The analog gain registers of the capture program, as the Windows driver sends them
AGC_REGISTER_OVERRIDES = {
    0x8000206c: 0x0070,  # SCM_VGA_AGC_INTERVAL
    0x80002070: 0x0070,  # SCM_VGA_AGC_RIGHT_GAIN
    0x80002074: 0x0000,  # SCM_PGA_AGC_RIGHT_GAIN
    0x80002078: 0x0000,  # SCM_PGA_AGC_LEFT_GAIN
}

# How often get_print() checks for cancellation while waiting for a touch
CANCEL_POLL_S = 1.0

# 0x51 statuses after which the Windows capture loop reads again. 7 means "image not
# ready". 4 aborts the capture, anything else not listed is an error.
IMAGE_READ_AGAIN = frozenset({0x0001, 0x0002, 0x0005, 0x0006, 0x0007})
# Capture event code that makes Windows keep waiting without a timeout
EVENT_NO_TIMEOUT = 5


class Cancelled(Exception):
    pass


class CaptureFailed(Exception):
    def __init__(self, status: int, source: str = '0x51 status'):
        super().__init__('Capture failed: %s 0x%04x' % (source, status))
        self.status = status


def rescale_pixel(b: int, five_to_four: bool = True) -> int:
    """clamp_i8((b - 0x80) * 10 / 4), truncating like C, with the DLL's 5 -> 4 quirk."""
    v = (b - 0x80) * 10
    q = -(-v // 4) if v < 0 else v // 4
    q = max(-0x80, min(0x7f, q))
    if five_to_four and q == 5:
        q = 4
    return q


def chunk_2e_flags(capture_flags: int, enroll: bool = False) -> int:
    d8 = 1 if enroll else 0
    if capture_flags & 0x10000:
        d8 |= 4
    elif capture_flags & 0x80000:
        d8 |= 8
    else:
        d8 |= 2
    if capture_flags & 0x100000:
        d8 |= 0x10
    elif capture_flags & 0x200000:
        d8 |= 0x20
    if capture_flags & 0x1000000:
        d8 |= 0x40
    if capture_flags & 0x2000000:
        d8 |= 0x80
    return d8


def build_chunk_26(quality_pct: int = QUALITY_PCT) -> bytes:
    """Finger-detect threshold"""
    pct = max(0, min(100, quality_pct))
    ival = (100 - pct) * (WINDSOR_CAL_HIGH - WINDSOR_CAL_LOW) // 100 + WINDSOR_CAL_LOW
    return pack('<HBBHBBIIIIIIHHBBBB', 0xb2fb, 0x0f, 0, 0, 0x0f, 0, 0x30, ival + 0x20000,
                ival + 0x9ffe0, 0x8001, 0x20a, 0x190b, 50000, 60000, 1, 9, 0x10, 0)


def build_chunk_2e(capture_flags: int = CAPTURE_FLAGS) -> bytes:
    """Image format descriptor"""
    return pack('<HHIHHHHHHBBBBBBBB', 2, 0x18, chunk_2e_flags(capture_flags), RECORD_0X32,
                RECORD_0X12, RECORD_0XE, RECORD_0X9C, IMAGE_WIDTH, IMAGE_HEIGHT, 0x3c, 0x32, 0x32,
                IMAGE_FMT_BYTE4, IMAGE_FMT_BYTE5, 10, 2, RECORD_0X14_LOW)


def patch_agc_registers(chunk32: bytes) -> bytes:
    """Apply AGC_REGISTER_OVERRIDES to a 0x32 register list (u32 base, then u16 offset/value pairs)."""
    base, = unpack('<L', chunk32[:4])
    out = bytearray(chunk32)
    for i in range(4, len(chunk32), 4):
        off, = unpack('<H', chunk32[i:i + 2])
        value = AGC_REGISTER_OVERRIDES.get(base + off)
        if value is not None:
            out[i + 2:i + 4] = pack('<H', value)
    return bytes(out)


def patch_agc_registers_prg(tst: bytes) -> bytes:
    """Apply AGC_REGISTER_OVERRIDES to the register writes in chunk 0x34's timeslot table.

    The table starts after the key line and has several sub-tables, so walk it to End of Data."""
    out = bytearray(tst)
    pc = LINE_WIDTH
    while pc < len(out):
        opcode, length, *operands = prg.decode_insn(bytes(out[pc:]))
        if opcode == 4:  # End of Data
            break
        if opcode == 13:  # Register Write
            value = AGC_REGISTER_OVERRIDES.get(operands[0])
            if value is not None:
                out[pc + 1:pc + 3] = pack('<H', value)
        pc += length
    return bytes(out)


class GetPrintResult(typing.NamedTuple):
    response: bytes  # reply to the IDENTIFY request
    interrupts: typing.List[bytes]  # every EP 0x83 interrupt seen
    status2: bytes  # the 0x51 reply
    image: typing.Optional[bytes]  # 144x56 8-bit pixels, or None if the reply didn't parse
    post_polls: typing.List[bytes]  # replies to the four 0x17 polls after the capture


class Sensor2449(Sensor):
    device_info: typing.Any
    type_info: SensorTypeInfo
    hardcoded_prog: bytes
    blank_data = b''
    firmware_calibrated = False
    capture_module_loaded = False

    def open(self, recalibrate: bool = False):
        # Session preamble, byte for byte as the Windows driver sends it
        assert_status(tls.app(bytes.fromhex('0860200080' '0b00000004')))
        assert_status(tls.app(bytes.fromhex('07' '8020008004')))

        info = identify_sensor()
        if info is None or info.type != SENSOR_TYPE:
            raise Exception('Expected sensor type 0x%04x, got %r' % (SENSOR_TYPE, info))
        self.device_info = info
        logging.info('Opening sensor: %s' % info.name)
        type_info = SensorTypeInfo.get_by_type(SENSOR_TYPE)
        assert type_info is not None
        self.type_info = type_info
        self.key_calibration_line = KEY_CALIBRATION_LINE
        self.calibration_frames = 3
        # The Windows driver sends one CALIBRATE and then the blank-image one
        self.calibration_iterations = 1

        self.rom_info = RomInfo.get()
        assert_status(tls.app(b'\x19'))
        identify_sensor()

        hardcoded_prog = SensorCaptureProg.get(self.rom_info, SENSOR_TYPE, 0x18, 0x19)
        if hardcoded_prog is None:
            raise Exception('Can\'t find initial capture program for rom %s and sensor type %x' %
                            (repr(self.rom_info), SENSOR_TYPE))
        self.hardcoded_prog = hardcoded_prog

        lines_2d = [
            unpack('<L', v)[0] for [k, v] in prg.split_chunks(hardcoded_prog)
            if k == 0x2f and isinstance(v, bytes)
        ][0]
        self.lines_per_frame = lines_2d * self.type_info.repeat_multiplier
        self.bytes_per_line = self.type_info.bytes_per_line

        factory_bits = self.factory_bits(refresh=recalibrate)
        self.factory_calibration_values = factory_bits[3][4:]
        if 7 in factory_bits:
            self.factory_calib_data = factory_bits[7][4:]

        self.calibrate(recalibrate=recalibrate)

    # -- calibration ----------------------------------------------------------------

    def cache_path(self, what: str) -> str:
        # Keyed by ROM and sensor type, so another firmware never loads stale data
        return PYTHON_VALIDITY_STATE_DIR + '%s-%d.%d-%04x.bin' % (
            what, self.rom_info.major, self.rom_info.minor, SENSOR_TYPE)

    def factory_bits(self, refresh: bool = False) -> typing.Dict[int, bytes]:
        """get_factory_bits(0x0e00), cached: they're factory constants, and a Windows login
        never reads them."""
        path = self.cache_path('factory')
        if not refresh and os.path.isfile(path):
            with open(path, 'rb') as f:
                data = f.read()
            bits = {}
            while data:
                subtag, l = unpack('<HL', data[:6])
                bits[subtag] = data[6:6 + l]
                data = data[6 + l:]
            return bits
        bits = get_factory_bits(0x0e00)
        init_state_dir()
        with open(path, 'wb') as f:
            f.write(b''.join(pack('<HL', k, len(v)) + v for k, v in bits.items()))
        return bits

    def calibrate(self, recalibrate: bool = False):
        calib_path, blank_path = self.cache_path('calib'), self.cache_path('blank')
        if not recalibrate and os.path.isfile(calib_path) and os.path.isfile(blank_path):
            with open(calib_path, 'rb') as f:
                self.calib_data = f.read()
            with open(blank_path, 'rb') as f:
                self.blank_data = f.read()
            logging.info('Calibration data loaded from %s' % calib_path)
            self.firmware_calibrated = True
            return

        logging.info('Calibrating...')
        assert_status(tls.app(b'\x06' + dll_tables.module('calibrate')))

        self.calib_data = b''
        for i in range(0, self.calibration_iterations):
            logging.debug('Calibration iteration %d...' % i)
            assert_status(tls.app(self.build_cmd_02(CaptureMode.CALIBRATE)))
            self.process_calibration_results(self.average(self.read_frame()))

        logging.debug('Requesting a blank image...')
        assert_status(tls.app(self.build_cmd_02(CaptureMode.CALIBRATE)))
        # The Windows driver keeps this averaged blank frame and sends it as chunk 0x48
        # with every capture.
        self.blank_data = self.average(self.read_frame())

        assert_status(tls.app(b'\x1a'))

        init_state_dir()
        with open(calib_path, 'wb') as f:
            f.write(self.calib_data)
        with open(blank_path, 'wb') as f:
            f.write(self.blank_data)
        self.firmware_calibrated = True

    def read_frame(self) -> bytes:
        raw = usb.read_82()
        if raw is None:
            raise Exception('No calibration frame on EP 0x82')
        return raw

    def process_calibration_results(self, cooked_data: bytes):
        # The Windows driver keeps average()'s output as it is: no scale(). rescale_pixel()
        # is applied when the 0x30/0x34 chunks are built.
        self.calib_data = cooked_data

    def get_key_line(self):
        if len(self.calib_data) == 0:
            return b'\0' * self.type_info.line_width
        bytes_per_calibration_line = len(self.calib_data) // self.type_info.lines_per_calibration_data
        key_line = b''
        for band, row_delta in enumerate(KEY_LINE_BAND_ROWS):
            row = self.key_calibration_line + row_delta
            start = 8 + row * bytes_per_calibration_line + band * KEY_LINE_BAND_WIDTH
            key_line += bytes(rescale_pixel(b) & 0xff
                              for b in self.calib_data[start:start + KEY_LINE_BAND_WIDTH])
        return key_line

    # These all use the flash
    def check_clean_slate(self):
        return False

    def persist_clean_slate(self, clean_slate: bytes):
        pass

    def save(self):
        pass

    # -- capture request ------------------------------------------------------------

    def line_update_type_1(self, mode: CaptureMode,
                           chunks: typing.List[typing.List[typing.Union[int, bytes]]]):
        if mode == CaptureMode.ENROLL:
            raise Exception('Sensor type 0x2449 enrolls on the host: use IDENTIFY captures')
        capture = mode == CaptureMode.IDENTIFY

        tst = b''
        for c in chunks:
            if c[0] == 0x34:
                assert isinstance(c[1], bytes)
                # Timeslot Table 2D. No patch_timeslot_again(): the Windows driver leaves
                # the 0x8000203c write as it is in the capture program.
                tst = self.patch_timeslot_table(c[1], True, self.type_info.repeat_multiplier)
                tst = patch_agc_registers_prg(tst)
                c[1] = self.get_key_line() + tst[self.type_info.line_width:]
            elif c[0] == 0x32:
                assert isinstance(c[1], bytes)
                c[1] = patch_agc_registers(c[1])

        chunks += [[0x17, b'']]
        if capture:
            chunks += [[0x26, build_chunk_26()]]
            chunks += [[0x2e, build_chunk_2e()]]
            chunks += [[0x47, b'']]
        chunks += [[0x44, pack('<L', 1)]]

        lines = []
        cnt = 2

        l = Line()
        lines += [l]
        l.mask = 0xff
        found = prg.find_nth_insn(tst, 6, 2)
        assert found is not None
        pc, _ = found
        l.flags = (pc + 1) | (cnt << 0x14) | 0x7000000
        l.data = self.type_info.calibration_blob
        l.v0 = 0xf
        cnt += 1

        # The factory calibration values, written to 0x8000203c and again to 0x80002040
        for reg in (0x8000203c, 0x80002040):
            found = prg.find_nth_regwrite(tst, reg, 1)
            if found is None:
                continue
            l = Line()
            lines += [l]
            l.mask = 0xff
            pc, _ = found
            l.flags = (pc + 1) | (cnt << 0x14) | 0x7000000
            l.v0, l.v1, l.data = bitpack(self.factory_calibration_values)
            l.v0 = (l.v0 - 1) | 8
            cnt += 1

        # Empty entries at the 3rd and 4th Enable Rx
        for n in (3, 4):
            found = prg.find_nth_insn(tst, 6, n)
            if found is not None:
                l = Line()
                lines += [l]
                l.mask = 0xffff
                pc, _ = found
                l.flags = pc | (cnt << 0x14) | 0x47000000
                l.data = b''
                cnt += 1

        # One more empty entry with fixed flags; it doesn't advance cnt
        l = Line()
        lines += [l]
        l.mask = 0xff
        l.flags = (cnt << 0x14) | 0x17000374
        l.data = b''
        l.v1 = 0xc

        if len(self.calib_data) > 0:
            bytes_per_calibration_line = len(self.calib_data) // self.type_info.lines_per_calibration_data
            for i in range(0, self.type_info.line_width, 4):
                l = Line()
                lines += [l]
                l.mask = 0xffffffff
                l.flags = i | (0x85 << 24)
                l.data = b''
                for j in range(0, self.type_info.lines_per_calibration_data):
                    p = 8 + j * bytes_per_calibration_line + i
                    l.data += bytes(rescale_pixel(b, five_to_four=False) & 0xff
                                    for b in self.calib_data[p:p + 4])

        # Chunk 0x43 packs the entries back to back and pads only the total
        update_transform = b''.join([
            pack('<BBH', l.v0, l.v1, l.v2) + l.data for l in lines
            if ((l.flags & 0x00f00000) >> 0x14) > 1
        ])
        pad = len(update_transform) % 4
        if pad > 0:
            update_transform += b'\0' * (4 - pad)

        for l in lines:
            pad = len(l.data) % 4
            if pad > 0:
                l.data += b'\0' * (4 - pad)

        line_update = pack('<L', len(lines))
        line_update += b''.join([pack('<LL', l.mask, l.flags) for l in lines])
        line_update += b''.join([l.data for l in lines if ((l.flags & 0x00f00000) >> 0x14) <= 1])
        chunks += [[0x30, line_update]]
        chunks += [[0x43, update_transform]]

        # The blank frame. Only once the firmware is calibrated (a 0x1a since pairing);
        # before that it crashes the device off the bus.
        if capture and self.firmware_calibrated and len(self.blank_data) > 0:
            chunks += [[0x48, pack('<HH', self.bytes_per_line,
                                   len(self.blank_data) // self.bytes_per_line) + self.blank_data]]

        return chunks

    def build_cmd_02(self, mode: CaptureMode):
        chunks = list(prg.split_chunks(self.hardcoded_prog))

        if self.rom_info.product not in PRODUCT_CODES:
            raise Exception('Unexpected RomInfo.product 0x%x' % self.rom_info.product)

        chunks = self.line_update_type_1(mode, chunks)

        if mode == CaptureMode.CALIBRATE:
            req_lines = self.calibration_frames * self.lines_per_frame + 1
        else:
            req_lines = 0

        return pack('<BHH', 2, self.bytes_per_line, req_lines) + prg.merge_chunks(chunks)

    # -- capture --------------------------------------------------------------------

    def get_print(self,
                  touch_timeout: float = 15.0,
                  settle_time: float = 5.0,
                  on_armed: typing.Optional[typing.Callable[[], None]] = None,
                  cancel: typing.Optional[threading.Event] = None,
                  on_touch: typing.Optional[typing.Callable[[], None]] = None) -> GetPrintResult:
        """Arm an IDENTIFY capture, wait for a touch and return the image.

        EP 0x83 gives the start ack (b[0]==0), the finger-detect (b[0]==2, waited on for
        touch_timeout) and capture complete (b[0]==3 with event code 4 or 7, waited on for
        settle_time). Then 0x51 returns the image; like the Windows driver we then send the
        same IDENTIFY again and poll 0x17 four times.

        Raises TimeoutError if there's no touch, CaptureFailed if the capture is aborted or
        0x51 returns an error, and Cancelled if cancel is set while waiting for a touch.
        """
        try:
            # Before the first capture of a session, load the capture module
            if not self.capture_module_loaded:
                assert_status(tls.app(b'\x06' + dll_tables.module('capture')))
                self.capture_module_loaded = True

            req = self.build_cmd_02(CaptureMode.IDENTIFY)
            rsp = tls.app(req)
            assert_status(rsp)
            if on_armed is not None:
                on_armed()

            interrupts = []

            def read_int(deadline: float) -> typing.Optional[bytes]:
                # One pending read until the deadline, as the Windows driver does.
                # A 0 ms timeout would mean "forever" to libusb.
                timeout_ms = int((deadline - time.monotonic()) * 1000)
                if timeout_ms <= 0:
                    return None
                assert usb.dev is not None
                try:
                    return bytes(usb.dev.read(0x83, 1024, timeout=timeout_ms))
                except USBError as e:
                    if e.errno != errno.ETIMEDOUT:
                        raise
                return None

            def wait_int(deadline: float) -> typing.Optional[bytes]:
                if cancel is None:
                    return read_int(deadline)
                while True:
                    if cancel.is_set():
                        raise Cancelled()
                    b = read_int(min(deadline, time.monotonic() + CANCEL_POLL_S))
                    if b is not None or time.monotonic() >= deadline:
                        return b

            # Start ack, then the finger-detect
            touch_deadline = time.monotonic() + touch_timeout
            while True:
                b = wait_int(touch_deadline)
                if b is None:
                    raise TimeoutError('No finger on the sensor within %ss' % touch_timeout)
                interrupts.append(b)
                if b[0] == 2:
                    break
            if on_touch is not None:
                on_touch()

            # Capture complete. Event codes as the Windows driver maps them: 4 = image ready,
            # 7 = read, 6 = aborted, 0 = failed, 5 = keep waiting, anything else = wait on.
            settle_deadline = time.monotonic() + settle_time
            while time.monotonic() < settle_deadline:
                b = read_int(min(settle_deadline, time.monotonic() + 0.2))
                if b is None:
                    continue
                interrupts.append(b)
                if b[0] == 3 and len(b) >= 4:
                    code, = unpack('<H', b[2:4])
                    if code in (4, 7):
                        break
                    if code in (0, 6):
                        raise CaptureFailed(code, 'capture event')
                    if code == EVENT_NO_TIMEOUT:
                        settle_deadline = time.monotonic() + settle_time
            else:
                logging.warning('No capture-complete interrupt within %.1fs, reading the image anyway' %
                                settle_time)

            read_deadline = time.monotonic() + settle_time
            while True:
                status2 = get_prg_status2()
                status, = unpack('<H', status2[:2])
                if status in IMAGE_READ_AGAIN and time.monotonic() < read_deadline:
                    continue
                if status != 0:
                    raise CaptureFailed(status)
                break

            post_polls = []
            try:
                assert_status(tls.app(req))
                for _ in range(4):
                    post_polls.append(tls.app(b'\x17'))
            except USBError:
                # Don't lose the image we already have
                logging.warning('IDENTIFY resend or 0x17 poll failed', exc_info=True)

            return GetPrintResult(rsp, interrupts, status2, self.parse_image(status2), post_polls)
        finally:
            # Capture stop if still running, cleanup. Don't let a failure here hide the
            # exception that got us here.
            try:
                tls.app(b'\x04')
                tls.app(b'\x52')
            except USBError as e:
                logging.warning('Capture cleanup failed: %s' % e)

    @staticmethod
    def parse_image(status2: bytes) -> typing.Optional[bytes]:
        """0x51 reply: status, u32 length, then x/y (rows/columns), w1, w2, error, pixels."""
        body = status2[2:]
        if len(body) < 16:
            logging.warning('0x51 reply too short for an image: %d bytes' % len(body))
            return None
        l, = unpack('<L', body[:4])
        body = body[4:]
        if l != len(body):
            logging.warning('0x51 reply length mismatch: header says %d, got %d' % (l, len(body)))
            return None
        x, y, w1, w2, error = unpack('<HHHHL', body[:12])
        pixels = body[12:]
        if error != 0 or len(pixels) != x * y:
            logging.warning('Unexpected 0x51 image: %dx%d, error 0x%x, %d bytes' % (x, y, error, len(pixels)))
            return None
        return pixels

    # -- on-chip database operations, which this sensor doesn't have -----------------

    def enroll(self, identity, subtype, update_cb):
        raise Exception('Sensor type 0x2449 has no template database: use validitysensor.hostmatch')

    def identify(self, update_cb):
        raise Exception('Sensor type 0x2449 has no template database: use validitysensor.hostmatch')
