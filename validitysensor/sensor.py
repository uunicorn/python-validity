
from enum import Enum
from hashlib import sha256
import os.path
from .tls import tls
from .usb import usb
from .db import db, subtype_to_string
from .flash import write_enable, flush_changes, read_flash, erase_flash, write_flash_all, read_flash_all
from time import sleep
from struct import pack, unpack
from .table_types import SensorTypeInfo, SensorCaptureProg
from binascii import hexlify, unhexlify
from .util import assert_status, unhex
from .hw_tables import dev_info_lookup
from .blobs import reset_blob
from . import timeslot as prg

# TODO: this should be specific to an individual device (system may have more than one sensor)
calib_data_path='/usr/share/python-validity/calib-data.bin'

line_update_type1_devices = [ 0xB5, 0x885, 0xB3, 0x143B, 0x1055, 0xE1, 0x8B1, 0xEA, 0xE4, 0xED, 0x1825, 0x1FF5, 0x199 ]

# TODO use more sophisticated glow patters in different cases
def glow_start_scan():
    cmd=unhexlify('3920bf0200ffff0000019900200000000099990000000000000000000000000020000000000000000000000000ffff000000990020000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000')
    assert_status(tls.app(cmd))

def glow_end_scan():
    cmd=unhexlify('39f4010000f401000001ff002000000000ffff0000000000000000000000000020000000000000000000000000f401000000ff0020000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000')
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


def read_hw_reg32(addr):
    rsp=tls.cmd(pack('<BLB', 7, addr, 4))
    assert_status(rsp)
    rsp, = unpack('<L', rsp[2:])
    return rsp

def write_hw_reg32(addr, val):
    rsp=tls.cmd(pack('<BLLB', 8, addr, val, 4))
    assert_status(rsp)

class RebootException(Exception):
    pass

def reboot():
    assert_status(tls.cmd(unhex('050200')))
    raise RebootException()

def factory_reset():
    assert_status(usb.cmd(reset_blob))
    assert_status(usb.cmd(b'\x10' + b'\0'*0x61))
    reboot()

class RomInfo():
    def get():
        rsp=tls.cmd(b'\x01')
        assert_status(rsp)
        rsp=rsp[2:]
        return RomInfo(*unpack('<LLBBxBxxxB', rsp[0:0x10]))

    def __init__(self, timestamp, build, major, minor, product, u1):
        self.timestamp, self.build, self.major, self.minor, self.product, self.u1 = timestamp, build, major, minor, product, u1

    def __repr__(self):
        return 'RomInfo(timestamp=%d, build=%d, major=%d, minor=%d, product=%d, u1=%d)' % (
            self.timestamp, self.build, self.major, self.minor, self.product, self.u1)


def identify_sensor():
    rsp=tls.cmd(b'\x75')
    assert_status(rsp)
    rsp=rsp[2:]

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
def get_factory_bits(tag):
    rsp=tls.cmd(pack('<B H HL', 0x6f, tag, 0, 0))
    assert_status(rsp)
    rsp=rsp[2:]

    wtf, entries = unpack('<LL', rsp[:8])
    rsp = rsp[8:]

    rc={}
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
    l=len(b)
    m=min(b)
    x=max(b)

    # maximum delta which we must encode
    x-=m

    # count useful bits
    u=0
    while x > 0:
        x>>=1
        u+=1

    # convert to array of binary strings with each element exactly u characters long
    b=[bin(i-m+0x100)[-u:] for i in b]

    # combine chunks into one long text number with u*l binary digits and parse it as integer
    b=int(''.join(b[::-1]), 2)

    # convert back to bytes
    b=b.to_bytes((u*l+7)//8, 'little')

    return (u, m, b)

class Line():
    mask=None
    flags=None
    data=None
    v0=0
    v1=0
    v2=0

def clip(x):
    if x < -128:
        x=-128

    if x > 127:
        x=127

    return x & 0xff

def scale(x):
    x -= 0x80
    x = int(x*10/0x22) # TODO: scaling factor depends on a device
    return clip(x)


def add(l, r):
    # Make signed
    l, r = unpack('bb', pack('BB', l, r))
    return clip(l+r)

def chunks(b, l):
    return [b[i:i+l] for i in range(0, len(b), l)]

class CaptureMode(Enum):
    CALIBRATE=1
    IDENTIFY=2
    ENROLL=3

class CancelledException(Exception):
    pass

class Sensor():
    calib_data=b''

    def open(self):
        self.interrupt_cb = None
        self.device_info = identify_sensor()

        print('Opening sensor: %s' % self.device_info.name)
        self.type_info = SensorTypeInfo.get_by_type(self.device_info.type)
        
        if self.device_info.type == 0x199:
            self.key_calibration_line = 0x38 # (lines_per_calibration_data/2), but hardcoded for sensor type 0x199
            self.calibration_frames = 3 # TODO: workout where it's really comming from
            self.calibration_iterations = 3 # hardcoded for type
        elif self.device_info.type == 0xdb:
            self.key_calibration_line = 0x48 # TODO 48 is just a guess -- find it
            self.calibration_frames = 6 # TODO: workout where it's really comming from
            self.calibration_iterations = 0
        else:
            raise Exception('Device %s is not supported (sensor type 0x%x)' % (self.device_info.name, self.device_info.type))


        self.rom_info = RomInfo.get()
        self.hardcoded_prog = SensorCaptureProg.get(self.rom_info, self.device_info.type, 0x18, 0x19) # TODO: find where 0x18, 0x19 coming from
        if self.hardcoded_prog is None:
            raise Exception('Can\'t find initial capture program for rom %s and sensor type %x' % (repr(self.rom_info), self.device_info.type))

        # Look for a "2D" chunk. It must have a 32 bit integer which represent the number of lines per frame
        lines_2d = [unpack('<L', v)[0] for [k, v] in prg.split_chunks(self.hardcoded_prog) if k == 0x2f][0]
        self.lines_per_frame = lines_2d*self.type_info.repeat_multiplier
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
    def patch_timeslot_table(self, b, inc_address, mult):
        b=bytearray(b)
        i=0
        while i+3 < len(b):
            if b[i] & 0xf8 == 0x10:
                if b[i+2] > 1:
                    b[i+2] *= mult
                    if inc_address:
                        b[i+1] += 1
                i+=3
                continue

            if b[i] == 0:
                i+=1
                continue

            if b[i] == 7:
                i+=2
                continue

            break

        return bytes(b)

    def patch_timeslot_again(self, b):
        b=bytearray(b)

        pc = 0
        match=None
        # Look for the last Call in the script
        while pc < len(b):
            opcode, l, *operands = prg.decode_insn(b[pc:])

            # End of Table, Return, End of Data
            if opcode == 1 or opcode == 2 or opcode == 4:
                break

            # Call
            if opcode == 11:
                match = operands[1] # destination address

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
        b[match+1] = self.factory_calibration_values[self.key_calibration_line]

        return bytes(b)

    def average(self, raw_calib_data):
        frame_size = self.lines_per_frame * self.bytes_per_line
        interleave_lines = self.lines_per_frame // self.type_info.lines_per_calibration_data # 2, TODO: algo is quite different when it is 1
        input_frames = self.calibration_frames
        
        if interleave_lines > 1:
            if input_frames > 1:
                # skip the first frame
                input_frames -= 1
                base_address = frame_size

            frame=raw_calib_data[base_address:base_address+frame_size]

            # split into groups of lines
            frame=chunks(frame, interleave_lines*self.bytes_per_line)

            # split group of lines into lines
            frame=[chunks(f, self.bytes_per_line) for f in frame]
            
            # calculate averages across interleaved lines
            frame=[bytes([sum(i)//len(f) for i in zip(*f)]) for f in frame]
            frame=b''.join(frame)
        else:
            if input_frames > 1:
                # skip the first frame
                input_frames -= 2
                base_address = frame_size*2

            frames=raw_calib_data[base_address:base_address+frame_size*input_frames]
            frames=chunks(frames, frame_size)
            frame=[int(sum(i)/input_frames) for i in zip(*frames)]
            frame=bytes(frame)

        return frame

    def process_calibration_results(self, cooked_data):
        frame=chunks(cooked_data, self.bytes_per_line)

        # apply scaling factors
        frame=[f[:8] + bytes(map(scale, f[8:])) for f in frame]
        frame=b''.join(frame)

        if len(self.calib_data) > 0:
            # Not the first calibration run. Combine results
            # split previous calibration info into lines
            lll=chunks(self.calib_data, self.bytes_per_line)

            # split next calibration info into lines
            rrr=chunks(frame, self.bytes_per_line)
            
            # Don't touch the first 8 bytes of each line, add everything else as signed characters, clipping the values
            combined=[ll[:8] + bytes([add(l, r) for l, r in zip(ll[8:],rr[8:])]) for ll, rr in zip(lll, rrr)]
            self.calib_data = bytes(b''.join(combined))
        else:
            self.calib_data = frame

    def get_key_line(self):
        if len(self.calib_data) > 0:
            bytes_per_calibration_line=len(self.calib_data) // self.type_info.lines_per_calibration_data
            key_line_offset=8+bytes_per_calibration_line*self.key_calibration_line
            key_line=self.calib_data[key_line_offset:key_line_offset+self.type_info.line_width]
            key_line=bytes([i-1 if i == 5 else i for i in key_line])
        else:
            key_line=b'\0'*self.type_info.line_width

        return key_line

    def line_update_type_1(self, mode, chunks):
        for c in chunks:
            # Timeslot Table 2D
            if c[0] == 0x34:
                # TODO: figure out when to use address increment
                tst = self.patch_timeslot_table(c[1], True, self.type_info.repeat_multiplier)
                if mode != CaptureMode.CALIBRATE:
                    tst=self.patch_timeslot_again(tst)
                c[1] = self.get_key_line() + tst[self.type_info.line_width:]

        #---------------- Reply Configuration ---------------
        chunks += [[0x17, b'']]

        if mode == CaptureMode.IDENTIFY:
            # This type of fragment is not present in the debugging dump routine.
            # It seems to be only used for identification and it looks almost identical to Finger Detect (0x26)
            # Seems to be the same all the time for a given sensor and mostly hardcoded
            # TODO: analyse construct_wtf_4e @0000000180090BF0
            chunks += [[0x4e, unhexlify('fbb20f0000000f00300000008700020067000a00018000000a0200000b1900008813b80b01091000')]]
            # Image Reconstruction.
            # TODO: analyse add_image_reconstruction_cmd_02_buff_list_item @000000018008EA70
            chunks += [[0x2e, unhexlify('0200180002000000700070004d010000a0008c003c32321e3c0a0202')]]
        elif mode == CaptureMode.ENROLL:
            chunks += [[0x26, unhexlify('fbb20f0000000f00300000008700020067000a00018000000a0200000b19000050c360ea01091000')]]
            # Image Reconstruction. There is only one byte difference with the "identify" version. (same is true for 0097)
            chunks += [[0x2e, unhexlify('0200180023000000700070004d010000a0008c003c32321e3c0a0202')]]

        #---------------- Interleave ---------------
        chunks += [[0x44, pack('<L', 1)]]

        lines=[]
        cnt=2 # TODO figure out why 2

        l=Line()
        lines += [l]
        l.mask = 0xff
        # Find 2nd "Enable Rx" instruction
        pc, _ = prg.find_nth_insn(tst, 6, 2) 
        l.flags = (pc + 1) | (cnt << 0x14) | 0x7000000
        l.data = self.type_info.calibration_blob
        l.v0 = 0xf
        cnt += 1

        l=Line()
        lines += [l]
        l.mask = 0xff
        # Find 1st "Write Register" instruction to the 0x8000203C port
        pc, _ = prg.find_nth_regwrite(tst, 0x8000203C, 1) 
        l.flags = (pc + 1) | (cnt << 0x14) | 0x7000000
        l.v0, l.v1, l.data = bitpack(self.factory_calibration_values)
        l.v0 = (l.v0-1) | 8
        cnt += 1

        if len(self.calib_data) > 0:
            bytes_per_calibration_line=len(self.calib_data) // self.type_info.lines_per_calibration_data

            for i in range(0, 112, 4):
                l=Line()
                lines += [l]
                l.mask=0xffffffff
                l.flags=i | (0x85 << 24)
                l.data=b''
                for j in range(0, 112):
                    p=8+j*bytes_per_calibration_line+i
                    l.data += self.calib_data[p:p+4]

        # Align to dwords, as the sensor demands it
        for l in lines:
            pad = len(l.data) % 4
            if pad > 0:
                l.data += b'\0' * (4 - pad)

            
        #---------------- Line Update ---------------
        line_update = pack('<L', len(lines))
        line_update += b''.join([pack('<LL', l.mask, l.flags) for l in lines])

        line_update += b''.join([l.data for l in lines if ((l.flags & 0x00f00000) >> 0x14) <= 1])
        chunks += [[0x30, line_update]]

        #---------------- Line Update Transform ---------------
        update_transform = b''.join([pack('<BBH', l.v0, l.v1, l.v2) + l.data for l in lines if ((l.flags & 0x00f00000) >> 0x14) > 1])
        chunks += [[0x43, update_transform]]

        return chunks

    def line_update_type_2(self, mode, chunks):
        for c in chunks:
            # patch the 2D params. 
            # The following is only needed on some rom versions below 6.5 as reported by cmd_01
            #if c[0] == 0x2f:
            #    c[1] = pack('<L', unpack('<L', c[1])[0]*mult)

            # Timeslot Table 2D
            if c[0] == 0x34:
                # TODO: figure out when to use address increment
                tst = self.patch_timeslot_table(c[1], True, self.type_info.repeat_multiplier)
                if mode != CaptureMode.CALIBRATE:
                    tst=self.patch_timeslot_again(tst)
                c[1] = tst

        #---------------- Reply Configuration ---------------
        chunks += [[0x17, b'']]

        if mode == CaptureMode.IDENTIFY:
            # This type of fragment is not present in the debugging dump routine.
            # It seems to be only used for identification and it looks almost identical to Finger Detect (0x26)
            # Seems to be the same all the time for a given sensor and mostly hardcoded
            # TODO: analyse construct_wtf_4e @0000000180090BF0
            chunks += [[0x4e, unhexlify('fbb20f0000000f00300000006001020040010a00018000000a0200000b1900008813b80b01091000')]]
            # Image Reconstruction.
            # TODO: analyse add_image_reconstruction_cmd_02_buff_list_item @000000018008EA70
            chunks += [[0x2e, unhexlify('0200180002000000900090004d01000090017c013c323232640a0201')]]
        elif mode == CaptureMode.ENROLL:
            chunks += [[0x26, unhexlify('fbb20f0000000f00300000006001020040010a00018000000a0200000b19000050c360ea01091000')]]
            # Image Reconstruction. There is only one byte difference with the "identify" version. (same is true for 0097)
            chunks += [[0x2e, unhexlify('0200180023000000900090004d01000090017c013c323232640a0201')]]

        lines = []

        l=Line()
        lines += [l]
        l.mask = 0xff
        # Find 2nd "Enable Rx" instruction
        pc, _ = prg.find_nth_insn(tst, 6, 2) 
        l.flags = (pc + 1) | 0x3000000
        l.data = self.type_info.calibration_blob

        l=Line()
        lines += [l]
        l.mask = 0xff
        # Find 1st "Write Register" instruction to the 0x8000203C port
        pc, _ = prg.find_nth_regwrite(tst, 0x800020fc, 1) 
        l.flags = (pc + 1) | 0x3000000
        l.data = self.factory_calib_data

        l=Line()
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

            
        #---------------- Line Update ---------------
        line_update = pack('<L', len(lines))
        line_update += b''.join([pack('<LL', l.mask, l.flags) for l in lines])

        line_update += b''.join([l.data for l in lines])
        chunks += [[0x30, line_update]]

        return chunks

    def build_cmd_02(self, mode):
        chunks=list(prg.split_chunks(self.hardcoded_prog))

        if self.rom_info.product != 0x30:
            raise Exception('Not implemented')

        if self.device_info.type in line_update_type1_devices:
            chunks=self.line_update_type_1(mode, chunks)
        else:
            chunks=self.line_update_type_2(mode, chunks)

        if mode == CaptureMode.CALIBRATE:
            req_lines = self.calibration_frames*self.lines_per_frame+1 # TODO: figure out how this is actually calculated
        else:
            req_lines = 0

        return pack('<BHH', 2, self.bytes_per_line, req_lines) + prg.merge_chunks(chunks)

    def persist_clean_slate(self, clean_slate):
        start = read_flash(6, 0, 0x44)

        if start != b'\xff' * 0x44:
            if clean_slate[:0x44] == start:
                print('Calibration data already matches the data on the flash.')
                return
            else:
                print('Calibration flash already written. Erasing.')
                erase_flash(6)

        write_flash_all(6, 0, clean_slate)

    def check_clean_slate(self):
        start = read_flash(6, 0, 0x44)
        magic, l = unpack('<HH', start[:4])
        start = start[4:]

        if magic != 0x5002:
            return False

        hs, zeroes = start[0:0x20], start[0x20:0x40]
        
        if zeroes != b'\0'*0x20:
            print('Unexpected contents in calibration flash partition')
            return False

        img = read_flash_all(6, 0x44, l)
        if hs != sha256(img).digest():
            print('Calibration flash hash mismatch')
            print(hexlify(hs), hexlify(img))
            return False

        return True


    def calibrate(self):
        if os.path.isfile(calib_data_path):
            with open(calib_data_path, 'rb') as f:
                self.calib_data = f.read()
                print('Calibration data loaded from a file.')

            if self.check_clean_slate():
                return
            else:
                print('No calibration data on the flash. Calibrating...')
        else:
            self.calib_data = b''
            print('No calibration data was loaded. Calibrating...')

        for i in range(0, self.calibration_iterations):
            print('Calibration iteration %d...' % i)
            rsp = tls.cmd(self.build_cmd_02(CaptureMode.CALIBRATE))
            assert_status(rsp)
            self.process_calibration_results(self.average(usb.read_82()))

        print('Requesting a blank image...')

        # Get the "clean slate" image to store on the flash for fine-grained after-capture adjustments
        rsp = tls.cmd(self.build_cmd_02(CaptureMode.CALIBRATE))
        assert_status(rsp)

        clean_slate = self.average(usb.read_82())
        clean_slate = pack('<H', len(clean_slate)) + clean_slate
        clean_slate = clean_slate + pack('<H', 0) # TODO: still don't know what this zero is for
        clean_slate = pack('<H', len(clean_slate)) + sha256(clean_slate).digest() + b'\0'*0x20 + clean_slate
        clean_slate = pack('<H', 0x5002) + clean_slate

        self.persist_clean_slate(clean_slate)
        self.save()

    def cancel(self):
        cb=usb.interrupt_cb
        if cb is not None:
            cb(None)

    def capture(self, mode, complete_cb):
        if usb.interrupt_cb is not None:
            raise Exception('Wrong state for capture')

        def next(cb):
            if cb is None:
                usb.interrupt_cb = None
                return

            def run(b):
                try:
                    if b is None:
                        raise CancelledException()

                    cb(b)
                except Exception as e:
                    usb.interrupt_cb = None
                    tls.app(unhexlify('04')) # capture stop if still running, cleanup
                    complete_cb(None, e)

            usb.interrupt_cb = run


        def wait_start(b):
            if b[0] != 0:
                raise Exception('wait_start: Unexpected interrupt type %s' % hexlify(b).decode())

            next(wait_finger)

        def wait_finger(b):
            if b[0] == 2:
                next(wait_capture_complete)

            # TODO: report status?

        def wait_capture_complete(b):
            if b[0] != 3:
                raise Exception('wait_finger: Unexpected interrupt type %s' % hexlify(b).decode())

            if b[2] & 4:
                capture_complete()
                return
            
            # TODO: report status?

        def capture_complete():
            next(None)

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

            complete_cb((x, y, w1, w2), None)

        next(wait_start)

        assert_status(tls.app(self.build_cmd_02(mode)))

    def enrollment_update_start(self, key, complete_cb):
        if usb.interrupt_cb is not None:
            raise Exception('Wrong state, sensor\'s busy')

        def wait(b):
            if b is None:
                raise Exception('Cancelling while enrollment is being updated is not a good idea.')

            usb.interrupt_cb = None
            complete_cb(new_key, b)

        usb.interrupt_cb = wait

        rsp=tls.app(pack('<BLL', 0x68, key, 0))
        assert_status(rsp)
        new_key, = unpack('<L', rsp[2:])

    def enrollment_update_end(self):
        assert_status(tls.app(pack('<BL', 0x69, 0)))

    # Generates interrupt
    def enrollment_update(self, prev):
        write_enable()
        rsp=tls.app(b'\x6b' + prev)
        assert_status(rsp)
        flush_changes()

        return rsp[2:]

    def append_new_image(self, prev, complete_cb):
        if usb.interrupt_cb is not None:
            raise Exception('Wrong state, sensor\'s busy')

        def finished(b):
            res = self.enrollment_update(prev)

            l, res = res[:2], res[2:]
            l, = unpack('<H', l)
            if l != len(res):
                raise Exception('Response size does not match %d != %d', l, len(res))

            magic_len = 0x38 # hardcoded in the DLL
            template = header = tid = None

            while len(res) > 0:
                tag, l = unpack('<HH', res[:4])

                if tag == 0:
                    template = res[:magic_len+l]
                elif tag == 1:
                    header = res[magic_len:magic_len+l]
                elif tag == 3:
                    tid = res[magic_len:magic_len+l]
                else:
                    print('Ignoring unknown tag %x' % tag)
                    
                res=res[magic_len+l:]

            return (header, template, tid)

        def wait(b):
            if b is None:
                raise Exception('Cancelling while enrollment is being updated is not a good idea.')

            usb.interrupt_cb = None

            try:
                complete_cb(finished(b), None)
            except Exception as e:
                complete_cb(None, e)

        usb.interrupt_cb = wait

        # Start the work. Interrupt will be generated when it is finished.
        self.enrollment_update(prev)
        

    def make_finger_data(self, subtype, template, tid):
        template = pack('<HH', 1, len(template)) + template
        tid = pack('<HH', 2, len(tid)) + tid

        tinfo = template + tid

        tinfo = pack('<HHHH', subtype, 3, len(tinfo), 0x20) + tinfo
        tinfo += b'\0' * 0x20

        return tinfo

    def enroll(self, identity, subtype, update_cb, complete_cb):
        def do_create_finger(final_template, tid):
            try:
                tinfo = self.make_finger_data(subtype, final_template, tid)

                usr=db.lookup_user(identity)
                if usr == None:
                    usr = db.new_user(identity)
                else:
                    usr = usr.dbid
                
                recid = db.new_finger(usr, tinfo)

                glow_end_scan()

                complete_cb(recid, None)
            except Exception as e:
                complete_cb(None, e)


        def start_iteration(key=0, template=b''):
            def wrap_cb(f):
                def r(res, ex):
                    try:
                        f(res, ex)
                    except CancelledException as e:
                        glow_end_scan()
                        complete_cb(None, e)
                    except Exception as e:
                        update_cb(None, e)
                        # sleep, so we don't end up in a busy loop spaming the sensor with requests in case of unrecoverable error
                        sleep(1)
                        self.enrollment_update_end()
                        start_iteration(key, template)

                return r

            def capture_cb(res, e):
                if e is not None: raise e
                def enrollment_update_start_cb(new_key, b):
                    def append_new_image_cb(rsp, e):
                        if e is not None: raise e

                        self.enrollment_update_end()

                        header, new_template, tid = rsp
                        update_cb(header, None)

                        if tid:
                            do_create_finger(new_template, tid)
                        else:
                            start_iteration(new_key, new_template)
                    ## end of append_new_image_cb

                    self.append_new_image(template, wrap_cb(append_new_image_cb))
                ## end of enrollment_update_start_cb

                self.enrollment_update_start(key, wrap_cb(enrollment_update_start_cb))
            ## end of capture_cb

            glow_start_scan()
            self.capture(CaptureMode.ENROLL, wrap_cb(capture_cb))

        start_iteration()

    def parse_dict(self, x):
        rc={}

        while len(x) > 0:
            (t, l), x = unpack('<HH', x[:4]), x[4:]
            rc[t], x = x[:l], x[l:]

        return rc

    def match_finger(self, complete_cb):
        if usb.interrupt_cb is not None:
            raise Exception('Wrong state for capture')

        def wait(b):
            if b is None:
                raise Exception('Cancelling while finger match is running is not a good idea.')

            try:
                if b[0] != 3:
                    raise Exception('Finger not recognized: %s' % hexlify(b).decode())

                # get results
                rsp = tls.app(unhexlify('6000000000'))
                assert_status(rsp)
                rsp = rsp[2:]

                (l,), rsp = unpack('<H', rsp[:2]), rsp[2:]
                if l != len(rsp):
                    raise Exception('Response size does not match')

                rsp=self.parse_dict(rsp)

                usrid, subtype, hsh = rsp[1], rsp[3], rsp[4]
                usrid, = unpack('<L', usrid)
                subtype, = unpack('<H', subtype)

                complete_cb((usrid, subtype, hsh), None)
            except Exception as e:
                complete_cb(None, e)
            finally:
                usb.interrupt_cb = None
                # cleanup, ignore any errors
                tls.app(unhexlify('6200000000'))

        usb.interrupt_cb = wait

        stg_id=0 # match against any storage
        usr_id=0 # match against any user
        cmd=pack('<BBBHHHHH', 0x5e, 2, 0xff, stg_id, usr_id, 1, 0,0)
        rsp=tls.app(cmd)
        assert_status(rsp)

        
    def identify(self, update_cb, complete_cb):
        def start():
            try:
                glow_start_scan()
                self.capture(CaptureMode.IDENTIFY, capture_cb)
            except Exception as e:
                # failed to start the capture, pointless to retry
                glow_end_scan()
                complete_cb(None, e)

        def capture_cb(_, e):
            try:
                if e is not None: raise e
                self.match_finger(complete_cb)
            except CancelledException as e:
                glow_end_scan()
                complete_cb(None, e)
            except Exception as e:
                # Capture failed, retry
                update_cb(e)
                sleep(1)
                start()

        start()

    def get_finger_blobs(self, usrid, subtype):
        usr = db.get_user(usrid)
        fingerids = [f['dbid'] for f in usr.fingers if f['subtype'] == subtype]

        if len(fingerids) != 1:
            raise Exception('Unexpected matching finger count')
        
        finger_record = db.get_record_children(fingerids[0])

        ids=[r['dbid'] for r in finger_record.children if r['type'] == 8]
        return [db.get_record_value(id).value for id in ids]

sensor = Sensor()

