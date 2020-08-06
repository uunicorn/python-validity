from binascii import hexlify
from struct import unpack, pack

codes = {}
codes[0x0] = "No Operation"
codes[0x1] = "Swipe"
codes[0x2] = "Timeslot Configuration"
codes[0x3] = "Register"
codes[0x4] = "Register Set 32"
codes[0x5] = "Register Operation 32"
codes[0x6] = "Security"
codes[0x7] = "WOE"
codes[0x8] = "Motion 1"
codes[0xa] = "CPUCLK"
codes[0xb] = "Motion 2"
codes[0xc] = "Calibration Block"
codes[0xd] = "Sweep"
codes[0xe] = "Zone Configuration"
codes[0xf] = "Zones Per Sweep"
codes[0x10] = "Lines Per Sweep Iteration"
codes[0x11] = "Lines Per Sweep"
codes[0x12] = "Total Zones"
codes[0x13] = "CAL WOE Ctrl"
codes[0x14] = "Cal WOE Mask"
codes[0x15] = "BW Reduciton"
codes[0x16] = "AGC"
codes[0x17] = "Reply Configuration"
codes[0x18] = "Motion 3"
codes[0x19] = "WOVAR"
codes[0x1a] = "Block MOde"
codes[0x1b] = "Bit Reduction"
codes[0x1c] = "Motion 4"
codes[0x1d] = "Calibration WOENF"
codes[0x1e] = "Calibration"
codes[0x1f] = "Zone Configuration A"
codes[0x20] = "Set Register 32"
codes[0x21] = "Register Operation 32A"
codes[0x22] = "Fingerprint Buffering"
codes[0x23] = "Reply Config + Timeslot Table"
codes[0x24] = "Baseline"
codes[0x25] = "SO Alternate"
codes[0x26] = "Finger Detect"
codes[0x27] = "Finger Detect Sample Register"
codes[0x28] = "Finger Detect Scan Registers"
codes[0x29] = "Timeslot Table Offset"
codes[0x2a] = "ACM Config"
codes[0x2b] = "ACM Control"
codes[0x2c] = "CEM Config"
codes[0x2d] = "CEM Control"
codes[0x2e] = "Image Reconstruction"
codes[0x2f] = "2D"
codes[0x30] = "Line Update"
codes[0x31] = "FDetect Timeslot Table"
codes[0x32] = "Register List 16"
codes[0x33] = "Register list 32"
codes[0x34] = "Timeslot Table 2D"
codes[0x35] = "Timeslot Table Offset for Finger Detect"
codes[0x36] = "Security Aligned"
codes[0x37] = "WOF2"
codes[0x38] = "WOE WOF"
codes[0x39] = "Navigation"
codes[0x3a] = "WOE WOF2 Version2"
codes[0x3b] = "Cal WOE WOF2"
codes[0x3c] = "Event Signal"
codes[0x3d] = "IFS Frame Stats"
codes[0x3e] = "SNR Method 4"
codes[0x3f] = "WOE WOF2 Version 3"
codes[0x40] = "Calibrate WOE WOF2 Version 3"
codes[0x41] = "Finger Detect Ratchet"
codes[0x42] = "Data Encoder"
codes[0x43] = "Line Update Transform"
codes[0x44] = "Line Update InterLeave"
codes[0x45] = "SO Table Values for Macros"
codes[0x46] = "Timeslot Macro Definitions"
codes[0x47] = "Enable ASP Feature"
codes[0x48] = "Baseline Frame"
codes[0x49] = "Rx Select"
codes[0x4e] = "WTF"
codes[0xffff] = "Unknown"

insn_to_string = [
    'NOOP',  # 0
    'End of Table',  # 1
    'Return',  # 2
    'Clear SO',  # 3
    'End of Data',  # 4 
    'Marco %02x',  # 5
    'Enable Rx 0x%02x',  # 6
    'Idle Rx 0x%03x',  # 7
    'Enable SO 0x%03x',  # 8
    'Disable SO 0x%03x',  # 9
    'Interrupt %x',  # 10
    'Call rx_inc=%d, addr=%x, repeat=%d',  # 11
    'Features %02x',  # 12
    'Register Write *0x%08x = 0x%04x',  # 13
    'Sample %x, %x',  # 14
    'Sample Repeat %x, %x, repeat=%x',  # 15
]


def decode_insn(b):
    if b[0] == 0:
        return 0, 1
    elif b[0] == 1:
        return 1, 1
    elif b[0] == 2:
        return 2, 1
    elif b[0] == 3:
        return 3, 1
    elif b[0] == 4:
        return 4, 1
    elif b[0] == 5:
        return 5, 2, b[1]
    elif b[0] == 6:
        return 6, 2, b[1]
    elif b[0] == 7:
        return 7, 2, 0x100 if b[1] == 0 else b[1]
    elif b[0] & 0xfe == 8:
        return 8, 2, (b[0] & 1) << 8 | b[1]
    elif b[0] & 0xfe == 0xa:
        return 9, 2, (b[0] & 1) << 8 | b[1]
    elif b[0] & 0xfc == 0xc:
        return 10, 1, b[0] & 3
    elif b[0] & 0xf8 == 0x10:
        return 11, 3, b[0] & 7, b[1] << 2, 0x100 if b[2] == 0 else b[2]
    elif b[0] & 0xe0 == 0x20:
        return 12, 1, b[0] & 0x1f  # TODO check how features are converted to op args
    elif b[0] & 0xc0 == 0x40:
        return 13, 3, (b[0] & 0x3f) * 4 + 0x80002000, b[1] | (b[2] << 8)
    elif b[0] & 0xc0 == 0x80:
        return 14, 1, (b[0] & 0x38) >> 3, b[0] & 7
    elif b[0] & 0xc0 == 0xc0:
        return 15, 2, (b[0] & 0x38) >> 3, b[0] & 7, 0x100 if b[1] == 0 else b[1]
    else:
        raise Exception('Unhandled instruction %02x' % b)


def disassm_timeslot_table(b, off):
    pc = off
    while len(b) > 0:
        op, sz, *operands = decode_insn(b)
        if sz > len(b):
            raise Exception('Truncated instruction')
        print('    %04x: %-6s %s' %
              (pc, hexlify(b[:sz]).decode(), insn_to_string[op] % tuple(operands)))
        b = b[sz:]
        pc += sz


def find_nth_insn(b, opcode, n):
    pc = 0
    while len(b) > 0:
        op, sz, *_ = decode_insn(b)

        if sz > len(b):
            raise Exception('Truncated instruction')

        if op == opcode:
            n -= 1
            if n == 0:
                return pc, b[:sz]

        b = b[sz:]
        pc += sz


def find_nth_regwrite(b, reg_addr, n):
    pc = 0
    while len(b) > 0:
        op, sz, *operands = decode_insn(b)

        if sz > len(b):
            raise Exception('Truncated instruction')

        if op == 13:
            addr, value = operands
            if addr == reg_addr:
                n -= 1
                if n == 0:
                    return pc, b[:sz]

        b = b[sz:]
        pc += sz


def split_chunks(b):
    while len(b) > 0:
        (typ, sz), b = unpack('<HH', b[:4]), b[4:]
        p, b = b[:sz], b[sz:]
        yield [typ, p]


def merge_chunks(cs):
    return b''.join([pack('<HH', key, len(val)) + val for key, val in cs])


def dump_all(b: bytes):
    ts = None  # type: typing.Optional[bytes]
    ts_off = None  # type: typing.Optional[int]
    while len(b) > 0:
        (typ, sz), b = unpack('<HH', b[:4]), b[4:]
        p, b = b[:sz], b[sz:]
        if typ == 0x20:
            addr, val = unpack('<LL', p)
            print('Set Register 32:')
            print('   *0x%08x = 0x%08x' % (addr, val))
        elif typ == 0x32:
            print('Set Registers 16:')
            (base, ), p = unpack('<L', p[:4]), p[4:]
            while len(p) > 0:
                (off, val), p = unpack('<HH', p[:4]), p[4:]
                print('   *0x%08x = 0x%04x' % (off + base, val))
        elif typ == 0x33:
            print('Set Registers 32:')
            (base, ), p = unpack('<L', p[:4]), p[4:]
            while len(p) > 0:
                (off, val), p = unpack('<HL', p[:6]), p[6:]
                print('   *0x%08x = 0x%08x' % (off + base, val))
        elif typ == 0x34:
            print('%04x (%20s): (0x%x bytes) %s' % (typ, codes[typ], len(p), hexlify(p).decode()))
            ts = p
        elif typ == 0x29:
            ts_off, = unpack('<L', p)
            print('%04x (%20s): 0x%x' % (typ, codes[typ], ts_off))
        else:
            print('%04x (%20s): (0x%x bytes) %s' % (typ, codes[typ], len(p), hexlify(p).decode()))

    if ts is not None:
        print('Timeslot table, starting at 0x%x:' % ts_off)
        disassm_timeslot_table(ts[ts_off:], ts_off)
