#!/usr/bin/env python3

import re
from struct import unpack
from binascii import unhexlify, hexlify

def unhex(x):
    return unhexlify(re.sub('\W', '', x))

enroll_prg=unhex('''
02980000002300000020000800002000800000010032007000000000802020050024200000502077362820010030200100082170000c210
000482102004c210000582000005c20000060200000682005006c20012970200121742001887820018084202000942001809c200902a020
0b19b4200000b8203b04bc201400c0200200c4200100c82002003300100000000080cc200000f503d0200000a1013200440000000080dc2
0e803e0206401e420d002e8200001f0200500f8200500fc200000b8203b0000080400140800000808000008080000140830000808000014
0831001c081a0032000c0000000080501101004c1126003400080310071d10071d10071d10071d10071c01065810080101000007c8078c0
6100000204f80007f000003070107010c07032c08fc80095a800afc08fb800b5a095b800afb08fa800b5b095c800afa08f9800b5c095d80
0af908f8800b5d095e800af808f7800b5e095f800af708f6800b5f0960800af608f5800b600961800af508f4800b610962800af408f3800
b620963800af308f2800b630964800af208f1800b640965800af108f0800b650966800af008ef800b660967800aef08ee800b670968800a
ee08ed800b68096c800aed08ec800b6c096d800aec08eb800b6d096e800aeb08ea800b6e096f800aea08e9800b6f0970800ae908e8800b7
00971800ae808e7800b710972800ae708e6800b720973800ae608e5800b730974800ae508e4800b740975800ae408e3800b750976800ae3
08e2800b760977800ae208e1800b770978800ae108e0800b780979800ae008df800b79097a800adf08de800b7a097b800ade08dd800b7b0
97c800add08dc800b7c097d800adc08db800b7d097e800adb08da800b7e097f800ada08d9800b7f0980800ad908d8800b800981800ad808
d7800b810982800ad708d6800b820983800ad608d5800b830984800ad508d4800b840985800ad408d3800b850986800ad308d2800b86098
7800ad208d1800b870988800ad108d0800b880989800ad008cf800b89098a800acf08ce800b8a098b800ace08cd800b8b098c800acd08cc
800b8c098d800acc08cb800b8d098e800acb08ca800b8e098f800aca08c9800b8f0990800ac908c8800b900991800ac808c7800b9109928
00ac708c6800b920993800ac608c5800b930994800ac508c4800b940995800ac408c3800b950996800ac308c2800b960997800ac208c180
0b970998800ac108c0800b980999800ac008bf800b99099a800abf08be800b9a099b800abe08bd800b9b099c800abd08bc800b9c099d800
abc08bb800b9d099e800abb08ba800b9e099f800aba08b9800b9f09a0800ab908b8800ba00801800ab808b7800a010802800ab708b6800a
020803800ab608b5800a030804802003070404020000000000002f000400900000002900040000000000350004001000000017000000260
02800fbb20f00f2220f00300000006001020040010a00018000000a0200000b19000050c360ea010910002e001c00020018002300000090
0090004d01000090017c013c323232640a02013000cc0103000000ff0000001d000003ff00000025000003ff00000022000003101112131
415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b
4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f8081828
38485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f2b23203c2d182e1e30182e1c321d341d341e321c301e1e241e201f
201d1c321a301e1c211e21341f1e202024201f1e20201f212221221d221e23341e1d1e1d20341f1d193b341c1d1e35201e201c20221f341
c1e1e1c221f201d21201e1c1f34242221201f20221f201e241e241d2020221e2420231d221e211e1f1e1e341c321e3220301d2d302f2d2c
2b23223a211c7e7f807f8080808080808080808080808080808080808180818081808180808080808180818080808180818081808180818
08180818081808180808081808180808081807f808081808080818081808180808081808180818081808180818080808180818081808180
81808180818081808180818081808180818081808080808080808080807f807f807f807f7f7e7e
''')

short=unhex('''
029000010023000000320074000000008000200000502077322820020030200000082110000c211000482105004c21050020200000242
00000582000005c20000060204300682014006c2001247020012c842020008c20900190202c01942001809c200902a0200b19b4200000
b8203a00bc201400c0200200c4200200c82008003300100000000080cc200000a101d0200000a10132004c0000000080dc20e803e0206
401e420d002e8200001ec201400f0200500fc200000b8203a00140800000008040008080000080802001408300008080300140831001c
081a004c112400501100002a00080020010100100100002c002800802080200000000000013f4000000000080f080f00000000279c100
0279c10000000000000000000340040000300000007160000240a59085a0701c9500aaa07010ada08db0701c9460b2107010800800a00
88c9590a5a07010aa908aa0701c91f0ac900000c04010000000029000400000000003500040000000000150008000000000020280000
''')

codes={}
codes[0x0] =  "No Operation"
codes[0x1] =  "Swipe"
codes[0x2] =  "Timeslot Configuration"
codes[0x3] =  "Register"
codes[0x4] =  "Register Set 32"
codes[0x5] =  "Register Operation 32"
codes[0x6] =  "Security"
codes[0x7] =  "WOE"
codes[0x8] =  "Motion 1"
codes[0xa] =  "CPUCLK"
codes[0xb] =  "Motion 2"
codes[0xc] =  "Calibration Block"
codes[0xd] =  "Sweep"
codes[0xe] =  "Zone Configuration"
codes[0xf] =  "Zones Per Sweep"
codes[0x10] =  "Lines Per Sweep Iteration"
codes[0x11] =  "Lines Per Sweep"
codes[0x12] =  "Total Zones"
codes[0x13] =  "CAL WOE Ctrl"
codes[0x14] =  "Cal WOE Mask"
codes[0x15] =  "BW Reduciton"
codes[0x16] =  "AGC"
codes[0x17] =  "Reply Configuration"
codes[0x18] =  "Motion 3"
codes[0x19] =  "WOVAR"
codes[0x1a] =  "Block MOde"
codes[0x1b] =  "Bit Reduction"
codes[0x1c] =  "Motion 4"
codes[0x1d] =  "Calibration WOENF"
codes[0x1e] =  "Calibration"
codes[0x1f] =  "Zone Configuration A"
codes[0x20] =  "Set Register 32"
codes[0x21] =  "Register Operation 32A"
codes[0x22] =  "Fingerprint Buffering"
codes[0x23] =  "Reply Config + Timeslot Table"
codes[0x24] =  "Baseline"
codes[0x25] =  "SO Alternate"
codes[0x26] =  "Finger Detect"
codes[0x27] =  "Finger Detect Sample Register"
codes[0x28] =  "Finger Detect Scan Registers"
codes[0x29] =  "Timeslot Table Offset"
codes[0x2a] =  "ACM Config"
codes[0x2b] =  "ACM Control"
codes[0x2c] =  "CEM Config"
codes[0x2d] =  "CEM Control"
codes[0x2e] =  "Image Reconstruction"
codes[0x2f] =  "2D"
codes[0x30] =  "Line Update"
codes[0x31] =  "FDetect Timeslot Table"
codes[0x32] =  "Register List 16"
codes[0x33] =  "Register list 32"
codes[0x34] =  "Timeslot Table 2D"
codes[0x35] =  "Timeslot Table Offset for Finger Detect"
codes[0x36] =  "Security Aligned"
codes[0x37] =  "WOF2"
codes[0x38] =  "WOE WOF"
codes[0x39] =  "Navigation"
codes[0x3a] =  "WOE WOF2 Version2"
codes[0x3b] =  "Cal WOE WOF2"
codes[0x3c] =  "Event Signal"
codes[0x3d] =  "IFS Frame Stats"
codes[0x3e] =  "SNR Method 4"
codes[0x3f] =  "WOE WOF2 Version 3"
codes[0x40] =  "Calibrate WOE WOF2 Version 3"
codes[0x41] =  "Finger Detect Ratchet"
codes[0x42] =  "Data Encoder"
codes[0x43] =  "Line Update Transform"
codes[0x44] =  "Line Update InterLeave"
codes[0x45] =  "SO Table Values for Macros"
codes[0x46] =  "Timeslot Macro Definitions"
codes[0x47] =  "Enable ASP Feature"
codes[0x48] =  "Baseline Frame"
codes[0x49] =  "Rx Select"
codes[0xffff] =  "Unknown"

def decode_tt_inst(b):
    if b[0] == 0:
        return (0, 1, 'NOOP')
    elif b[0] == 1:
        return (1, 1, 'End of Table')
    elif b[0] == 2:
        return (2, 1, 'Return')
    elif b[0] == 3:
        return (3, 1, 'Clear SO')
    elif b[0] == 4:
        return (4, 1, 'End of Data')
    elif b[0] == 6:
        return (6, 2, 'Enable Rx 0x%02x' % b[1])
    elif b[0] == 7:
        return (7, 2, 'Idle Rx 0x%03x' % (0x100 if b[1] == 0 else b[1]))
    elif b[0] & 0xfe == 8:
        return (8, 2, 'Enable SO 0x%03x' % ((b[0] & 1) << 8 | b[1]) )
    elif b[0] & 0xfe == 0xa:
        return (9, 2, 'Disable SO 0x%03x' % ((b[0] & 1) << 8 | b[1]) )
    elif b[0] & 0xfc == 0xc:
        return (0xa, 1, 'Interrupt %x' % (b[0] & 3))
    elif b[0] & 0xf8 == 0x10:
        return (0xb, 3, 'Call rx_inc=%d, addr=%x, repeat=%d' % (b[0] & 7, b[1] << 2, 0x100 if b[2] == 0 else b[2]))
    elif b[0] & 0xe0 == 0x20:
        return (0xc, 1, 'Features %02x' % (b[0] & 0x1f)) # TODO check how features are converted to op args
    elif b[0] & 0xc0 == 0x40:
        reg=b[0] & 0x3f
        reg=reg*4 + 0x80002000
        val=b[1] | (b[2] << 8)
        return (0xd, 3, 'Register Write *0x%08x = 0x%04x' % (reg, val))
    elif b[0] & 0xc0 == 0x80:
        return (0xe, 1, 'Sample %x, %x' % ((b[0] & 0x38) >> 3, b[0] & 7 ))
    elif b[0] & 0xc0 == 0xc0:
        return (0xf, 2, 'Sample Repeat %x, %x, repeat=%x' % ( (b[0] & 0x38) >> 3, b[0] & 7, 0x100 if b[1] == 0 else b[1] ))
    elif b[0] == 5:
        return (5, 2, 'Marco %02x' % b[1])
    else:
        raise Exception('Unhandled instruction %02x' % b[0])



def decode_tt(b):
    pc=0
    while len(b) > 0:
        (op, sz, txt) = decode_tt_inst(b)
        if sz > len(b):
            raise Exception('Truncated instruction')
        print('%04x: %-6s %s' % (pc, hexlify(b[:sz]).decode(), txt))
        b = b[sz:]
        pc += sz


b=enroll_prg[5:]
#b=short[5:]
while len(b) > 0:
    (typ, sz), b = unpack('<HH', b[:4]), b[4:]
    p, b = b[:sz], b[sz:]
    if typ == 0x20:
        addr, val = unpack('<LL', p)
        print('Set Register 32:')
        print('   *0x%08x = 0x%08x' % (addr, val))
    elif typ == 0x32:
        print('Set Registers 16:')
        (base,), p = unpack('<L', p[:4]), p[4:]
        while len(p) > 0:
            (off, val), p = unpack('<HH', p[:4]), p[4:]
            print('   *0x%08x = 0x%04x' % (off + base, val))
    elif typ == 0x33:
        print('Set Registers 32:')
        (base,), p = unpack('<L', p[:4]), p[4:]
        while len(p) > 0:
            (off, val), p = unpack('<HL', p[:6]), p[6:]
            print('   *0x%08x = 0x%08x' % (off + base, val))
    elif typ == 0x34:
        print('Timeslot Table 2D:')
        decode_tt(p)
        #print('%04x (%20s): %s' % (typ, codes[typ], hexlify(p)))
    else:
        print('%04x (%20s): (0x%x bytes) %s' % (typ, codes[typ], len(p), hexlify(p).decode()))

