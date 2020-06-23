
from hashlib import sha256
from binascii import hexlify, unhexlify
from os.path import isfile
from threading import Thread
from struct import unpack, pack

from .tls import tls
from .usb import usb
from time import ctime
from .sensor import write_hw_reg32, read_hw_reg32, identify_sensor
from .flash import erase_flash, read_flash, get_fw_info, write_flash_all
from .util import assert_status
from .blobs import calibrate_prg

class Line():
    def __init__(self, blob):
        # what's with the rest of fields?
        self.u0, self.u1, self.line, self.frame, self.u2, self.u3, self.u4, self.u5 = unpack('<BBBBBBBB', blob[:8])
        self.data = blob[8:]

    def serialize(self):
        return pack('<BBBBBBBB', self.u0, self.u1, self.line, self.frame, self.u2, self.u3, self.u4, self.u5) + self.data

    def __repr__(self):
        return 'Line(line=%d, frame=%d)' % (self.line, self.frame)

def persist_calib_data(calib_data):
    start=read_flash(6, 0, 0x44)
    if start != b'\xff' * 0x44:
        if calib_data[:0x44] == start:
            print('Calibration data already matches the data on the flash.')
            return
        else:
            print('Calibration flash already written. Erasing.')
            erase_flash(6)

    write_flash_all(6, 0, calib_data)

def calibrate(calib_data_path='calib-data.bin'):
    # no idea what this is:
    write_hw_reg32(0x8000205c, 7)
    if read_hw_reg32(0x80002080) not in [2, 3]:
        raise Exception('Unexpected register value')

    dev=identify_sensor()
    print('Sensor: %s' % dev.name)
    # ^ TODO -- what is the real reason to detect HW at this stage? -- likely it is required to construct calibrate_prg

    fwi=get_fw_info(2)
    if fwi == None:
        raise Exception('No firmware detected')

    print('FWExt version %d.%d (%s), %d modules' % (fwi.major, fwi.minor, ctime(fwi.buildtime), len(fwi.modules)))

    if isfile(calib_data_path):
        with open(calib_data_path, 'rb') as f:
            calib_data=f.read()
            print('Calibration data loaded from the file.')
    else:
        # TODO Properly construct calibrate_prg.
        # >>> 6f 000e 000000000000
        # <<< 0000 880d 0000 07000000 
        #      0800 0000 9400 0e00 0300 0080 07000000 7e7f807f808080808080808080808080808080808080818081808180818080808080818081808080818081808180818081808180818081808180808081808180808081807f80808180808081808180818080808180818081808180818081808080818081808180818081808180818081808180818081808180818081808080808080808080807f807f807f807f7f7e7e
        #      a400 0000 0800 0e00 0200 0000 00000000 0d007100
        #      b400 0000 0800 0e00 0800 0080 db000000 00000000
        #      c400 0000 0400 0e00 0500 0080 1c6f0400
        #      d000 0000 9400 0e00 0700 0080 07000000 2b23203c2d182e1e30182e1c321d341d341e321c301e1e241e201f201d1c321a301e1c211e21341f1e202024201f1e20201f212221221d221e23341e1d1e1d20341f1d193b341c1d1e35201e201c20221f341c1e1e1c221f201d21201e1c1f34242221201f20221f201e241e241d2020221e2420231d221e211e1f1e1e341c321e3220301d2d302f2d2c2b23223a211c
        #      6c01 0000 1400 0e00 0f00 0080 05550007 7701002805720000080100020811e107
        #      8801 0000 0c00 0e00 1200 0080 07000000 7002 7800 7002 7800
        #
        # Empty reply:
        # >>> 6f 000a 000000000000
        # <<< 0000 880d 0000 00000000

        rsp=tls.cmd(calibrate_prg)
        assert_status(rsp)
        # ^ TODO check what the rest of the rsp means

        calib_data=usb.read_82()
        print('len=%d' % len(calib_data))
        with open(calib_data_path, 'wb') as f:
            f.write(calib_data)

    lines=[calib_data[i:i+0x70+8] for i in range(0, len(calib_data), 0x70+8)] # TODO work out where "bytes per line" constant is comming from
    lines=[Line(i) for i in lines]
    frame4=[i.serialize() for i in lines if i.frame == 4] # why 4?
    frame4=b''.join(frame4)
    calib_data=pack('<H', len(frame4)) + frame4 + pack('<H', 0) # what's that 00000 in the end?
    calib_data=pack('<H', len(calib_data)) + sha256(calib_data).digest() + b'\0'*0x20 + calib_data
    calib_data=unhexlify('0250') + calib_data

    persist_calib_data(calib_data)
    # no need to reboot

