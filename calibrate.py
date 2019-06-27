
from hashlib import sha256
from binascii import hexlify, unhexlify

from tls97 import tls
from usb97 import usb
from time import ctime
from sensor import write_hw_reg32, read_hw_reg32, identify_sensor
from flash import read_flash, get_fw_info
from util import assert_status
from blobs import calibrate_prg

#usb.trace_enabled=True
#tls.trace_enabled=True

usb.open()
tls.parseTlsFlash(read_flash(1, 0, 0x1000))
tls.open()

# no idea what this is:
write_hw_reg32(0x8000205c, 7)
if read_hw_reg32(0x80002080) != 2:
    raise Exception('Unexpected register value')

dev=identify_sensor()
print('Sensor: %s' % dev.name)
# ^ TODO -- what is the real reason to detect HW at this stage?

fwi=get_fw_info(2)
if fwi == None:
    raise Exception('No firmware detected')

print('FWExt version %d.%d (%s), %d modules' % (fwi.major, fwi.minor, ctime(fwi.buildtime), len(fwi.modules)))



# >>> 6f 000e 000000000000
# <<< 0000 880d 0000 07000000 
#      0800 0000 9400 0e00 0300 0080 07000000 7e7f807f808080808080808080808080808080808080818081808180818080808080818081808080818081808180818081808180818081808180808081808180808081807f80808180808081808180818080808180818081808180818081808080818081808180818081808180818081808180818081808180818081808080808080808080807f807f807f807f7f7e7e
#      a400 0000 0800 0e00 0200 0000 00000000 0d007100
#      b400 0000 0800 0e00 0800 0080 db000000 00000000
#      c400 0000 0400 0e00 0500 0080 1c6f0400
#      d000 0000 9400 0e00 0700 0080 07000000 2b23203c2d182e1e30182e1c321d341d341e321c301e1e241e201f201d1c321a301e1c211e21341f1e202024201f1e20201f212221221d221e23341e1d1e1d20341f1d193b341c1d1e35201e201c20221f341c1e1e1c221f201d21201e1c1f34242221201f20221f201e241e241d2020221e2420231d221e211e1f1e1e341c321e3220301d2d302f2d2c2b23223a211c
#      6c01 0000 1400 0e00 0f00 0080 05550007 7701002805720000080100020811e107
#      8801 0000 0c00 0e00 1200 0080 07000000 7002780070027800
#
# Empty reply:
# >>> 6f 000a 000000000000
# <<< 0000 880d 0000 00000000

rsp=tls.cmd(calibrate_prg)
assert_status(rsp)
print(rsp.hex())
# ^ check what the rest of the rsp means, how the calibrate_prg is constructed/selected, etc

buf=usb.read_82()

print(sha256(buf).digest().hex())

# >>> read_flash(6, 0, 0x44)
# <<< ffff...

# >>> write_flash_all(6, 0, buf)

