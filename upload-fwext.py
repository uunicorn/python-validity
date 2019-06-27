
from binascii import hexlify, unhexlify
from time import ctime

from tls97 import tls
from usb97 import usb
from sensor import reboot, write_hw_reg32, read_hw_reg32, identify_sensor
from flash import flush_changes, read_flash, erase_flash, write_flash_all, write_fw_signature, get_fw_info
from util import assert_status


with open('6_07f_lenovo_mis.xpfwext', 'rb') as f:
    fwext=f.read()

fwext=fwext[fwext.index(b'\x1a')+1:]
fwext, signature = fwext[:-0x100], fwext[-0x100:]

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

# get fwext header info
rsp=tls.cmd(unhexlify('4302')) #  should fail 'cause no fwext uploaded yet

fwi=get_fw_info(2)
if fwi != None:
    raise Exception('FW is already present (version %d.%d (%s))' % (fwi.major, fwi.minor, ctime(fwi.buildtime)))

#flush_changes()
write_flash_all(2, 0, fwext)
write_fw_signature(2, signature)

fwi=get_fw_info(2)
if fwi == None:
    raise Exception('No firmware detected')

print('Loaded FWExt version %d.%d (%s), %d modules' % (fwi.major, fwi.minor, ctime(fwi.buildtime), len(fwi.modules)))

# Reboot
reboot()
