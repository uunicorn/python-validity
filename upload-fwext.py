
from db97 import *
from tls97 import *
from usb97 import *
from prototype import *
from util import assert_status

with open('6_07f_lenovo_mis.xpfwext', 'rb') as f:
    fwext=f.read()

fwext=fwext[fwext.index(b'\x1a')+1:]
fwext, signature = fwext[:-0x100], fwext[-0x100:]

usb.trace_enabled=True
tls.trace_enabled=True
open97()

write_hw_reg32(0x8000205c, 7)
print('*0x80002080=%08x' % read_hw_reg32(0x80002080))

tls.cmd(unhexlify('75'))

# get fwext header info
rsp=tls.cmd(unhexlify('4302'))
# ^ should fail 'cause no fwext uploaded yet

if rsp[:2] == b'\0' * 2:
    raise Exception('FW is already present')

db.flush_changes()

ptr=0
while len(fwext) > 0:
    chunk, fwext = fwext[:0x1000], fwext[0x1000:]
    db.write_flash(2, ptr, chunk)
    ptr += len(chunk)

rsp=tls.cmd(pack('<BBxH', 0x42, 2, len(signature)) + signature)
assert_status(rsp)

rsp=tls.cmd(unhexlify('4302'))
assert_status(rsp)

# Reboot
tls.cmd(unhexlify('050200'))
