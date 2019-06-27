
from usb97 import usb
from util import unhex, assert_status
from blobs import reset_blob
from sensor import reboot

#usb.trace_enabled=True
usb.open()
assert_status(usb.cmd(reset_blob))
assert_status(usb.cmd(b'\x10' + b'\0'*0x61))
reboot()
