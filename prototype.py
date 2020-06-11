
from proto9x.tls import tls
from proto9x.usb import usb
from proto9x.db import db
from proto9x.flash import read_flash
from proto9x.sensor import *
from proto9x.sid import *

def open97():
    usb.open()
    usb.send_init()

    # try to init TLS session from the flash
    tls.parseTlsFlash(read_flash(1, 0, 0x1000))

    tls.open()
    tls.save()
    #usb.trace_enabled = True
    #tls.trace_enabled = True

def load97():
    #usb.trace_enabled = True
    #tls.trace_enabled = True
    usb.open()
    tls.load()



