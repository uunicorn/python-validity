
from proto9x.tls import tls
from proto9x.usb import usb
from proto9x.db import db
from proto9x.flash import read_flash
from proto9x.sensor import *
from proto9x.sid import *

def open_common():
    usb.send_init()

    # try to init TLS session from the flash
    tls.parseTlsFlash(read_flash(1, 0, 0x1000))

    tls.open()
    tls.save()
    sensor.open()
    #usb.trace_enabled = True
    #tls.trace_enabled = True

def open97():
    usb.open(vendor=0x138a, product=0x0097)
    open_common()

def open9a():
    usb.open(vendor=0x06cb, product=0x009a)
    open_common()

def load97():
    #usb.trace_enabled = True
    #tls.trace_enabled = True
    usb.open()
    tls.load()
    sensor.open()



