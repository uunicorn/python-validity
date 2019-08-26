
from proto97.tls import tls
from proto97.usb import usb
from proto97.db import db
from proto97.flash import read_flash
from proto97.sensor import *
from proto97.sid import *

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



