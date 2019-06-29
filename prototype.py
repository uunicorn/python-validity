
from util import assert_status
from time import sleep
from struct import pack, unpack
from binascii import hexlify, unhexlify
from tls97 import tls
from usb97 import usb, unhex
from sensor import enroll, identify
from db97 import db
from flash import read_flash
from sid import *

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



