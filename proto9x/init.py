
from proto9x.usb import usb
from proto9x.tls import tls
from proto9x.sensor import sensor
from proto9x.flash import read_tls_flash
from usb import core as usb_core


def open():
    usb.open()
    usb.send_init()

    tls.parseTlsFlash(read_tls_flash())
    tls.open()

    sensor.open()
