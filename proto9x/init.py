
import atexit

from proto9x.usb import usb
from proto9x.tls import tls
from proto9x.sensor import sensor
from proto9x.sensor import reboot
from proto9x.flash import read_tls_flash

def close():
    if usb.dev is not None:
        # Send the reboot command before closing the device.
        # Without it the sensor seems to keep creating new TLS sessions and eventually runs out of memory.
        # The reboot command may fail if we're shutting down because the device is already gone.
        try:
            reboot()
        finally:
            usb.close()

def open():
    usb.open()
    usb.send_init()
    # We must register atexit only after we opened usb device, 
    # so that our handler is called before pyusb's one and we can still talk to the device
    atexit.register(close)

    tls.parseTlsFlash(read_tls_flash())
    tls.open()

    sensor.open()



