
import atexit

from validitysensor.usb import usb
from validitysensor.tls import tls
from validitysensor.sensor import sensor
from validitysensor.sensor import reboot
from validitysensor.flash import read_tls_flash

def close():
    if usb.dev is not None:
        # Send the reboot command before closing the device.
        # Without it the sensor seems to keep creating new TLS sessions and eventually runs out of memory.
        # The reboot command may fail if we're shutting down because the device is already gone.
        try:
            reboot()
        finally:
            usb.close()

def open_common():
    usb.send_init()
    # We must register atexit only after we opened usb device, 
    # so that our handler is called before pyusb's one and we can still talk to the device
    atexit.register(close)

    tls.parseTlsFlash(read_tls_flash())
    tls.open()

    sensor.open()

def open():
    usb.open()
    open_common()

def open_devpath(busnum, address):
    usb.open_devpath(busnum, address)
    open_common()
