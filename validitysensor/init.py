import atexit
import logging

from validitysensor.init_data_dir import init_data_dir
from validitysensor.flash import read_tls_flash
from validitysensor.init_db import init_db
from validitysensor.init_flash import init_flash
from validitysensor.sensor import sensor, reboot, RebootException
from validitysensor.tls import tls
from validitysensor.upload_fwext import upload_fwext
from validitysensor.usb import usb


def close():
    logging.debug('In atexit handler')
    if usb.dev is not None:
        # Send the reboot command before closing the device.
        # Without it the sensor seems to keep creating new TLS sessions and eventually runs out of memory.
        # The reboot command may fail if we're shutting down because the device is already gone.
        try:
            logging.debug('atexit: forcing reboot')
            reboot()
        except RebootException:
            pass
        finally:
            usb.close()


def open_common():
    init_data_dir()
    init_flash()
    usb.send_init()
    tls.parse_tls_flash(read_tls_flash())
    tls.open()
    upload_fwext()
    sensor.open()
    init_db()

    # We must register atexit only after we opened usb device,
    # so that our atexit handler is called before pyusb's one and we can still talk to the device
    #
    # Don't attempt to autoreboot unless we finished initializing the sensor successfully.
    # Otherwise if there is a bug in initialization, we may end up in a loop constantly rebooting the device.
    atexit.register(close)
    logging.debug('atexit registered')


def open():
    usb.open()
    open_common()


def open_devpath(busnum: int, address: int):
    usb.open_devpath(busnum, address)
    open_common()
