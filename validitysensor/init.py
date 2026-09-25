import atexit
import logging
from pathlib import Path

from validitysensor.init_data_dir import init_data_dir
from validitysensor.flash import read_tls_flash
from validitysensor.init_db import init_db
from validitysensor.init_flash import init_flash
from validitysensor.init_flashless import CommandFailed, pair, resume_pairing
from validitysensor.sensor import sensor, reboot, RebootException
from validitysensor.sensor_2449 import Sensor2449
from validitysensor.tls import tls
from validitysensor.upload_fwext import upload_fwext
from validitysensor.usb import usb


def close():
    logging.debug('In atexit handler')
    if usb.dev is not None and usb.flashless:
        close_flashless()
    elif usb.dev is not None:
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


def _refresh_hwkey():
    # The pairing keys are derived from the DMI product serial, which only root can read.
    # Tls() quietly falls back to made-up values; a flashless pairing must not.
    try:
        product_name = Path('/sys/class/dmi/id/product_name').read_text().strip()
        product_serial = Path('/sys/class/dmi/id/product_serial').read_text().strip()
    except OSError as e:
        raise PermissionError('Pairing needs the DMI product serial, run as root (%s)' % e)
    tls.set_hwkey(product_name=product_name, serial_number=product_serial)


def _reset_flashless():
    """USB reset, back to the plaintext state, and reopen."""
    vendor, product = usb.usb_id()
    tls.reset()
    usb.bus_reset()
    usb.close()
    usb.open(vendor, product)
    usb.send_init()


def open_flashless(recalibrate: bool = False) -> Sensor2449:
    """Start a session with a flashless sensor: resume the stored pairing (or pair) and
    open the sensor. End it with close().

    The session is ended with the reboot command, after which the device re-enumerates,
    so open one session per operation rather than keeping it for the life of the process.
    """
    _refresh_hwkey()
    try:
        usb.send_init()
    except Exception as e:
        # A session that ended without the reboot command (a killed process) leaves the
        # device in TLS mode, and the plaintext 0x01 fails with 0x0315.
        logging.warning('send_init failed (%s), resetting the device' % e)
        _reset_flashless()

    try:
        resumed = resume_pairing()
    except Exception as e:
        logging.warning('Stored pairing rejected (%s), pairing again' % e)
        _reset_flashless()
        resumed = False

    if not resumed:
        try:
            pair()
        except CommandFailed as e:
            logging.warning('Pairing failed (%s), resetting the device and retrying' % e)
            _reset_flashless()
            pair()

    s = Sensor2449()
    s.open(recalibrate=recalibrate)
    atexit.register(close)
    return s


def close_flashless():
    """End the session as the Windows driver does: 05 02 00, after which the device reboots
    and re-enumerates, back in plaintext mode but still paired."""
    atexit.unregister(close)
    rebooting = False
    try:
        if tls.secure_tx and tls.secure_rx:
            rsp = tls.app(b'\x05\x02\x00')
            rebooting = rsp[:2] == b'\0\0'
    except Exception as e:
        # The device may already be gone
        logging.warning('End of session failed: %s' % e)
    finally:
        tls.reset()
        old = usb.address()
        usb.close()
    if rebooting and not usb.wait_for_reboot(old):
        logging.warning('The device did not re-enumerate after the end of session')


def open():
    usb.open()
    if usb.flashless:
        return open_flashless()
    open_common()


def open_devpath(busnum: int, address: int):
    usb.open_devpath(busnum, address)
    if usb.flashless:
        return open_flashless()
    open_common()
