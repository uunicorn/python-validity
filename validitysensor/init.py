import atexit
import logging
import time
import typing

from validitysensor.init_data_dir import init_data_dir
from validitysensor.flash import read_tls_flash
from validitysensor.init_db import init_db
from validitysensor.init_flash import init_flash
from validitysensor.sensor import sensor, reboot, RebootException
from validitysensor.tls import tls
from validitysensor.upload_fwext import upload_fwext
from validitysensor.usb import usb

# Bounded initialization recovery: the sensor can be left unresponsive after a
# reboot or resume. Reset/re-open the USB device a few times before giving up,
# so a stuck sensor recovers instead of crash-looping.
INIT_ATTEMPTS = 5
INIT_RETRY_DELAY = 1.0

_close_registered = False


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
        except Exception as e:
            # The device can already be gone/reset during shutdown or suspend;
            # this is expected and must not print a traceback from atexit.
            logging.debug('atexit: reboot failed: %s', e)
        finally:
            usb.close()


def open_common():
    init_data_dir()
    # Load the hardcoded init/firmware blobs before touching the protected
    # flash. On 06cb:009a the flash commands time out when send_init() runs
    # after init_flash() (see uunicorn/python-validity#272).
    usb.send_init()
    init_flash()
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
    global _close_registered
    if not _close_registered:
        atexit.register(close)
        _close_registered = True
    logging.debug('atexit registered')


def _open_with_recovery(opener: typing.Callable[[], None]):
    """Open the device and initialize the sensor, with bounded recovery.

    On failure the USB device is reset and re-opened before the next attempt.
    This breaks the infinite restart loop seen when the sensor stops answering
    commands (USBTimeoutError) and was never reset because a failed init never
    reached the atexit handler that performs usb.close().
    """
    last_exc: typing.Optional[Exception] = None
    for attempt in range(1, INIT_ATTEMPTS + 1):
        try:
            opener()
            open_common()
            return
        except RebootException:
            # Normal exit: the sensor reboots and udev starts the service again.
            raise
        except Exception as e:
            last_exc = e
            logging.warning('Sensor initialization attempt %d/%d failed: %s: %s', attempt,
                            INIT_ATTEMPTS, type(e).__name__, e)
            if attempt == INIT_ATTEMPTS:
                break
            try:
                usb.reopen()
            except Exception as reopen_exc:
                logging.debug('Could not reopen USB device: %s', reopen_exc)
            time.sleep(INIT_RETRY_DELAY)

    raise last_exc


def open():
    _open_with_recovery(usb.open)


def open_devpath(busnum: int, address: int):
    _open_with_recovery(lambda: usb.open_devpath(busnum, address))


def _reacquire_usb():
    try:
        usb.reopen()
    except Exception:
        # Fall back to plain discovery if the original open method is unknown
        # or the device re-enumerated in a way reopen() cannot handle.
        usb.open()


def resume():
    """Re-initialize the sensor after suspend/resume.

    The USB device may have been reset or re-enumerated while suspended, so the
    previous handle cannot be reused (that produced 'USBError: [Errno 19] No
    such device'). Re-acquire the device and rebuild all sensor state, with the
    same bounded recovery as a normal start.
    """
    tls.reset()
    _open_with_recovery(_reacquire_usb)
