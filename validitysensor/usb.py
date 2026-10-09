import errno
import logging
import time
import typing
from binascii import hexlify, unhexlify
from enum import Enum
from struct import unpack

import usb.core as ucore
from usb.core import USBError

from .blobs import init_hardcoded, init_hardcoded_clean_slate
from .util import assert_status


class SupportedDevices(Enum):
    """USB IDs for supported devices"""
    DEV_90 = (0x138a, 0x0090)
    DEV_97 = (0x138a, 0x0097)
    DEV_9d = (0x138a, 0x009d)
    DEV_9a = (0x06cb, 0x009a)

    @classmethod
    def from_usbid(cls, vendorid, productid):
        return supported_devices[(vendorid, productid)]


supported_devices = dict((dev.value, dev) for dev in SupportedDevices)

# Status words the sensor may return while it is still settling after a
# wake-up or a reset. They are transient, so the command should be retried
# instead of being treated as a hard failure by assert_status().
BUSY_STATUSES = (0x0104, 0x0401)

# Retry budget for a single command: 20 * 0.5s = 10s on top of the 15s USB
# timeout. Bounded so a genuinely stuck sensor still fails fast enough for the
# init recovery loop to reset it.
CMD_RETRY_ATTEMPTS = 20
CMD_RETRY_DELAY = 0.5


class CancelledException(Exception):
    pass


class Usb:
    def __init__(self):
        self.trace_enabled = False
        self.dev: typing.Optional[ucore.Device] = None
        self.cancel = False
        # Callable that re-opens the device the way it was opened originally.
        self._reopen_fn: typing.Optional[typing.Callable[[], None]] = None

    def open(self, vendor=None, product=None):
        if vendor is not None and product is not None:
            dev = ucore.find(idVendor=vendor, idProduct=product)
        else:

            def match(d):
                return (d.idVendor, d.idProduct) in supported_devices

            dev = ucore.find(custom_match=match)

        self.open_dev(dev)
        self._reopen_fn = lambda: self.open(vendor, product)

    def open_devpath(self, busnum: int, address: int):
        def match(d):
            return d.bus == busnum and d.address == address

        dev = ucore.find(custom_match=match)

        self.open_dev(dev)
        self._reopen_fn = lambda: self.open_devpath(busnum, address)

    def open_dev(self, dev: ucore.Device):
        if dev is None:
            raise USBError('No matching devices found')

        self.dev = dev
        self.dev.default_timeout = 15000
        dev.set_configuration()

    def reset(self):
        """Reset the USB device without sending the sensor reboot command."""
        if self.dev is not None:
            try:
                self.dev.reset()
            except Exception:
                pass

    def reopen(self):
        """Reset and re-open the device the way it was originally opened.

        Used to recover a sensor that stopped responding to commands. The
        device may re-enumerate at a different USB address, so discovery is
        repeated instead of reusing the stale handle.
        """
        self.reset()
        self.dev = None
        if self._reopen_fn is None:
            raise Exception('USB device was never opened; cannot reopen')
        self._reopen_fn()

    def close(self):
        if self.dev is not None:
            try:
                self.dev.reset()
                self.dev = None
            except:
                pass

    def usb_dev(self):
        return self.dev

    def cmd_retry_busy(self, out: typing.Union[bytes, typing.Callable[[], bytes]]):
        """Run a command, retrying while the sensor reports a transient busy
        status (or times out). Returns the last response.
        """
        if callable(out):
            out = out()
            if not out:
                return 0

        rsp: typing.Union[bytes, int] = 0
        for attempt in range(CMD_RETRY_ATTEMPTS):
            last_attempt = attempt + 1 == CMD_RETRY_ATTEMPTS
            try:
                rsp = self.cmd(out)
            except USBError as e:
                if e.errno == errno.ETIMEDOUT and not last_attempt:
                    time.sleep(CMD_RETRY_DELAY)
                    continue
                raise

            if not isinstance(rsp, (bytes, bytearray)) or len(rsp) < 2:
                return rsp

            status, = unpack('<H', rsp[:2])
            if status in BUSY_STATUSES and not last_attempt:
                time.sleep(CMD_RETRY_DELAY)
                continue

            return rsp

        return rsp

    def send_init(self):
        # self.dev.set_configuration()

        # TODO analyse responses, detect hardware type
        # The first command after wake-up/reset can return a transient busy
        # status (0x0104/0x0401); retry it before asserting.
        assert_status(self.cmd_retry_busy(unhexlify('01')))  # RomInfo.get()
        assert_status(self.cmd(unhexlify('19')))

        # 43 -- get partition header(?) (02 -- fwext partition)
        # c28c745a in response is a FwextBuildtime = 0x5A748CC2
        rsp = self.cmd_retry_busy(unhexlify('4302'))  # get_fw_info()

        # init_hardcoded returns a non-zero status when no firmware is loaded
        # yet; that is a normal state which the check below handles, so do not
        # assert on it.
        self.cmd_retry_busy(init_hardcoded)

        (err, ), rsp = unpack('<H', rsp[:2]), rsp[2:]
        if err != 0:
            # fwext is not loaded
            logging.info('Clean slate')
            self.cmd(init_hardcoded_clean_slate)

    def cmd(self, out: typing.Union[bytes, typing.Callable[[], bytes]]):
        if callable(out):
            out = out()
            if not out:
                return 0
        self.trace('>cmd> %s' % hexlify(out).decode())
        self.dev.write(1, out)
        resp = self.dev.read(129, 100 * 1024)
        resp = bytes(resp)
        self.trace('<cmd< %s' % hexlify(resp).decode())
        return resp

    def read_82(self):
        try:
            resp = self.dev.read(130, 1024 * 1024, timeout=10000)
            resp = bytes(resp)
            self.trace('<130< %d bytes' % len(resp))
            #self.trace('<130< %s' % hexlify(resp).decode())
            return resp
        except Exception as e:
            self.trace('<130< Error: %s' % repr(e))
            return None

    # FIXME There is a chance of a race condition here
    def cancel(self):
        self.cancel = True

    def wait_int(self):
        self.cancel = False

        while True:
            try:
                resp = self.dev.read(131, 1024, timeout=100)
                resp = bytes(resp)
                self.trace('<int< %s' % hexlify(resp).decode())
                return resp
            except USBError as e:
                if e.errno == errno.ETIMEDOUT:
                    if self.cancel:
                        raise CancelledException()
                else:
                    raise e

    def trace(self, s: str):
        if self.trace_enabled:
            logging.debug(s)


usb = Usb()
