import errno
import logging
import time
import typing
from binascii import hexlify, unhexlify
from enum import Enum
from struct import unpack

import usb.core as ucore
import usb.util as uutil
from usb.core import USBError

from .blobs import init_hardcoded, init_hardcoded_clean_slate
from .util import assert_status


class SupportedDevices(Enum):
    """USB IDs for supported devices"""
    DEV_90 = (0x138a, 0x0090)
    DEV_97 = (0x138a, 0x0097)
    DEV_9d = (0x138a, 0x009d)
    DEV_9a = (0x06cb, 0x009a)
    DEV_a8 = (0x06cb, 0x00a8)

    @classmethod
    def from_usbid(cls, vendorid, productid):
        return supported_devices[(vendorid, productid)]


supported_devices = dict((dev.value, dev) for dev in SupportedDevices)

# Sensors without an external SPI flash: nothing survives a power cycle on the device,
# so pairing and calibration are kept on the host and templates are matched on the host.
FLASHLESS_DEVICES = {SupportedDevices.DEV_a8}


class CancelledException(Exception):
    pass


class Usb:
    def __init__(self):
        self.trace_enabled = False
        self.dev: typing.Optional[ucore.Device] = None
        self.cancel = False

    def open(self, vendor=None, product=None):
        if vendor is not None and product is not None:
            dev = ucore.find(idVendor=vendor, idProduct=product)
        else:

            def match(d):
                return (d.idVendor, d.idProduct) in supported_devices

            dev = ucore.find(custom_match=match)

        self.open_dev(dev)

    def open_devpath(self, busnum: int, address: int):
        def match(d):
            return d.bus == busnum and d.address == address

        dev = ucore.find(custom_match=match)

        self.open_dev(dev)

    def open_dev(self, dev: ucore.Device):
        if dev is None:
            raise Exception('No matching devices found')

        self.dev = dev
        self.dev.default_timeout = 15000
        if self.flashless:
            # set_configuration() wedges 06cb:00a8 (reads on 0x81 time out afterwards).
            # The configuration is already active after enumeration, so just claim it.
            try:
                if dev.is_kernel_driver_active(0):
                    dev.detach_kernel_driver(0)
            except (NotImplementedError, USBError):
                pass
            uutil.claim_interface(dev, 0)
        else:
            dev.set_configuration()

    def close(self):
        if self.dev is not None:
            if self.flashless:
                # No reset: init.close() has already ended the session with a reboot
                # command, and the Windows driver never resets this device either.
                try:
                    uutil.release_interface(self.dev, 0)
                except USBError:
                    pass
                self.dev = None
                return
            try:
                self.dev.reset()
                self.dev = None
            except:
                pass

    def usb_dev(self):
        return self.dev

    def usb_id(self):
        """(idVendor, idProduct) of the open device"""
        if self.dev is None:
            raise Exception('No device open')
        return self.dev.idVendor, self.dev.idProduct

    @property
    def flashless(self):
        return self.dev is not None and supported_devices.get(self.usb_id()) in FLASHLESS_DEVICES

    def bus_reset(self):
        """USBDEVFS_RESET. Brings a wedged flashless sensor back to its plaintext state."""
        if self.dev is not None:
            try:
                self.dev.reset()
            except USBError as e:
                logging.warning('USB reset failed: %s' % e)

    def address(self):
        return (self.dev.bus, self.dev.address) if self.dev is not None else None

    def wait_for_reboot(self, old_address, timeout=5.0):
        """Wait for the device to re-enumerate at a new address after a reboot command.

        The old address can stay listed for a moment, so a device found there doesn't count."""
        vid_pid = [d.value for d in FLASHLESS_DEVICES]
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            dev = ucore.find(custom_match=lambda d: (d.idVendor, d.idProduct) in vid_pid)
            if dev is not None and (dev.bus, dev.address) != old_address:
                return True
            time.sleep(0.05)
        return False

    def send_init(self):
        if self.flashless:
            # No fwext partition to ask about and no init_hardcoded blob for this ROM:
            # the Windows driver sends only these two before pairing or the TLS handshake.
            assert_status(self.cmd(unhexlify('01')))  # RomInfo.get()
            assert_status(self.cmd(unhexlify('19')))
            return

        # self.dev.set_configuration()

        # TODO analyse responses, detect hardware type
        assert_status(self.cmd(unhexlify('01')))  # RomInfo.get()
        assert_status(self.cmd(unhexlify('19')))

        # 43 -- get partition header(?) (02 -- fwext partition)
        # c28c745a in response is a FwextBuildtime = 0x5A748CC2
        rsp = self.cmd(unhexlify('4302'))  # get_fw_info()

        assert_status(self.cmd(init_hardcoded))

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
