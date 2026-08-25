import errno
import logging
import time
import typing
from binascii import hexlify, unhexlify
from enum import Enum
from struct import unpack
from threading import Event

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
    DEV_AB = (0x138a, 0x00ab)  # HP EliteBook 840 G5 — sensor type 0xd51
    DEV_B7 = (0x06cb, 0x00b7)  # HP G6 series — sensor type 0xd51
    DEV_CB = (0x06cb, 0x00cb)  # HP Pavilion x360 14-dh -- sensor type 0x969

    @classmethod
    def from_usbid(cls, vendorid, productid):
        return supported_devices[(vendorid, productid)]


supported_devices = dict((dev.value, dev) for dev in SupportedDevices)


def requires_startup_usb_reset(dev):
    """Limit the recovery reset to hardware that has demonstrated the wedge."""
    return (dev.idVendor, dev.idProduct) in {
        SupportedDevices.DEV_AB.value,
        SupportedDevices.DEV_B7.value,
    }


class CancelledException(Exception):
    pass


class Usb:
    def __init__(self):
        self.trace_enabled = False
        self.dev: typing.Optional[ucore.Device] = None
        self.cancel_event = Event()

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

        # Defensive USB reset on init.
        #
        # The 0xd51-family chips (HP 138a:00ab / 06cb:00b7) can be left in
        # a "stuck" protocol state across a previous unclean exit of this
        # daemon, a cold boot, or a sudden suspend/resume. In that state
        # the chip accepts the bulk-OUT but never replies on bulk-IN, so
        # the very first cleartext command (typically `cmd 3e`
        # get_flash_info) times out — the daemon then restart-loops at
        # 15s intervals and the sensor is "vanished" until a manual USB
        # reset. This block is the in-driver equivalent of the manual
        # `udevadm trigger --attr-match=idVendor=... --attr-match=idProduct=...`
        # workaround users have been running to recover.
        #
        # Reported by Killersparrow1 (#238, Fedora 44, vanishes on reboot)
        # and Maarten (Arch, ZBook G5, USBTimeoutError on first 3e). Also
        # observed locally on the maintainer's machine (sensor prompts but
        # doesn't detect after a while).
        if requires_startup_usb_reset(dev):
            try:
                vid, pid = dev.idVendor, dev.idProduct
                dev.reset()
                time.sleep(0.5)
                # USB address may shift after reset; re-find by vid/pid.
                dev = ucore.find(idVendor=vid, idProduct=pid)
                if dev is None:
                    raise Exception('Device disappeared after USB reset')
            except USBError as e:
                logging.warning(
                    'open_dev: USB reset failed (often non-fatal): %s', e)

        self.dev = dev
        self.dev.default_timeout = 15000
        dev.set_configuration()

    def close(self):
        if self.dev is not None:
            try:
                self.dev.reset()
                self.dev = None
            except:
                pass

    def usb_dev(self):
        return self.dev

    def send_init(self):
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

    def request_cancel(self):
        """Cancel the current operation without losing an early request."""
        self.cancel_event.set()

    def clear_cancel(self):
        """Arm the USB transport for a new, exclusively-owned operation."""
        self.cancel_event.clear()

    def wait_int(self):
        while True:
            if self.cancel_event.is_set():
                raise CancelledException()
            try:
                resp = self.dev.read(131, 1024, timeout=100)
                resp = bytes(resp)
                self.trace('<int< %s' % hexlify(resp).decode())
                return resp
            except USBError as e:
                if e.errno == errno.ETIMEDOUT:
                    if self.cancel_event.is_set():
                        raise CancelledException()
                else:
                    raise e

    def trace(self, s: str):
        if self.trace_enabled:
            logging.debug(s)


usb = Usb()
