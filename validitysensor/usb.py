import errno
import logging
from binascii import hexlify, unhexlify
from struct import unpack
import typing

import usb.core as ucore
from usb.core import USBError

from .blobs import init_hardcoded, init_hardcoded_clean_slate
from .util import assert_status

supported_devices = [
    (0x138a, 0x0090),
    (0x138a, 0x0097),
    (0x06cb, 0x009a),
]


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
            self.trace('<130< %s' % hexlify(resp).decode())
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
