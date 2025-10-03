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


class CancelledException(Exception):
    pass


class DeviceBusyException(Exception):
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
        
        max_retries = 5
        base_delay = 0.1  # 100ms base delay
        
        for attempt in range(max_retries):
            try:
                self.trace('>cmd> %s (attempt %d/%d)', hexlify(out).decode(), attempt + 1, max_retries)
                self.dev.write(1, out)
                resp = self.dev.read(129, 100 * 1024)
                resp = bytes(resp)
                self.trace('<cmd< %s', hexlify(resp).decode())
                return resp
            except USBError as e:
                if attempt < max_retries - 1:  # Don't sleep on the last attempt
                    if e.errno == errno.EBUSY or e.errno == errno.EAGAIN or 'busy' in str(e).lower():
                        delay = base_delay * (2 ** attempt)  # Exponential backoff
                        self.trace('USB device busy, retrying in %.2fs (attempt %d/%d): %s', 
                                 delay, attempt + 1, max_retries, str(e))
                        time.sleep(delay)
                        continue
                    elif e.errno == errno.ENODEV or e.errno == errno.ENOENT:
                        self.trace('USB device not found, retrying in %.2fs (attempt %d/%d): %s', 
                                 base_delay, attempt + 1, max_retries, str(e))
                        time.sleep(base_delay)
                        continue
                
                # Re-raise the exception if it's the last attempt or unrecoverable error
                self.trace('USB command failed after %d attempts: %s', attempt + 1, str(e))
                if e.errno == errno.EBUSY or 'busy' in str(e).lower():
                    raise DeviceBusyException(f"USB device is busy after {max_retries} attempts: {str(e)}") from e
                raise
            except Exception as e:
                self.trace('Unexpected error in USB command (attempt %d/%d): %s', attempt + 1, max_retries, str(e))
                if attempt == max_retries - 1:
                    raise
                time.sleep(base_delay)
        
        # This should never be reached, but just in case
        raise USBError('USB command failed after all retry attempts')

    def read_82(self):
        try:
            resp = self.dev.read(130, 1024 * 1024, timeout=10000)
            resp = bytes(resp)
            self.trace('<130< %d bytes' % len(resp))
            #self.trace('<130< %s' % hexlify(resp).decode())
            return resp
        except Exception as e:
            self.trace('<130< Error: %s', repr(e))
            return None

    # FIXME There is a chance of a race condition here
    def cancel(self):
        self.cancel = True

    def wait_int(self):
        self.cancel = False
        retry_count = 0
        max_retries = 10  # Maximum number of retries before giving up

        while retry_count < max_retries:
            try:
                resp = self.dev.read(131, 1024, timeout=500)  # Increased timeout to 500ms
                resp = bytes(resp)
                self.trace('<int< %s', hexlify(resp).decode())
                return resp
            except USBError as e:
                if e.errno == errno.ETIMEDOUT:
                    if self.cancel:
                        self.trace('wait_int: Operation cancelled')
                        raise CancelledException()
                    retry_count += 1
                    self.trace('wait_int: Timeout (%d/%d)', retry_count, max_retries)
                    continue
                self.trace('wait_int: USB error: %s', str(e))
                raise
            except Exception as e:
                self.trace('wait_int: Unexpected error: %s', str(e))
                raise
        
        self.trace('wait_int: Max retries reached')
        raise USBError('Operation timed out after multiple retries', errno.ETIMEDOUT)

    def trace(self, msg: str, *args, **kwargs):
        if self.trace_enabled:
            logging.log(5, msg, *args, **kwargs)


usb = Usb()
