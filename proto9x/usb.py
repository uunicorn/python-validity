
import usb.core as ucore
from binascii import *
from .util import assert_status, unhex
from struct import unpack
from usb.util import claim_interface, release_interface
from queue import Queue
from threading import Thread
from usb.core import USBError
from .blobs import init_hardcoded, init_hardcoded_clean_slate


class Usb():
    def __init__(self):
        self.trace_enabled = False
        self.queue = Queue(maxsize=10)
        self.quit = None

    def purge_int_queue(self):
        try:
            while True:
                self.queue.get_nowait()
        except:
            pass

    def open(self, vendor=0x138a, product=0x0097):
        self.dev = ucore.find(idVendor=vendor, idProduct=product)
        self.dev.default_timeout = 15000
        self.thread = Thread(target=lambda: self.int_thread())
        self.thread.daemon = True
        self.thread.start()

    def usb_dev(self):
        return self.dev

    def send_init(self):
        #self.dev.set_configuration()

        # TODO analyse responses, detect hardware type
        assert_status(self.cmd(unhexlify('01')))
        assert_status(self.cmd(unhexlify('19')))

        # 43 -- get partition header(?) (02 -- fwext partition)
        # c28c745a in response is a FwextBuildtime = 0x5A748CC2
        rsp=self.cmd(unhexlify('4302'))

        assert_status(self.cmd(init_hardcoded))
        
        (err,), rsp = unpack('<H', rsp[:2]), rsp[2:]
        if err != 0:
            # fwext is not loaded
            print('Clean slate')
            self.cmd(init_hardcoded_clean_slate)

    def cmd(self, out):
        if callable(out):
            out = out()
            if not out:
                return 0
        self.trace('>cmd> %s' % hexlify(out).decode())
        self.dev.write(1, out)
        resp = self.dev.read(129, 100*1024)
        resp = bytes(resp)
        self.trace('<cmd< %s' % hexlify(resp).decode())
        return resp

    def read_82(self):
        try:
            resp = self.dev.read(130, 1024*1024, timeout=10000)
            resp = bytes(resp)
            self.trace('<130< %s' % hexlify(resp).decode())
            return resp
        except Exception as e:
            self.trace('<130< Error: %s' % repr(e))
            return None

    def int_thread(self):
        try:
            while True:
                resp = self.dev.read(131, 1024, timeout=0)
                resp = bytes(resp)
                self.trace('<int< %s' % hexlify(resp).decode())
                self.queue.put(resp)
        except USBError as e:
            self.trace('<int< Exception on interrupt thread: %s' % repr(e))
            if self.quit != None:
                self.quit(e)
        finally:
            self.trace('<int< Interrupt thread is dead')


    def wait_int(self):
        resp = self.queue.get()
        return resp

    def trace(self, s):
        if self.trace_enabled:
            print(s)

usb=Usb()
