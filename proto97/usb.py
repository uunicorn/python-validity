
import usb.core as ucore
from binascii import *
from .util import assert_status, unhex
from struct import unpack
from usb.util import claim_interface, release_interface
from queue import Queue
from threading import Thread
from usb.core import USBError

# ...............................................................................................................
init_hardcoded=unhex('''
06020000013917b3dda91383b5bcac64fa4ad35dce96570a9d2d974b80926a431f9cd46248980a263c6fcef6a82839a90b59ac590848859
afac817b7d53bf51cd3205c1b8f43048be8253c3bd247937c837aca8b18d3cc8ee8c8971ac4f688813cf3d8550d71496985b7ec07ff2dc7
896d330fdab263a0ee433a5c4bc910439d1c6161853feb03f5502209502e7308beb7919473cfe69f422c30502d226a4d0a34d96c8c77956
cf69db8ef6cf927a3b57849d4aa8ad4b44266923e34b82a39c8146ba3cd708c70dfedb50c2de61feb45b1d4f19584297203f5fdc865795f
ec9d6449f3ba9b6f1e4bed698ee151e83d4d8702f76a4006cfa24d9b797888203b2269f8a77d524034ac32e4af58b86ebc63552cb35b12b
285255deaf3a32bf46cdc5ad3bc1c9ed1bcc112c72143f9aec568e2cacfa89ba0c7bb65590d8b93e6871a33c6c6983c0acd04e737ff55ee
e024ca6b9a48332c1a69a5a3fdd24b964cf7e7c55229bb0b48a6e339eb2c42d07ec850a4ee780660ad6c77ffa302a63bd19426134c4533d
6f967441163fb78b73547c68a493b2f800d3cdab827b116762789992aae3c8ab345a49edd312dfd2a27bc501427dc7fa00ac3c5c36551db
b3d5cad8d5bd7cea37e58a31307a6d50e6ae379a53f1366678c0741a3d872b8dcfefa7f63128dc8245
''')

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

    def open(self):
        self.dev = ucore.find(idVendor=0x138a, idProduct=0x0090)
        self.dev.default_timeout = 15000
        self.thread = Thread(target=lambda: self.int_thread())
        self.thread.daemon = True
        self.thread.start()

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

    def cmd(self, out):
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
