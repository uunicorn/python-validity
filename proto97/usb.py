
import usb.core as ucore
from binascii import *
from .util import assert_status, unhex
from struct import unpack
from usb.util import claim_interface, release_interface
from queue import Queue
from threading import Thread
from usb.core import USBError

init_hardcoded=unhex('''
06020000015cb560afa595d0dcf4fca09ebb69301e2b9e24a5dfb6f2602833427d3bd65222c418ff15b54587ab2854c4fe9aea74fa55567
2036fa3ec73c6912c58b1b49cbdcc7664165482cd70d5bb95d9d469626fdc2e012d74157c5792260968a2a4572b1ccccc26ec2e2ed0ddda
1b0931d3d0566460915d43e0a654a0582706be9113ea88f0c15ba058507efb0dadecb4a4cc64444dddf050b6e8d4ebb34ebba33e8651c75
e5fb28f85c83197df1de460d9e1cb82208753ceff0ef60a823dba75d05548f5b3a5a0e2972232f7403bd6869da90e5371a0ab8ad23972f1
597630f5ff7c8b8272800563477288b5591bbb0341d3975efc1778225767fa35480ff7f8dd633e4034ac32e4af58b86ebc63552cb35b12b
285255deaf3a32bf46cdc5ad3bc1c9ed1bcc112c72143f9aec568e2cacfa89ba0c7bb65590d8b93e6871a33c6c6983c0acd04e737ff55ee
e024ca6b9a48332c1a69a5a3fdd24b964cf7e7c55229bb0b48a6e339eb2c42d07ec850a4ee780660ad6c77ffa302a63bd19426134c4533d
69192ef2e16591df26394791a4ecb994a24f5a7f70f1eb2604e6bfb67a452cb74ead8b0d9808f890ac386750cbac06ee03a852145094053
b2b074b9905de5cdbf2272b67e51f159164778d6d2ef7a1ccb81df9f896ddb38ce11e8140cf6cb9c82
''')
init_hardcoded_clean_slate=unhex('''
06020000012c40c9d271378bc0912ef5dced69bd81b7fc16972c7b46e621af54a00e2cc6baca6eb83ea30222dfc6c925262006ae93412ea
cf482f2034ee7b13297474b7e1e91f279cac2ccb7195443e4dd3328cfd292ade073fcc2eaa8f07b77231130ba997f921b9be7b4fb6cc691
0d2976b3e050913b27dbe73afd6e964260b9435ebab5117e71f7cb68464d4b6f8afc7e1a421f671f5854a1d0c8ab93ed3b88b2bc1a42875
e40b15f0e78496ac40e4a4a7fd39a97534ce1866479e0384f0789bbfc2fea0ce982bf7a9df97d60b237edbe1b26c9791043a96b81e435d6
de5971c758d374905df95b0cddabfbf531749ba191f07a6f5e2722852f137a53513a9ec6ab30c3f09aa6ce21b391e55cf81dcda6422011b
f163317a9a4382546141d45f2274bd660103bd3af705f3ed12e493bc4f834d5d7f162e2c3405cf857b00129789a3353bf7fab7796e267e3
062d55660dbbb857911ac8e871c460dd31c56a86a5631475f0f2ee5e9ce2af0faec0931a640ba2394025f29ffeca3a7e99c15a78ce1f1f7
808cedd7601b9b6382d72ca873257d4f6af70e29e22afea15e36e0282b8f0bfc68ffa3417d212b8bbe11bb73b363a19872e6e947d45de30
fbc493ca083a0a4650615d8628606362081ca6df5d67527971d1776ad76a7a28c932f0317b59cb4a82a14b2bcb7b01fb662be1496d24d91
9140ec80068b21a818daa2fb8e05f63edbd4bd5797c74a28b3e7cf81c9045248584977711341fca3f08ba91ff853b62dc24ce4bba4ed57f
47bd458545d805b6bb14fe0cde01440b60bf7be937f6444a8e2a10ed8fa9ddb8604bb95fe411b97112e78dbf5a4a0f004669c93765a9f38
665cb55f5658895c1c06a7aedf694bfb3afa9b8b1dea5ab85c821ac20b0663b95023642fda36ad78e3e00140b966f404f7e55f0b416ea43
b4c74c39900830abc6906a1004bef1b5b7dbbbeb5ec1b22604ac86429b9f56511b746a7124c449b8c9498f49144abc2d64f6a114f1d7f91
aa41249faeef4d838e280cb5d6fc19cfe86c75f
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
        self.dev = ucore.find(idVendor=0x138a, idProduct=0x0097)
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
            self.cmd(init_hardcoded_clean_slate)

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
