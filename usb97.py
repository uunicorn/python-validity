
import re
import usb.core
from binascii import *

def unhex(x):
    return unhexlify(re.sub('\W', '', x))

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

class Usb():
    def __init__(self):
        self.trace_enabled = False

    def open(self):
        self.dev = usb.core.find(idVendor=0x138a, idProduct=0x0097)
        self.dev.default_timeout = 5000
        self.dev.set_configuration()

        # TODO analyse responses
        self.cmd(unhexlify('01'))
        self.cmd(unhexlify('19'))
        self.cmd(unhexlify('4302'))
        # TODO is this one always the same?
        self.cmd(init_hardcoded)

        self.cmd(unhexlify('3e'))

    def cmd(self, out):
        self.trace('>cmd> %s' % hexlify(out).decode())
        self.dev.write(1, out)
        resp = self.dev.read(129, 100*1024)
        resp = bytes(resp)
        self.trace('<cmd< %s' % hexlify(resp).decode())
        return resp

    def wait_int(self):
        resp = self.dev.read(131, 1024, timeout=0)
        resp = bytes(resp)
        self.trace('<int< %s' % hexlify(resp).decode())
        return resp

    def trace(self, s):
        if self.trace_enabled:
            print(s)

