
import re
from struct import unpack
from binascii import unhexlify

def assert_status(b):
    s,=unpack('<H', b[:2])
    if s != 0:
        raise Exception('Failed: %04x' % s)

def unhex(x):
    return unhexlify(re.sub('\W', '', x))

