
from struct import unpack

def assert_status(b):
    s,=unpack('<H', b[:2])
    if s != 0:
        raise Exception('Failed: %04x' % s)

