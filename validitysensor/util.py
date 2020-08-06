import re
from binascii import unhexlify
from struct import unpack


def assert_status(b: bytes):
    s, = unpack('<H', b[:2])
    if s != 0:
        if s == 0x44f:
            raise Exception('Signature validation failed: %04x' % s)

        raise Exception('Failed: %04x' % s)


def unhex(x: str):
    return unhexlify(re.sub(r'\W', '', x))
