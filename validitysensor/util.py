import re
from binascii import unhexlify
from struct import unpack


class DatabaseFullException(Exception):
    """Exception raised when the fingerprint database is full."""
    pass

class DeviceStorageException(Exception):
    """Exception raised for device storage related issues."""
    pass

def assert_status(b: bytes):
    s, = unpack('<H', b[:2])
    if s != 0:
        if s == 0x44f:
            raise Exception('Signature validation failed: %04x' % s)
        elif s == 0x04c3:
            raise DatabaseFullException(
                'Database storage full (error %04x). '
                'Please delete existing fingerprints or clear the database to make space for new enrollments.' % s
            )
        elif s in [0x04b3, 0x04c0, 0x04c1, 0x04c2]:
            raise DeviceStorageException('Device storage error: %04x' % s)

        raise Exception('Failed: %04x' % s)


def unhex(x: str):
    return unhexlify(re.sub(r'\W', '', x))
