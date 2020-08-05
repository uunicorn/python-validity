import typing
from struct import unpack, pack


class SidIdentity():
    def __init__(self, revision: int, auth: int, subauth: typing.Sequence[int]):
        self.revision = revision
        self.auth = auth
        self.subauth = subauth

    def to_bytes(self):
        b = pack('>BBHL', self.revision, len(self.subauth), self.auth >> 32, self.auth & 0xffffffff)
        for i in self.subauth:
            b += pack('<L', i)

        return b

    def __repr__(self):
        return 'S-%d-%d-%s' % (self.revision, self.auth, '-'.join(map(str, self.subauth)))


def sid_from_bytes(b: bytes):
    revision = b[0]
    subcnt = b[1]
    auth = 0

    for i in b[2:8]:
        auth <<= 8
        auth |= i

    subauth = unpack('<%dL' % subcnt, b[8:])

    return SidIdentity(revision, auth, subauth)


def sid_from_string(s: str):
    parts = s.split('-')

    if parts[0] != 'S':
        raise Exception('Expected "S" as a first part')

    parts = list(map(int, parts[1:]))
    revision, auth, subauth = parts[0], parts[1], parts[2:]

    return SidIdentity(revision, auth, subauth)
