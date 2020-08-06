import typing
from struct import pack, unpack

from .blobs import db_write_enable
from .hw_tables import flash_ic_table_lookup, FlashIcInfo
from .tls import tls
from .util import assert_status, unhex


# type 01 is for the firmware - written blocks are decrypted on the fly using fw key
# access lvl:
# 2 -- write only
# 7 -- can read/write even without TLS
class PartitionInfo:
    def __init__(self, id: int, type: int, access_lvl: int, offset: int, size: int):
        self.id, self.type, self.access_lvl, self.offset, self.size = id, type, access_lvl, offset, size

    def __repr__(self):
        return 'PartitionInfo(0x%02x, 0x%02x, 0x%04x, 0x%08x, 0x%08x)' % (
            self.id, self.type, self.access_lvl, self.offset, self.size)


class FlashInfo:
    def __init__(self, ic: FlashIcInfo, blocks: int, unknown0: int, blocksize: int, unknown1: int,
                 partitions: typing.Sequence[PartitionInfo]):
        self.ic = ic
        self.blocks = blocks
        self.unknown0 = unknown0
        self.blocksize = blocksize
        self.unknown1 = unknown1
        self.partitions = partitions

    def __repr__(self):
        return 'FlashInfo(%s, 0x%x, 0x%x, 0x%x, 0x%x, %s)' % (repr(
            self.ic), self.blocks, self.unknown0, self.blocksize, self.unknown1,
                                                              repr(self.partitions))


def get_flash_info():
    rsp = tls.cmd(unhex('3e'))
    assert_status(rsp)
    rsp = rsp[2:]
    hdr = rsp[:0xe]
    rsp = rsp[0xe:]
    jid0, jid1, blocks, unknown0, blocksize, unknown1, pcnt = unpack('<HHHHHHH', hdr)

    ic = flash_ic_table_lookup(jid0, jid1, blocks * blocksize)

    if ic is None:
        raise Exception('Unknown flash IC. JEDEC id=%x:%x, size=%dx%d' %
                        (jid0, jid1, blocks, blocksize))

    partitions = [rsp[i * 0xc:(i + 1) * 0xc] for i in range(0, pcnt)]
    partitions = [unpack('<BBHLL', i) for i in partitions]
    partitions = [PartitionInfo(*i) for i in partitions]

    return FlashInfo(ic, blocks, unknown0, blocksize, unknown1, partitions)


# >>> 4302 -- get partition header (get fwext info)
# b004 -- no fw detected
# 0000
#   0100 (major) 0100 (minor) 0800 (modules) c28c745a (buildtime)
#      type subtype  major   minor   size
#      0100 3446     0200    0700    d03e0000
#      0100 8408     0100    0700    00040000
#      0200 8428     0300    1200    e0100000
#      0200 7636     0100    0c00    100a0000
#      0100 8647     0000    0100    505a0000
#      0200 2377     0000    0100    802f0000
#      0200 6637     0100    0c00    f0220200
#      0100 2556     0000    0100    60040000
class ModuleInfo:
    def __init__(self, type: int, subtype: int, major: int, minor: int, size: int):
        self.type, self.subtype, self.major, self.minor, self.size = type, subtype, major, minor, size

    def __repr__(self):
        return 'ModuleInfo(0x%04x, 0x%04x, %d, %d, %d)' % (self.type, self.subtype, self.major,
                                                           self.minor, self.size)


class FirmwareInfo:
    def __init__(self, major: int, minor: int, buildtime: int,
                 modules: typing.Sequence[ModuleInfo]):
        self.major, self.minor, self.buildtime, self.modules = major, minor, buildtime, modules

    def __repr__(self):
        return 'FirmwareInfo(%d, %d, %d, %s)' % (self.major, self.minor, self.buildtime,
                                                 repr(self.modules))


def get_fw_info(partition: int):
    rsp = tls.cmd(pack('<BB', 0x43, partition))

    # don't want to throw exception here - it is normal not to have FW when we're about to upload it
    if len(rsp) == 2 and rsp[1] == 4 and rsp[0] == 0xb0:
        return None

    assert_status(rsp)
    rsp = rsp[2:]
    hdr = rsp[:0xa]
    rsp = rsp[0xa:]
    major, minor, modcnt, buildtime = unpack('<HHHL', hdr)
    modules = [rsp[i * 0xc:(i + 1) * 0xc] for i in range(0, modcnt)]
    modules = [unpack('<HHHHL', i) for i in modules]
    modules = [ModuleInfo(*i) for i in modules]

    return FirmwareInfo(major, minor, buildtime, modules)


def write_enable():
    assert_status(tls.cmd(db_write_enable))


def call_cleanups():
    rsp = tls.cmd(b'\x1a')
    err = unpack('<H', rsp[:2])[0]
    if err == 0x0491:  # Nothing to commit
        return  # don't throw an exception, just ignore
    assert_status(rsp)


def erase_flash(partition: int):
    assert_status(tls.cmd(db_write_enable))
    try:
        assert_status(tls.cmd(pack('<BB', 0x3f, partition)))
    finally:
        call_cleanups()


def read_flash(partition: int, addr: int, size: int) -> bytes:
    cmd = pack('<BBBHLL', 0x40, partition, 1, 0, addr, size)
    rsp = tls.cmd(cmd)
    assert_status(rsp)
    sz, = unpack('<xxLxx', rsp[:8])

    return rsp[8:8 + sz]


def write_flash(partition: int, addr: int, buf: bytes):
    tls.cmd(db_write_enable)
    cmd = pack('<BBBHLL', 0x41, partition, 1, 0, addr, len(buf)) + buf
    try:
        rsp = tls.cmd(cmd)
        assert_status(rsp)
    finally:
        call_cleanups()


def write_flash_all(partition: int, ptr: int, buf: bytes):
    bs = 0x1000
    while len(buf) > 0:
        chunk, buf = buf[:bs], buf[bs:]
        write_flash(partition, ptr, chunk)
        ptr += len(chunk)


def read_flash_all(partition: int, start: int, size: int):
    bs = 0x1000
    blocks = [read_flash(partition, addr, bs) for addr in range(start, start + size, bs)]
    return b''.join(blocks)[:size]


def write_fw_signature(partition: int, signature: bytes):
    rsp = tls.cmd(pack('<BBxH', 0x42, partition, len(signature)) + signature)
    assert_status(rsp)


def read_tls_flash():
    return read_flash(1, 0, 0x1000)
