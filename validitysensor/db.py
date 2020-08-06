import typing
from binascii import hexlify
from struct import pack, unpack

from .blobs import db_write_enable
from .flash import call_cleanups
from .sid import SidIdentity, sid_from_bytes
from .tls import tls
from .util import assert_status
from .winbio_constants import finger_names


class UserStorage:
    def __init__(self, dbid: int, name: str):
        self.dbid = dbid
        self.name = name
        self.users = []

    def __repr__(self):
        return '<UserStorage: dbid=%04x name=%s users=%s>' % (self.dbid, repr(
            self.name), repr(self.users))


class User:
    def __init__(self, dbid: int, identity: str):
        self.dbid = dbid
        self.identity = identity
        self.fingers: typing.List[typing.Mapping[str, int]] = []

    def __repr__(self):
        return '<User: dbid=%04x identity=%s fingers=%s>' % (self.dbid, repr(
            self.identity), repr(self.fingers))


def subtype_to_string(s: int):
    finger_name = finger_names.get(s, None)
    return finger_name or 'Unknown'


def parse_user_storage(rsp: bytes):
    rc, = unpack('<H', rsp[:2])

    if rc == 0x04b3:
        return None

    assert_status(rsp[:2])
    rsp = rsp[2:]

    hdr, rsp = rsp[:8], rsp[8:]
    recid, usercnt, namesz, unknwn = unpack('<HHHH', hdr)
    usrtab, rsp = rsp[:4 * usercnt], rsp[4 * usercnt:]
    name, rsp = rsp[:namesz], rsp[namesz:]

    if len(rsp) > 0:
        raise Exception('Junk at the end of the storage info response: %s' % rsp.hex())

    storage = UserStorage(recid, name)

    while len(usrtab) > 0:
        rec, usrtab = usrtab[:4], usrtab[4:]
        urid, valsz = unpack('<HH', rec)
        storage.users += [{'dbid': urid, 'valueSize': valsz}]

    return storage


def parse_identity(b: bytes):
    t, b = b[:4], b[4:]
    t, = unpack('<L', t)

    if t == 3:
        l, b = b[:4], b[4:]
        l, = unpack('<L', l)
        return sid_from_bytes(b[:l])

    raise Exception('Don' 't know how to handle identity type %d' % t)


def parse_user(rsp: bytes):
    assert_status(rsp[:2])
    rsp = rsp[2:]

    hdr, rsp = rsp[:8], rsp[8:]
    recid, fingercnt, unknwn, identitysz = unpack('<HHHH', hdr)
    fingertab, rsp = rsp[:8 * fingercnt], rsp[8 * fingercnt:]
    identity, rsp = rsp[:identitysz], rsp[identitysz:]

    if len(rsp) > 0:
        raise Exception('Junk at the end of the user info response: %s' % rsp.hex())

    identity = parse_identity(identity)
    user = User(recid, identity)

    while len(fingertab) > 0:
        rec, fingertab = fingertab[:8], fingertab[8:]
        frid, subtype, stgid, valsz = unpack('<HHHH', rec)
        user.fingers += [{'dbid': frid, 'subtype': subtype, 'storage': stgid, 'valueSize': valsz}]

    return user


def identity_to_bytes(identity: str):
    if isinstance(identity, SidIdentity):
        b = identity.to_bytes()
        b = pack('<LL', 3, len(b)) + b

        # May not be neccessary, but windows union has a minimum size of 0x4c bytes
        # and search by identity treats same SIDs with different sizes as different keys
        while len(b) < 0x4c:
            b += b'\0'

        return b
    else:
        raise Exception('Don' 't know how to handle identity %s' % repr(identity))


class DbRecord:
    def __init__(self):
        self.dbid = 0
        self.type = 0
        self.storage = 0
        self.value = None
        self.children = None

    def __repr__(self):
        return '<DbRecord: dbid=%d type=%d storage=%d value=%s children=%s>' % (
            self.dbid, self.type, self.storage, repr(self.value), repr(self.children))


class Db:
    class Info:
        def __init__(self, total: int, used: int, free: int, records: int, roots):
            self.total = total  # partition size
            self.used = used  # used (not deleted)
            self.free = free  # unallocated space
            self.records = records  # total number, including deleted
            self.roots = roots

        def __repr__(self):
            return 'Db.Info(total=%d, used=%d, free=%d, records=%d, roots=%s)' % (
                self.total, self.used, self.free, self.records, repr(self.roots))

    def get_user_storage(self, dbid=0, name=''):
        name = name.encode()

        if len(name) > 0:
            name += b'\0'

        return parse_user_storage(tls.cmd(pack('<BHH', 0x4b, dbid, len(name)) + name))

    def new_user_storate(self):
        db.new_record(1, 4, 3, b'StgWindsor\0')

    def get_storage_data(self):
        stg = self.get_user_storage(name='StgWindsor')
        rc = self.get_record_children(stg.dbid).children
        return [i['dbid'] for i in rc if i['type'] == 8]  # 8 == "data" type

    def get_user(self, dbid: int):
        return parse_user(tls.cmd(pack('<BHHH', 0x4a, dbid, 0, 0)))

    def lookup_user(self, identity: str) -> typing.Optional[User]:
        stg = self.get_user_storage(name='StgWindsor')
        data = identity_to_bytes(identity)

        rsp = tls.cmd(pack('<BHHH', 0x4a, 0, stg.dbid, len(data)) + data)
        rc, = unpack('<H', rsp[:2])

        if rc == 0x04b3:
            return None
        else:
            return parse_user(rsp)

    def get_record_value(self, dbid: int):
        rsp = tls.cmd(pack('<BH', 0x49, dbid))
        assert_status(rsp)

        rec = DbRecord()
        rec.dbid, rec.type, rec.storage, sz = unpack('<xxHHHHxx', rsp[:12])
        rec.value = rsp[12:12 + sz]

        return rec

    def get_record_children(self, dbid: int):
        rsp = tls.cmd(pack('<BH', 0x46, dbid))
        assert_status(rsp)

        rec = DbRecord()
        rec.dbid, rec.type, rec.storage, sz, cnt = unpack('<xxHHHHHxx', rsp[:14])
        rsp = rsp[14:]
        rec.children = []
        for i in range(0, cnt):
            dbid, typ = unpack('<HH', rsp[i * 4:i * 4 + 4])
            rec.children += [{'dbid': dbid, 'type': typ}]

        return rec

    def del_record(self, dbid: int):
        assert_status(tls.cmd(pack('<BH', 0x48, dbid)))

    def db_info(self):
        rsp = tls.cmd(b'\x45')
        assert_status(rsp)
        rsp = rsp[2:]

        unknown1, unknown0, total, used, free, records, nroots = unpack('<LLLLLHH', rsp[:0x18])
        # Seems to always be unknown1 == 1, unknown0 == 0
        rsp = rsp[0x18:]
        roots = [unpack('<H', rsp[i * 2:i * 2 + 2])[0] for i in range(0, nroots)]

        return Db.Info(total, used, free, records, roots)

    def new_record(self, parent: int, typ: int, storage: int, data: bytes):
        self.db_info()  # TODO check free space, compact the partition when out of storage
        assert_status(tls.cmd(db_write_enable))
        try:
            rsp = tls.cmd(pack('<BHHHH', 0x47, parent, typ, storage, len(data)) + data)
            assert_status(rsp)
            recid, = unpack('<H', rsp[2:])
        finally:
            call_cleanups()
        return recid

    def new_user(self, identity: str):
        data = identity_to_bytes(identity)

        stg = self.get_user_storage(name='StgWindsor')
        rec = self.new_record(stg.dbid, 5, stg.dbid, data)
        return rec

    def new_finger(self, userid: int, template: bytes):
        stg = self.get_user_storage(name='StgWindsor')
        # We ask to create an object of type 0xb,
        # but because of the magical `db_write_enable` in the new_record() it ends up being 0x6
        rec = self.new_record(userid, 0xb, stg.dbid, template)
        return rec

    def new_data(self, parent: int, data: bytes):
        stg = self.get_user_storage(name='StgWindsor')
        data = pack('<HH', 1, len(data)) + data
        rec = self.new_record(parent, 0x8, stg.dbid, data)
        return rec

    def dump_raw(self, root=3, depth=0):
        rec = self.get_record_value(root)
        val = hexlify(rec.value).decode()
        if len(val) > 80:
            val = val[:80] + '...'
        print('%s%d (type %d) %s' % ('  ' * depth, rec.dbid, rec.type, val))

        rec = self.get_record_children(root)
        for c in rec.children:
            self.dump_raw(c['dbid'], depth + 1)

    def dump_all(self):
        stg = self.get_user_storage(name='StgWindsor')
        usrs = [self.get_user(u['dbid']) for u in stg.users]
        for u in usrs:
            print('%2d: User %s with %d fingers:' % (u.dbid, repr(u.identity), len(u.fingers)))
            for f in u.fingers:
                print('    %2d: %02x (%s)' %
                      (f['dbid'], f['subtype'], subtype_to_string(f['subtype'])))


db = Db()
