
from util import unhex
from tls97 import tls
from util import assert_status
from struct import pack, unpack
from binascii import hexlify, unhexlify
from blobs import db_write_enable
from flash import flush_changes
from sid import *

class UserStorage():
    def __init__(self, dbid, name):
        self.dbid=dbid
        self.name=name
        self.users=[]

    def __repr__(self):
        return '<UserStorage: dbid=%04x name=%s users=%s>' % (self.dbid, repr(self.name), repr(self.users))

class User():
    def __init__(self, dbid, identity):
        self.dbid=dbid
        self.identity=identity
        self.fingers=[]

    def __repr__(self):
        return '<User: dbid=%04x identity=%s fingers=%s>' % (self.dbid, repr(self.identity), repr(self.fingers))

def subtype_to_string(s):
    if s < 0xf5 or s > 0xfe:
        return 'Unknown'

    return 'WINBIO_FINGER_UNSPECIFIED_POS_%02d' % (s - 0xf5 + 1)

def parse_user_storage(rsp):
    assert_status(rsp[:2])
    rsp=rsp[2:]

    hdr, rsp = rsp[:8], rsp[8:]
    recid, usercnt, namesz, unknwn = unpack('<HHHH', hdr)
    usrtab, rsp = rsp[:4*usercnt], rsp[4*usercnt:]
    name, rsp = rsp[:namesz], rsp[namesz:]

    if len(rsp) > 0:
        raise Exception('Junk at the end of the storage info response: %s' % rsp.hex())

    storage=UserStorage(recid, name)

    while len(usrtab) > 0:
        rec, usrtab = usrtab[:4], usrtab[4:]
        urid, valsz = unpack('<HH', rec)
        storage.users += [ { 'dbid': urid, 'valueSize': valsz } ]

    return storage

def parse_identity(b):
    t, b = b[:4], b[4:]
    t, = unpack('<L', t)

    if t == 3:
        l, b = b[:4], b[4:]
        l, = unpack('<L', l)
        return sid_from_bytes(b[:l])

    raise Exception('Don''t know how to handle identity type %d' % t)

def parse_user(rsp):
    assert_status(rsp[:2])
    rsp=rsp[2:]

    hdr, rsp = rsp[:8], rsp[8:]
    recid, fingercnt, unknwn, identitysz = unpack('<HHHH', hdr)
    fingertab, rsp = rsp[:8*fingercnt], rsp[8*fingercnt:]
    identity, rsp = rsp[:identitysz], rsp[identitysz:]

    if len(rsp) > 0:
        raise Exception('Junk at the end of the user info response: %s' % rsp.hex())

    identity = parse_identity(identity)
    user=User(recid, identity)

    while len(fingertab) > 0:
        rec, fingertab = fingertab[:8], fingertab[8:]
        frid, subtype, stgid, valsz = unpack('<HHHH', rec)
        user.fingers += [ { 'dbid': frid, 'subtype': subtype, 'storage': stgid, 'valueSize': valsz } ]

    return user

def identity_to_bytes(identity):
    if isinstance(identity, SidIdentity):
        b=identity.to_bytes()
        b = pack('<LL', 3, len(b)) + b

        # May not be neccessary, but windows union has a minimum size of 0x4c bytes 
        # and search by identity treats same SIDs with different sizes as different keys
        while len(b) < 0x4c:
            b += b'\0'

        return b
    else:
        raise Exception('Don''t know how to handle identity %s' % repr(identity))
    
class DbRecord():
    def __init__(self):
        self.dbid = 0
        self.type = 0
        self.storage = 0
        self.value = None
        self.children = None

    def __repr__(self):
        return '<DbRecord: dbid=%d type=%d storage=%d value=%s children=%s>' % (
                    self.dbid,
                    self.type,
                    self.storage,
                    repr(self.value),
                    repr(self.children)
                )
            

class Db():
    def get_user_storage(self, dbid=0, name=''):
        name=name.encode()

        if len(name) > 0:
            name += b'\0'

        return parse_user_storage(tls.cmd(pack('<BHH', 0x4b, dbid, len(name)) + name))

    def get_user(self, dbid):
        return parse_user(tls.cmd(pack('<BHHH', 0x4a, dbid, 0, 0)))

    def lookup_user(self, identity):
        stg = self.get_user_storage(name='StgWindsor')
        data = identity_to_bytes(identity)
        
        rsp = tls.cmd(pack('<BHHH', 0x4a, 0, stg.dbid, len(data)) + data)
        rc, = unpack('<H', rsp[:2])

        if rc == 0x04b3:
            return None
        else:
            return parse_user(rsp)

    def get_record_value(self, dbid):
        rsp = tls.cmd(pack('<BH', 0x49, dbid))
        assert_status(rsp)

        rec = DbRecord()
        rec.dbid, rec.type, rec.storage, sz = unpack('<xxHHHHxx', rsp[:12])
        rec.value = rsp[12:12+sz]

        return rec

    def get_record_children(self, dbid):
        rsp = tls.cmd(pack('<BH', 0x46, dbid))
        assert_status(rsp)
        
        rec = DbRecord()
        rec.dbid, rec.type, rec.storage, sz, cnt = unpack('<xxHHHHHxx', rsp[:14])
        rsp = rsp[14:]
        rec.children=[]
        for i in range(0, cnt):
            dbid, typ = unpack('<HH', rsp[i:i+4])
            rec.children += [{ 'dbid': dbid, 'type': typ }]

        return rec

    def del_record(self, dbid):
        assert_status(tls.cmd(pack('<BH', 0x48, dbid)))


    def new_record(self, parent, typ, storage, data):
        assert_status(tls.cmd(b'\x45'))
        assert_status(tls.cmd(db_write_enable))
        rsp = tls.cmd(pack('<BHHHH', 0x47, parent, typ, storage, len(data)) + data)
        assert_status(rsp)
        recid, = unpack('<H', rsp[2:])
        flush_changes()
        return recid

    def new_user(self, identity):
        data = identity_to_bytes(identity)

        stg = self.get_user_storage(name='StgWindsor')
        rec = self.new_record(stg.dbid, 5, stg.dbid, data)
        return rec

    def new_finger(self, userid, template):
        stg = self.get_user_storage(name='StgWindsor')
        # We ask to create an object of type 0xb, 
        # but because of the magical `db_write_enable` in the new_record() it ends up being 0x6
        rec = self.new_record(userid, 0xb, stg.dbid, template)
        return rec

    def new_data(self, parent, data):
        stg = self.get_user_storage(name='StgWindsor')
        data = pack('<HH', 1, len(data)) + data
        rec = self.new_record(parent, 0x8, stg.dbid, data)
        return rec

    def dump_all(self):
        stg = self.get_user_storage(name='StgWindsor')
        usrs = [self.get_user(u['dbid']) for u in stg.users]
        for u in usrs:
            print('%2d: User %s with %d fingers:' % (u.dbid, repr(u.identity), len(u.fingers)))
            for f in u.fingers:
                print('    %2d: %02x (%s)' % (f['dbid'], f['subtype'], subtype_to_string(f['subtype'])))

db = Db()

