
from usb97 import unhex
from util import assert_status
from struct import pack, unpack
from binascii import hexlify, unhexlify
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

def parse_user_storage(rsp):
    assert_status(rsp[:2])
    rsp=rsp[2:]

    hdr, rsp = rsp[:8], rsp[8:]
    recid, usercnt, namesz, unknwn = unpack('<HHHH', hdr)
    usrtab, rsp = rsp[:4*usercnt], rsp[4*usercnt:]
    name, rsp = rsp[:namesz], rsp[namesz:]

    if len(rsp) > 0:
        raise Exception('Junk at the end of the storage info response: %s' % unhexlify(rsp).decode())

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
        raise Exception('Junk at the end of the user info response: %s' % unhexlify(rsp).decode())

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
    
wtf_hardcoded=unhex('''
0602000001648445315dac4d9c91edfb3c327ec18aee87a1fd5e0993fe74b56ee9a70f0eb4d65bfc877060728ad26e695be98899ef76b85
2162cc5e6ccded51e5a26e7e345c4a8e83aafa2e10fa4cc78f0f34575b0565089b4c78ce1ac7fe3744f4721aa73209fa4a8699e7161bfd7
ee58dee33f1af15ba3b9ce9a469c5c82eda2b2a2f01658ee14118304e865bc2ad415bec9f06757bb3f2263bd0349a3c089380b72a30edf8
db01db75586c60ddc9e7bedc8cf9006fcc6825b0ec9dc8782b95f53325bfb6a6945644f2803a4c7fd35574d8b7b089102fb072dfa883049
f9484a789ff763a029f78adfceac92db195573c65986e38aec2135b5da3c0797939154135be5227515602c0148dbcb8c8a3760dad71f877
471244cf1053a3cc4bc73c437589a1a47e08c260ea40d3259138e754a556a23e09bf926ad90ff36096c27c460ebdd28f20f31e9f42a1925
26d79b94e7f2c36b66db69946d93edf8fbd516e3ae59a0b81400c39f6bc1feb209924bc04703fd36ab53dd5658b2dd91633823917c37e94
4e740409c5fd66974ed42b73d5d7db519c7037b1ed32e471750da95299463cb070c80cea4a03bf20351716ee14423f84670c53ef7b998c1
79b84ae91cff6ca6b33a372e9947eebc873c6a98c6bcda68e5278b6f799a468bd1a33ae07bf717fbfc20f4d019f0fb25a5d6cb75a97fbd9
b8490e6204d272d93f62ad393307cad3e24d292040e61fce6f1104c42dc4260de15f42971bbab18064b5dd6ceb12a32d9d25614d9326048
052bc178b5a0aed3f350cbbec021c4b1ac6ed383f7f4eca0e475cf56caefc3edd3cde6526401936cc095b2df8e0008b2d9bd78c82af0a1e
c0a71f047dd06b4ce6e91886607c55536f0d8712eae4ccb890008ccc27f2d6f6cb9b9bb88ec205019ec722160ffb1c65ca3177cff09c4bd
ae8c40be5bf91488a600ed199d0aad40510afe580802c56c0241a8b2a836800e8a0d07ae37176934252f92fc0e501aee29e6c3567e37b3e
1992ff00b561fd1b3ae37caecc3a1fea7720b0806d3b39cf8a3fb46087b43775b9e473e65cb18af1c9d87a5140a5edf8b7843524910d631
79c436b6a806d100eb066db889768f7da603631d75a6d79e3d0eb1fe9ba55401b828d4a367f695f3922b982be10fdb1f139a0b1438abc91
1db5da00ed464d80e3086d368dd131985a21610cd485740599afa772b5dc44d1906ea4c13b8e10b8db896fb81b706038a3328cd07aeb049
e6ec92ecd30044c54eb171e9cf7a0034cd24614616048491f576826af5ca6afe4bc01f86dc01c2ea25efb32bc9b1c8d56cc7d4d86adf8f1
f3bb6a649f98bae686ef93524721c618fad85a8125a8ac7d72bfeb7de9f590e8f43535e59259a7a1d13a12a1af91c8ba0dd45ddad02e5b8
6224fc00dcbc143b0e1d2da638d6798fcc340bda8f1e3abf21cadb2161c4c4be7001371dc56f0d112b42b113288effea6cab8c4b610f730
37643de21f433774d9fb28cfd213a62dcafab8b662b57e77239dc2fb69f026fcb773f09129c8db04b82dce68734516ffcb938d43deeeeda
a02cc08d7d06f34ec55ba4b224d3270265001df114b946d4238d51cfbfb84cf715b745ec918259c1165ee12ab82b4373eaa2b0c7e68da3e
b869ff033d5953800012bb006d1cf17dcbbe2fb2e129614351c000cab8ccc7c389df33dbe504a0c1df37868b839ef84a6c04072d69fc866
33055b2569c9c04f1994758987fc7063b97853c727809185a25cd69bfebf6a4367760fd21e7942b997bb2b7098dbec715769d13413c1c93
185409e54a2c9a97daf63114c71348f19549fb3a8551afbbb7476842f7045a0ec8e6d97fb4bb6de76090687ab4e9991a31e7625ba7088a3
263797be4787db02573b72100b3ba117e8897b939548715bcfa11d98861b60fa2a4759630b47cbbf329fbc675c4cfc2f963cc9ba72cbe67
13aff1851869917ba0b761f6532d1dee95331c4c621bb0513e993f7e6dda6da1e3076829b24093c8338c125aa2f5a0730f9e5631f7a9594
c13025fde9bb4f2431540a1c743c7fc55fc8909d85847fe71af8a68d2981b0eee84a308e0160fc4226aa679ca9b35d0aacae8240aabd5b2
17c5e66ac4795596f8742acb9869c3f52a96b1d946ff72f403ba491c1a0e4be778efab9d61a250562d705c2b459fc3a420143daf9355226
4bb8c7caa64143697961fab1b6af9e852d43a94736e1e75e4b9a7c2bee73598360c7e4c648e47ba9400dbe22b3eea6d9ab87fe677b36242
57f81d26b87536a642a7840bdccd8fce05c23891a4fa4ce2156fba2856313653207bf225b8114005432824d16a93473deb81721c77196af
d80cf723e8cdea81aaed19f55a09a8986f2950c49f4eebfb142d5e4815632d93ccb0106c156b47efca25dc3d7f31eb9b2dee0d2d83a51cb
e5d1270222920f2c87e5acc884c11b0df7a7e1bb49b06fa4f936964d3f2782fa46eec3e430815f82ab0fb5eb82377277f8fe3ae5b33732d
7d76ba3de284c66fba372f04f9ad6a39fa669a00583313d51c8e6b1eb960bf1e82ae8e0504b2d3035b371d5ecf638c1cc0c1dd67eff286f
c9ee0950da53f339a85fbbcbacf61fcdadee8cdba0950d23ec71e2239ae7ab5be1bf56364897af990428822d23deed81fbbe622420234de
d92b8fc3073bfa0a9677cd9e24b9f81278c50584bdc880fa2cd5c5c4b03bd78be872a656f3ef74b30d4e66f1ff091a343f75f096e64ab25
b64d426862ed3f21dc54c6b6a8cb90b065c7b33b03e97acde7d58a2fa35664ec03ef1f82a30441a021ec008bee9444bbe50ec8ff457d32d
06a63b9dc84fd82fa110a30dd849bf9f8cb4d3599b9aa09a76ad1b7c52bb972e5b16670670994ef7471f2d738ba9430664b7a1c259745ba
8b2b9d98e695bad0b59e1fd989475a61570b2b677734c3f1887f9555b760811e20caba91eff59e9fb328561e12749c32f603bd50da5c449
7393ccd560e88f367a664c5f2f9fe73107e2664a07a0f015877ce085f469dd24be1a20ce9544692e23094650a991e5bd7ab7d3b575d5ef7
1549fa442fe75a79a6c9f598eb1396e9332878c73f8af9e8f9f0cc11a4b42245acbb421646d6181c8f7f602298042a37d8b57520a1d68d6
e3d473d5f1897e05db677c7ff6e260048255fdbe35fae42c791ea57ac0f2334e6ab5c650f59f3b27b1af30347314510a29fe19e20ac6e8e
eb1e84deb687d2dc3d5cf4b03dbe35d165e
''')

class Db():
    def __init__(self, tls):
        self.tls = tls

    def get_user_storage(self, dbid=0, name=''):
        name=name.encode()

        if len(name) > 0:
            name += b'\0'

        return parse_user_storage(self.tls.app(pack('<BHH', 0x4b, dbid, len(name)) + name))

    def get_user(self, dbid):
        return parse_user(self.tls.app(pack('<BHHH', 0x4a, dbid, 0, 0)))

    def lookup_user(self, identity):
        stg = self.get_user_storage(name='StgWindsor')
        data = identity_to_bytes(identity)
        
        rsp = self.tls.app(pack('<BHHH', 0x4a, 0, stg.dbid, len(data)) + data)
        rc, = unpack('<H', rsp[:2])

        if rc == 0x04b3:
            return None
        else:
            return parse_user(rsp)

    def del_record(self, dbid):
        assert_status(self.tls.app(pack('<BH', 0x48, dbid)))

    def new_record(self, parent, typ, storage, data):
        assert_status(self.tls.app(b'\x45'))
        assert_status(self.tls.app(wtf_hardcoded))
        rsp = self.tls.app(pack('<BHHHH', 0x47, parent, typ, storage, len(data)) + data)
        assert_status(rsp)
        recid, = unpack('<H', rsp[2:])
        self.flush_changes()
        return recid

    def new_user(self, identity):
        data = identity_to_bytes(identity)

        stg = self.get_user_storage(name='StgWindsor')
        rec = self.new_record(stg.dbid, 5, stg.dbid, data)
        return rec

    def new_finger(self, userid, template):
        stg = self.get_user_storage(name='StgWindsor')
        # We ask to create an object of type 0xb, 
        # but because of the magical `wtf_hardcoded` in the new_record() it ends up being 0x6
        rec = self.new_record(userid, 0xb, stg.dbid, template)
        return rec

    def flush_changes(self):
        assert_status(self.tls.app(b'\x1a'))

    def dump_all(self):
        stg = self.get_user_storage(name='StgWindsor')
        usrs = [self.get_user(u['dbid']) for u in stg.users]
        for u in usrs:
            print('%2d: User %s with %d fingers:' % (u.dbid, repr(u.identity), len(u.fingers)))
            for f in u.fingers:
                print('    %2d: %02x (WINBIO_FINGER_UNSPECIFIED_POS_%02d)' % (f['dbid'], f['subtype'], f['subtype'] - 0xf5 + 1))

