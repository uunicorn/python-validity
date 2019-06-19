
from prototype import *
from tls97 import hs_key
from hashlib import sha256
from fastecdsa.encoding.der import DEREncoder
from fastecdsa.curve import P256
from fastecdsa.ecdsa import verify
from fastecdsa.point import Point
from fastecdsa.keys import get_public_key

blob4f=unhex('''
4f0000000000000c000000100000100000000020000100f000010407000010000000100000000000009da
6bb3eb1d4d1641811b0a2402ba5010d6d0f2f7ffd8debc7e7e68c31473333020102000020000000e00300
00000000840acfea4e998b5302df52db54b7654b164a1057681149fcbb3ec7a559c80db20505030000000
40000800000000000005c70f7ccce2fc2d7620f69da63548fc392877c88393e9c45327a10c21d46267f06
0603000080040000800000000000005a5eeb284ee05ddae47ee27dc75fafaf09bc8b112a652bde4eab8af
c61f2df75040305000000050000000300000000000e828eaff826a0454f6a50f60a36d5014372aaaf2621
41e5ced9d0a0056907c20500bc011700000020000000ebfaf1f684cd4e4739e56588695ba19b515be4c16
f3e89bfe6b33f59b209a26b00000000000000000000000000000000000000000000000000000000000000
00000000003870b373e2a0c3b7b09c16cdb8bd5f04bfdfdd55583c67db236c5b522ad6b49000000000000
0000000000000000000000000000000000000000000000000000000000000000000000000000000000000
00000000000000000000000000000000000000000000000000000000460000003044022036a452cef79a1
f146ca26dcf06eb58b333f95fab2d49eb89abbcb07c39dbe4c602200dc95d991f7f89e66ad8ee546619dc
4262617fb813e6e53f4333bbe21fe705d3000000000000000000000000000000000000000000000000000
0000000000000000000000000000000000000000000000000000000000000000000000000000000000000
0000000000000000000000000000000000000000000000000000000000000000000000000000000000000
0000000000000000000000000000000000000000000000000000000000000000000000000000000000000
0000000000000000000000000000000000000000000000000000000000000000000300a40117000000000
1000001000000fcffffffffffffffffffffff00000000000000000000000001000000ffffffff00000000
00000000000000000000000000000000000000000000000000000000000000004b60d2273e3cce3bf6b05
3ccb0061d65bc86987655bdebb3e7933aaad835c65a000000000000000000000000000000000000000000
00000000000000000000000000000096c298d84539a1f4a033eb2d817d0377f240a463e5e6bcf847422ce
1f2d1176b000000000000000000000000000000000000000000000000000000000000000000000000f551
bf376840b6cbce5e316b5733ce2b169e0f7c4aebe78e9b7f1afee242e34f0000000000000000000000000
00000000000000000000000000000000000000000000000512563fcc2cab9f3849e17a7adfae6bcffffff
ffffffffff00000000ffffffff00000000000000000000000000000000000000000000000000000000000
0000000000000ffffffffffffffffffffffff00000000000000000000000001000000ffffffff00000000
0000000000000000000000000000000000000000000000000000000000000000
''')

#skip 4f 0000 0000
blob4f=blob4f[5:]

while len(blob4f) > 0:
    hdr, blob4f = blob4f[:4], blob4f[4:]
    id, l = unpack('<HH', hdr)
    p, blob4f = blob4f[:l], blob4f[l:]
    print('block %04x: %s' % (id, hexlify(p).decode()))

    if id == 1:
        while len(p) > 0:
            d, align, hsh, p = p[:12], p[12:12+4], p[12+4:12+4+32], p[12+4+32:]
            if align != b'\0' * 4:
                raise Exception('align should be blank')
            m=sha256()
            m.update(d)
            if m.digest() != hsh:
                raise Exception('Hash mismatch')

            print('block 1, blob: %s' % hexlify(d).decode())
    elif id == 5:
        hdr, p = p[:4+4], p[4+4:]

        magic, keysz = unpack('<LL', hdr)

        if magic != 0x17:
            raise Exception('Unexpected magic')

        if keysz != 0x20:
            raise Exception('Unexpected key size')

        x, p = p[:0x20], p[0x20:]
        x=int(hexlify(x[::-1]).decode(), 16)
        print('block 5, x=%x' % x)
        
        nulls, p = p[:0x24], p[0x24:]
        if nulls != b'\0' * len(nulls):
            raise Exception('Nulls expected')

        y, p = p[:0x20], p[0x20:]
        y=int(hexlify(y[::-1]).decode(), 16)
        print('block 5, y=%x' % y)

        if not P256.is_point_on_curve( (x, y) ):
            raise Exception('pub key point is not on curve')

        nulls, p = p[:0x4c], p[0x4c:]
        if nulls != b'\0' * len(nulls):
            raise Exception('Nulls expected')

        ssz, p = p[:4], p[4:]
        ssz, = unpack('<L', ssz)
        signature, nulls = p[:ssz], p[ssz:]

        if nulls != b'\0' * len(nulls):
            raise Exception('Nulls expected')

        signature = DEREncoder().decode_signature(signature)
        msg=(pack('<LL', 0x17, 0x20) +
            unhexlify('%064x' % x)[::-1] +
            (b'\0'*0x24) +
            unhexlify('%064x' % y)[::-1] +
            (b'\0'*0x4c))
        
        pub=get_public_key(hs_key(), P256)

        if not verify(signature, msg, pub):
            raise Exception('Signature validation failed')

