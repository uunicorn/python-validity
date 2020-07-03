
from .tls import tls, hs_key, crt_hardcoded
from hashlib import sha256
import hmac
from struct import pack, unpack
from binascii import hexlify, unhexlify
from .usb import usb
from .flash import write_flash, erase_flash, flush_changes, PartitionInfo, get_flash_info
from .sensor import reboot
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from fastecdsa.encoding.der import DEREncoder
from fastecdsa.curve import P256
from fastecdsa.ecdsa import sign
from fastecdsa.keys import gen_private_key, get_public_key
from .util import assert_status, unhex
from .blobs import reset_blob

flash_layout_hardcoded=[
    #             id  type  access  offset       size
    #                       lvl                       
    PartitionInfo(1,  4,    7,      0x00001000,  0x00001000), # cert store
    PartitionInfo(2,  1,    2,      0x00002000,  0x0003e000), # xpfwext
    PartitionInfo(5,  5,    3,      0x00040000,  0x00008000), # ???
    PartitionInfo(6,  6,    3,      0x00048000,  0x00008000), # calibration data
    PartitionInfo(4,  3,    5,      0x00050000,  0x00080000), # template database
]

partition_signature=unhex('''
1db02a886b007e2b47263bb8fe30bd64a1f58bea7b25f1e1ba9ae09add7ecff36333f8198339cdd713f043633710a17bc7b3f418f1d8ff435a1bf47f065dffca
727109152217fce73bf2bf8e01a1641f6a24b0c492a6a3f10114057275846842b1c8b66bd6700738524d4471bca3315ba23bb832743220ad195b60558aa79a3e
deb2604834e2bb62e890b0ce405b3b8ef2fec2aab3e22bff23f89a58ff0dc015fece5d3ed3f5496ace879a92980aec9d85eb7e9df245eae03a41acfd4e7d1cb1
dbd0df42d534904de00b6389f68867646e9d7c3d0b1dffd74070b2d0f2049b9f1dc7b0c9651c59be3ea891674725e1f2f7a484a941615b80211105978369cf71
''')

def get_partition_signature():
    if usb.usb_dev().idVendor == 0x138a:
        if usb.usb_dev().idProduct == 0x0090:
            return b''
    
    return partition_signature


def with_hdr(id, buf):
    return pack('<HH', id, len(buf)) + buf

def encrypt_key(client_private, client_public):
    x = unhexlify('%064x' % client_public.x)[::-1]
    y = unhexlify('%064x' % client_public.y)[::-1]
    d = unhexlify('%064x' % client_private)[::-1]

    m = x+y+d
    l = 16 - (len(m) % 16)
    m = m + bytes([l])*l

    iv = get_random_bytes(AES.block_size)
    aes = AES.new(tls.psk_encryption_key, AES.MODE_CBC, iv)
    c = iv + aes.encrypt(m)
    sig = hmac.new(tls.psk_validation_key, c, sha256).digest()
    return b'\x02' + c + sig
    
def make_cert(client_public):
    msg=(pack('<LL', 0x17, 0x20) +
            unhexlify('%064x' % client_public.x)[::-1] +
            (b'\0'*0x24) +
            unhexlify('%064x' % client_public.y)[::-1] +
            (b'\0'*0x4c))
    s=sign(msg, hs_key())
    s=DEREncoder().encode_signature(s[0], s[1])
    s=pack('<L', len(s)) + s
    msg = msg + s
    msg += b'\0'*(444 - len(msg)) # FIXME not sure this math is right
    return msg

def serialize_flash_params(ic):
    return pack('<LLxxBx', ic.size, ic.secror_size, ic.sector_erase_cmd)

def serialize_partition(p):
    b = pack('<BBHLL', p.id, p.type, p.access_lvl, p.offset, p.size)
    b = b + b'\0'*4 + sha256(b).digest()
    return b

def partition_flash(layout, client_public):
    info = get_flash_info()

    print('Detected Flash IC: %s, %d bytes' % (info.ic.name, info.ic.size))

    if len(info.partitions) > 0:
        raise Exception('Flash is already partitioned')

    cmd = unhex('4f 0000 0000')
    cmd += with_hdr(0, serialize_flash_params(info.ic)) 
    cmd += with_hdr(1, b''.join([serialize_partition(p) for p in layout]) + get_partition_signature())
    cmd += with_hdr(5, make_cert(client_public))
    cmd += with_hdr(3, crt_hardcoded)
    rsp = tls.cmd(cmd)
    assert_status(rsp)
    rsp = rsp[2:]
    crt_len, rsp=rsp[:4], rsp[4:]
    crt_len, = unpack('<L', crt_len)
    tls.handle_cert(rsp[:crt_len])
    rsp = rsp[crt_len:]
    # ^ TODO - figure out what the rest of rsp means

def init_flash():
    assert_status(usb.cmd(reset_blob))

    client_private = gen_private_key(P256)
    client_public = get_public_key(client_private, P256)

    partition_flash(flash_layout_hardcoded, client_public)

    rsp=usb.cmd(unhex('01'))
    assert_status(rsp)
    # ^ get device info, contains firmware version which is needed to lookup pubkey for server cert validation

    rsp=usb.cmd(unhex('50'))
    assert_status(rsp)
    flush_changes()

    rsp=rsp[2:]
    l,=unpack('<L', rsp[:4])

    if len(rsp) != l:
        raise Exception('Length mismatch')

    zeroes, rsp = rsp[4:-400], rsp[-400:]

    if zeroes != b'\0' * len(zeroes):
        raise Exception('Expected zeroes')

    tls.handle_ecdh(rsp)
    tls.handle_priv(encrypt_key(client_private, client_public))
    tls.open()

    # Wipe newly created partitions clean
    erase_flash(1)
    erase_flash(2)
    erase_flash(5)
    erase_flash(6)
    erase_flash(4)

    # Persist certs and keys on cert partition.
    write_flash(1, 0, tls.makeTlsFlash())

    # Reboot
    reboot()
