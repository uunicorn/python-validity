
from tls97 import tls, psk_encryption_key, psk_validation_key, hs_key, crt_hardcoded
from hashlib import sha256
import hmac
from struct import pack, unpack
from binascii import hexlify, unhexlify
from usb97 import usb
from flash import write_flash, erase_flash, flush_changes, PartitionInfo, get_flash_info
from sensor import reboot
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from fastecdsa.encoding.der import DEREncoder
from fastecdsa.curve import P256
from fastecdsa.ecdsa import sign
from fastecdsa.point import Point
from fastecdsa.keys import gen_private_key, get_public_key
from util import assert_status, unhex
from blobs import reset_blob

flash_layout_hardcoded=[
    #             id  type  access  offset       size
    #                       lvl                       
    PartitionInfo(1,  4,    7,      0x00001000,  0x00001000), # cert store
   #PartitionInfo(2,  1,    2,      0x00002000,  0x0003e000), # xpfwext
    PartitionInfo(2,  1,    7,      0x00002000,  0x0003e000), # xpfwext
    PartitionInfo(5,  5,    3,      0x00040000,  0x00008000), # ???
    PartitionInfo(6,  6,    3,      0x00048000,  0x00008000), # calibration data
    PartitionInfo(4,  3,    5,      0x00050000,  0x00030000), # template database
]


def with_hdr(id, buf):
    return pack('<HH', id, len(buf)) + buf

client_private = gen_private_key(P256)
client_public = get_public_key(client_private, P256)

def encrypt_key():
    x = unhexlify('%064x' % client_public.x)[::-1]
    y = unhexlify('%064x' % client_public.y)[::-1]
    d = unhexlify('%064x' % client_private)[::-1]

    m = x+y+d
    l = 16 - (len(m) % 16)
    m = m + bytes([l])*l

    iv = get_random_bytes(AES.block_size)
    aes = AES.new(psk_encryption_key, AES.MODE_CBC, iv)
    c = iv + aes.encrypt(m)
    sig = hmac.new(psk_validation_key, c, sha256).digest()
    return b'\x02' + c + sig
    
tls.handle_priv(encrypt_key())


def make_cert():
    msg=(pack('<LL', 0x17, 0x20) +
            unhexlify('%064x' % client_public.x)[::-1] +
            (b'\0'*0x24) +
            unhexlify('%064x' % client_public.y)[::-1] +
            (b'\0'*0x4c))
    s=sign(msg, hs_key())
    s=DEREncoder().encode_signature(s[0], s[1])
    s=pack('<L', len(s)) + s
    msg = msg + s
    msg += b'\0'*(444 - len(msg)) # not sure this math is right
    return msg

def serialize_flash_params(ic):
    return pack('<LLxxBx', ic.size, ic.secror_size, ic.sector_erase_cmd)

def serialize_partition(p):
    b = pack('<BBHLL', p.id, p.type, p.access_lvl, p.offset, p.size)
    b = b + b'\0'*4 + sha256(b).digest()
    return b

def partition_flash(layout):
    info = get_flash_info()

    print('Detected Flash IC: %s, %d bytes' % (info.ic.name, info.ic.size))

    if len(info.partitions) > 0:
        raise Exception('Flash is already partitioned')

    cmd = unhex('4f 0000 0000')
    cmd += with_hdr(0, serialize_flash_params(info.ic)) 
    cmd += with_hdr(1, b''.join([serialize_partition(p) for p in layout]))
    cmd += with_hdr(5, make_cert())
    cmd += with_hdr(3, crt_hardcoded)
    rsp = tls.cmd(cmd)
    assert_status(rsp)
    rsp = rsp[2:]
    crt_len, rsp=rsp[:4], rsp[4:]
    crt_len, = unpack('<L', crt_len)
    tls.handle_cert(rsp[:crt_len])
    # ^ TODO - validate cert
    rsp = rsp[crt_len:]
    # ^ TODO - figure out what the rest of rsp means

#usb.trace_enabled=True
#tls.trace_enabled=True

usb.open()
assert_status(usb.cmd(reset_blob))

partition_flash(flash_layout_hardcoded)

rsp=usb.cmd(unhex('01'))
assert_status(rsp)
# ^ get device info, contains firmware version which is needed to lookup pubkey for server cert validation

rsp=usb.cmd(unhex('50'))
# ^ TODO validate response
# It should be signed by the firmware private key. 
# The corresponding pub key is hardcoded for each fw revision in the synaWudfBioUsb.dll.
# for my device it is: x=f727653b4e16ce0665a6894d7f3a30d7d0a0be310d1292a743671fdf69f6a8d3,
#                      y=a85538f8b6bec50d6eef8bd5f4d07a886243c58b2393948df761a84721a6ca94
assert_status(rsp)
rsp=rsp[2:]
l,=unpack('<L', rsp[:4])
tls.handle_ecdh(rsp[l-400:]) # not sure offsets are calculated this way

flush_changes()

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
