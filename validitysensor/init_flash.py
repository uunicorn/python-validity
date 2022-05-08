import hmac
import logging
import os
import typing
from binascii import unhexlify
from hashlib import sha256
from struct import pack, unpack

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from .blobs import reset_blob
from .flash import write_flash, erase_flash, call_cleanups, PartitionInfo, get_flash_info, FlashInfo
from .hw_tables import FlashIcInfo
from .sensor import reboot, RomInfo
from .tls import tls, hs_key, crt_hardcoded
from .usb import usb
from .util import assert_status, unhex

# FIXME!! this table is for 0092, don't merge as-is!
flash_layout_hardcoded = [
    #             id  typ access  offset       size
    #                     lvl
    PartitionInfo(1, 4, 7,    0x00001000, 0x00001000), # cert store
    PartitionInfo(2, 1, 2,    0x00002000, 0x00055000), # xpfwext
    PartitionInfo(6, 6, 3,    0x00057000, 0x00008000), # calibration data
    PartitionInfo(3, 2, 0x17, 0x0005f000, 0x0004f000), # 
    PartitionInfo(4, 3, 5,    0x000ae000, 0x00052000), # template database
]

partition_signature = unhex('''
d6b3f8c9307d0e6de3676178c18b80203fd5126ba026216c14e7e9d097a185c06728a4c0b4dcb44c8160c572672a5c3019fdf02c2143c01
d6da176e8857ca0dd4524e0e79126aaf6d90c3de3b2d50156eaff87c7e92ffb770516959fa2f0d8aad0249cc8d8365ec0c2d0548d220dcc
4413e5b4844eb69ac05997a6cf32ddf6b6ee8f8ee50c6534c1fdc7c65618957bb74b97c7f49a56120f95f2793d9c2775ee4519cd7005ad6
b46d1791a8758a89e4530529a28084a002c1bf55a81f6b710185c096d16950ae2dc6da0c16dd03b6fd19354c317ce3bf828c755c6e887d0
61feae643bb80437f2654d940dfea278ac6611c9df3d04e0d107fb7f78a667417bb1
''')

crypto_backend = default_backend()


def get_partition_signature():
    if usb.usb_dev().idVendor == 0x138a:
        if usb.usb_dev().idProduct == 0x0090:
            return b''

    return partition_signature


def with_hdr(id: int, buf: bytes):
    return pack('<HH', id, len(buf)) + buf


def encrypt_key(client_private, client_public):
    x = unhexlify('%064x' % client_public.x)[::-1]
    y = unhexlify('%064x' % client_public.y)[::-1]
    d = unhexlify('%064x' % client_private)[::-1]

    m = x + y + d
    l = 16 - (len(m) % 16)
    m = m + bytes([l]) * l

    iv = os.urandom(0x10)
    cipher = Cipher(algorithms.AES(tls.psk_encryption_key), modes.CBC(iv), backend=crypto_backend)
    encryptor = cipher.encryptor()
    c = iv + encryptor.update(m) + encryptor.finalize()

    sig = hmac.new(tls.psk_validation_key, c, sha256).digest()
    return b'\x02' + c + sig


def make_cert(client_public):
    msg = (pack('<LL', 0x17, 0x20) + unhexlify('%064x' % client_public.x)[::-1] + (b'\0' * 0x24) +
           unhexlify('%064x' % client_public.y)[::-1] + (b'\0' * 0x4c))
    pk = ec.derive_private_key(hs_key(), ec.SECP256R1(), backend=crypto_backend)
    s = pk.sign(msg, ec.ECDSA(hashes.SHA256()))
    s = pack('<L', len(s)) + s
    msg = msg + s
    msg += b'\0' * (444 - len(msg))  # FIXME not sure this math is right
    return msg


def serialize_flash_params(ic: FlashIcInfo):
    return pack('<LLxxBx', ic.size, ic.secror_size, ic.sector_erase_cmd)


def serialize_partition(p: PartitionInfo):
    b = pack('<BBHLL', p.id, p.type, p.access_lvl, p.offset, p.size)
    b = b + b'\0' * 4 + sha256(b).digest()
    return b


def partition_flash(info: FlashInfo, layout: typing.List[PartitionInfo], client_public):
    logging.info('Detected Flash IC: %s, %d bytes' % (info.ic.name, info.ic.size))

    cmd = unhex('4f 0000 0000')
    cmd += with_hdr(0, serialize_flash_params(info.ic))
    cmd += with_hdr(1,
                    b''.join([serialize_partition(p) for p in layout]) + get_partition_signature())
    cmd += with_hdr(5, make_cert(client_public))
    cmd += with_hdr(3, crt_hardcoded)
    rsp = tls.cmd(cmd)
    assert_status(rsp)
    rsp = rsp[2:]
    crt_len, rsp = rsp[:4], rsp[4:]
    crt_len, = unpack('<L', crt_len)
    tls.handle_cert(rsp[:crt_len])
    rsp = rsp[crt_len:]
    # ^ TODO - figure out what the rest of rsp means


def init_flash():
    info = get_flash_info()

    if len(info.partitions) > 0:
        logging.info('Flash has %d partitions.' % len(info.partitions))
        return
    else:
        logging.info('Flash was not initialized yet. Formatting...')

    assert_status(usb.cmd(reset_blob))

    skey = ec.generate_private_key(ec.SECP256R1(), crypto_backend)
    snums = skey.private_numbers()
    client_private = snums.private_value
    client_public = snums.public_numbers

    partition_flash(info, flash_layout_hardcoded, client_public)

    RomInfo.get()
    # ^ TODO: use the firmware version which to lookup pubkey for server cert validation

    try:
        rsp = usb.cmd(unhex('50'))
        assert_status(rsp)
    finally:
        call_cleanups()

    rsp = rsp[2:]
    l, = unpack('<L', rsp[:4])

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
    erase_flash(3)
    erase_flash(6)
    erase_flash(4)

    # Persist certs and keys on cert partition.
    write_flash(1, 0, tls.make_tls_flash())

    # Reboot.
    # The device will disconnect and our service will be started by udev as soon as it is connected again.
    reboot()
