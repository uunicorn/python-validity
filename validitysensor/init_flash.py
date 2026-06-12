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

flash_layout_hardcoded = [
    #             id  type  access  offset       size
    #                       lvl
    PartitionInfo(1, 4, 7, 0x00001000, 0x00001000),  # cert store
    PartitionInfo(2, 1, 2, 0x00002000, 0x0003e000),  # xpfwext
    PartitionInfo(5, 5, 3, 0x00040000, 0x00008000),  # ???
    PartitionInfo(6, 6, 3, 0x00048000, 0x00008000),  # calibration data
    PartitionInfo(4, 3, 5, 0x00050000, 0x00080000),  # template database
]

partition_signature = unhex('''
1db02a886b007e2b47263bb8fe30bd64a1f58bea7b25f1e1ba9ae09add7ecff36333f8198339cdd713f043633710a17bc7b3f418f1d8ff435a1bf47f065dffca
727109152217fce73bf2bf8e01a1641f6a24b0c492a6a3f10114057275846842b1c8b66bd6700738524d4471bca3315ba23bb832743220ad195b60558aa79a3e
deb2604834e2bb62e890b0ce405b3b8ef2fec2aab3e22bff23f89a58ff0dc015fece5d3ed3f5496ace879a92980aec9d85eb7e9df245eae03a41acfd4e7d1cb1
dbd0df42d534904de00b6389f68867646e9d7c3d0b1dffd74070b2d0f2049b9f1dc7b0c9651c59be3ea891674725e1f2f7a484a941615b80211105978369cf71
''')

flash_layout_hardcoded_0090 = [
    #             id  type  access  offset       size
    #                       lvl
    PartitionInfo(1, 4, 7, 0x00001000, 0x00001000),  # cert store
    PartitionInfo(2, 1, 2, 0x00002000, 0x0003e000),  # xpfwext
    PartitionInfo(5, 5, 3, 0x00040000, 0x00008000),  # ???
    PartitionInfo(6, 6, 3, 0x00048000, 0x00008000),  # calibration data
    PartitionInfo(4, 3, 5, 0x00050000, 0x00030000),  # template database
]

partition_signature_0090 = unhex('''
e44f7a80d6137794d330b5d026c328a73c907f3f653d411255b7c2f8b425d870a8a53c6630ca864b84590e3c6786f0d69be4bbab5736388f8527237a0a86bbce
7ced9450c4964709e89ac535aa00787158e0a8d9b1fb75f0f7ae53d4bd11abfcf5ee67a5a71e248a426b3aff4567048fa93de65939ccfbe3f31149a82c64fbfd
6a2a6cf748e1d9bd8562cf39b1a4b307b37be223317b1b817e364f2877d29d123731314aa627cbf234e0ea69a406a4735a03a45495023ef706bdb542c949d243
ac2c08c00abf43faa5528a0a8e49b02c507b01b6f1c9abffc669d8c84d7e4a714da32aade7928eca9698b82bee6b72c642c9add80bbd7ccc4121b80220d52b8a
''')

# 06cb:00a2 uses the same partition layout as the generic flash_layout_hardcoded
# (byte-exact), but the partition table is signed with a device-model-specific
# key, so it needs its own signature. Extracted byte-exact from the Windows
# driver's reset/format capture (1780409730-usb.txt, 0x4f command).
partition_signature_a2 = unhex('''
f52c94d3a340cd3d166516582be27d2c6f497fcf4f511b23f70f86927d48004330e4f17f3d1231fd8a0c9ff712c63759b8933a15cd7046f86c0b75d95fd54e93
ff9e174f837eb643922d9c7bd5261f9139e40ca53e2a9735f7d472047c5eca6b463e2d1e42a147e54943e7cceba15b7f8452548a6b7f453336a3dbed6194f3a7
705618132c3775f5906fe1baf4f87245865ae3cbe97c7a41858e87488ccd26077de5e3869b2ff22cf213377575a7a4dc5bc202bbb3539da9593df1d5616309ce
f84b3f45e1a4f2c3c4b45e856bb0eef652d916539b944da210e78537f9cb8d41b949fddb1af6ac8226b6e5763b3d570e901fa0f96d21de915fec1f945146a362
''')

crypto_backend = default_backend()


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


def partition_flash(info: FlashInfo, layout: typing.List[PartitionInfo], signature, client_public):
    logging.info('Detected Flash IC: %s, %d bytes' % (info.ic.name, info.ic.size))

    cmd = unhex('4f 0000 0000')
    cmd += with_hdr(0, serialize_flash_params(info.ic))
    cmd += with_hdr(1,
                    b''.join([serialize_partition(p) for p in layout]) + signature)
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

    layout = flash_layout_hardcoded
    signature = partition_signature

    if usb.usb_dev().idVendor == 0x138a:
        if usb.usb_dev().idProduct == 0x0090:
            layout = flash_layout_hardcoded_0090
            signature = partition_signature_0090
    elif usb.usb_dev().idVendor == 0x06cb:
        if usb.usb_dev().idProduct == 0x00a2:
            # same layout as generic, but a2-specific table signature
            signature = partition_signature_a2

    partition_flash(info, layout, signature, client_public)

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
    erase_flash(5)
    erase_flash(6)
    erase_flash(4)

    # Persist certs and keys on cert partition.
    write_flash(1, 0, tls.make_tls_flash())

    # Reboot.
    # The device will disconnect and our service will be started by udev as soon as it is connected again.
    reboot()
