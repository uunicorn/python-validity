"""Pairing for the flashless sensors (06cb:00a8).

init_flash() formats the flash, gets the ECDH parameters back from command 0x50 and
leaves the keys in flash for later boots. A flashless sensor keeps its side of the
pairing across reboots, but the host has to keep the rest: the device certificate from
0x4f, the ECDH blob from 0x50 and our PSK-encrypted private key, i.e. the three blobs
make_tls_flash_block() would write to flash. First pairing, as the Windows driver does it
(issue #179):

    0x06 + pairing module     (dll_tables)
    0x4f + our certificate -> device certificate
    0x01                      RomInfo again
    0x50                   -> ECDH params
    0x1a
    TLS handshake

Every later session goes straight to the TLS handshake with the stored blobs.
"""

import logging
import os
from struct import pack, unpack

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec

from . import dll_tables
from .init_data_dir import PYTHON_VALIDITY_STATE_DIR, init_state_dir
from .init_flash import encrypt_key, make_cert, with_hdr
from .tls import tls
from .usb import usb

pairing_path = PYTHON_VALIDITY_STATE_DIR + '06cb_00a8-pairing.bin'


class CommandFailed(Exception):
    def __init__(self, label: str, status: int):
        super().__init__('%s failed with status 0x%04x' % (label, status))
        self.status = status


def _cmd(send, payload: bytes, label: str) -> bytes:
    rsp = send(payload)
    status, = unpack('<H', rsp[:2])
    logging.debug('%s -> status 0x%04x, %d bytes' % (label, status, len(rsp)))
    if status != 0:
        raise CommandFailed(label, status)
    return rsp


def save_pairing():
    init_state_dir()
    fd = os.open(pairing_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, 'wb') as f:
        for b in (tls.tls_cert, tls.ecdh_blob, tls.priv_blob):
            f.write(pack('<L', len(b)) + b)


def load_pairing():
    """The stored (cert, ecdh_blob, priv_blob), or None."""
    try:
        with open(pairing_path, 'rb') as f:
            data = f.read()
    except FileNotFoundError:
        return None
    blobs = []
    while len(data) >= 4:
        l, = unpack('<L', data[:4])
        blobs.append(data[4:4 + l])
        data = data[4 + l:]
    if len(blobs) != 3:
        logging.warning('Ignoring malformed %s' % pairing_path)
        return None
    return blobs


def resume_pairing() -> bool:
    """TLS handshake with the stored pairing. False if there's no usable stored pairing.

    Raises if the handshake itself fails; the device must then be reset before pairing."""
    blobs = load_pairing()
    if blobs is None:
        return False
    cert, ecdh_blob, priv_blob = blobs
    try:
        tls.handle_cert(cert)
        tls.handle_ecdh(ecdh_blob)
        tls.handle_priv(priv_blob)
    except Exception as e:
        logging.warning('Stored pairing is unusable (%s), pairing again' % e)
        tls.reset()
        return False
    tls.open()
    logging.info('TLS session resumed from the stored pairing')
    return True


def pair():
    """Pair from scratch. Leaves a TLS session open and the pairing stored."""
    client_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    pub = client_key.public_key().public_numbers()
    priv = client_key.private_numbers().private_value

    _cmd(usb.cmd, b'\x06' + dll_tables.module('pair'), '0x06 (pairing module)')

    rsp = _cmd(tls.cmd, b'\x4f\0\0\0\0' + with_hdr(5, make_cert(pub)), '0x4f (certificate)')
    body = rsp[2:]
    l, = unpack('<L', body[:4])
    tls.handle_cert(body[4:4 + l])

    # The Windows driver reads RomInfo again here; loading the module changed one byte of it.
    usb.cmd(b'\x01')

    rsp = _cmd(usb.cmd, b'\x50', '0x50 (ECDH params)')
    body = rsp[2:]
    l, = unpack('<L', body[:4])
    if l != len(body):
        raise Exception('0x50 reply length mismatch: header says %d, got %d' % (l, len(body)))
    ecdh_blob = body[-400:]

    _cmd(usb.cmd, b'\x1a', '0x1a')

    tls.handle_ecdh(ecdh_blob)  # throws InvalidSignature
    tls.handle_priv(encrypt_key(priv, pub))
    tls.open()
    logging.info('Paired, TLS session established')
    save_pairing()
