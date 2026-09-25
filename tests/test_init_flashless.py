"""Flashless pairing and the session lifecycle, without hardware."""

import os
import stat
from struct import unpack

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec

from validitysensor import init, init_flashless
from validitysensor.init_flash import encrypt_key, make_cert, with_hdr
from validitysensor.tls import tls


def client_key():
    n = ec.generate_private_key(ec.SECP256R1(), default_backend()).private_numbers()
    return n.private_value, n.public_numbers


def test_0x4f_certificate_request_layout():
    _, pub = client_key()
    cert = make_cert(pub)
    # 184 bytes of certificate, a 4-byte signature length and the signature
    assert len(cert) == 444
    assert unpack('<LL', cert[:8]) == (0x17, 0x20)
    assert len(b'\x4f\0\0\0\0' + with_hdr(5, cert)) == 453


def test_encrypted_private_key_layout():
    priv, pub = client_key()
    blob = encrypt_key(priv, pub)
    # 0x02, IV, AES-CBC of x, y, d, HMAC-SHA256
    assert blob[0] == 2 and len(blob) == 1 + 16 + 112 + 32


def test_pairing_round_trips_and_is_private(state_dir, monkeypatch):
    monkeypatch.setattr(tls, 'tls_cert', b'cert' * 10, raising=False)
    monkeypatch.setattr(tls, 'ecdh_blob', b'\x01' * 400, raising=False)
    monkeypatch.setattr(tls, 'priv_blob', b'\x02' + b'k' * 96, raising=False)
    init_flashless.save_pairing()
    assert stat.S_IMODE(os.stat(init_flashless.pairing_path).st_mode) == 0o600
    assert init_flashless.load_pairing() == [b'cert' * 10, b'\x01' * 400, b'\x02' + b'k' * 96]


def test_resume_without_stored_pairing_sends_nothing(state_dir, monkeypatch):
    monkeypatch.setattr(tls, 'open', lambda: (_ for _ in ()).throw(AssertionError('sent')))
    assert init_flashless.resume_pairing() is False


def test_unusable_stored_pairing_is_ignored(state_dir, monkeypatch):
    with open(init_flashless.pairing_path, 'wb') as f:
        f.write(b'\x03\0\0\0abc' * 3)
    monkeypatch.setattr(tls, 'open', lambda: (_ for _ in ()).throw(AssertionError('sent')))
    assert init_flashless.resume_pairing() is False


class FakeUsb:
    def __init__(self, calls):
        self.calls = calls

    def address(self):
        return (1, 6)

    def close(self):
        self.calls.append('close')

    def wait_for_reboot(self, old):
        self.calls.append(('wait', old))
        return True


def close_with(monkeypatch, secure, app):
    calls = []
    monkeypatch.setattr(init, 'usb', FakeUsb(calls))
    monkeypatch.setattr(tls, 'secure_tx', secure, raising=False)
    monkeypatch.setattr(tls, 'secure_rx', secure, raising=False)
    monkeypatch.setattr(tls, 'app', app, raising=False)
    init.close_flashless()
    assert not tls.secure_tx
    return calls


def test_close_ends_the_session_with_0x05_and_waits_for_the_reboot(monkeypatch):
    sent = []
    calls = close_with(monkeypatch, True, lambda req: sent.append(req) or b'\0\0')
    assert sent == [b'\x05\x02\x00']
    assert calls == ['close', ('wait', (1, 6))]


def test_close_without_tls_sends_nothing(monkeypatch):
    calls = close_with(monkeypatch, False, lambda req: (_ for _ in ()).throw(AssertionError(req)))
    assert calls == ['close']


def test_close_on_a_dead_device_does_not_wait(monkeypatch):
    def gone(req):
        raise OSError(19, 'No such device')

    assert close_with(monkeypatch, True, gone) == ['close']
