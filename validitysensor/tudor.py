import json
import logging
import os
import time
from binascii import hexlify, unhexlify
from hashlib import sha256, sha384
from struct import pack, pack_into

import usb.core as ucore
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from usb.core import USBError

from .db import Db, User, db
from .sensor import Sensor, sensor
from .tls import tls, hs_key
from .usb import usb, CancelledException

# Kensington VeriMark IT (Synaptics "Tudor"). Unlike the Prometheus sensors this
# reader takes ownership through a 0x93 command carrying the host key and then
# speaks AES-256-GCM TLS, so it needs its own bring-up instead of the flash based
# one in init.open_common().
VERIMARK_IT = (0x047d, 0x8054)

# The host key and the enrolled-finger map must survive reboots (the reader is
# paired to this key and re-pairing a fresh one wears its one-time-programmable
# memory), so they live under /var/lib rather than the runtime data dir.
data_dir = '/var/lib/python-validity/'
host_key_path = data_dir + 'host_key.pem'

# Constant part of the 0x93 request captured from the Windows driver. Only the
# host public key gets written into it (X at 0x04, Y at 0x48, little-endian).
take_ownership_body = unhexlify(
    '3f5f1700f034785215a99b8288ed111ee33722491aa2d9933d155679612eece967c02e2b000000000000000000000000000000000000000000000000000000000000000000000000911027e62eee3d4c10712a1a95de59c6acfd208d6806ea97cd4015a97dbf57030000000000000000000000000000000000000000000000000000000000000000000000000000'
)


def _find():
    return ucore.find(idVendor=VERIMARK_IT[0], idProduct=VERIMARK_IT[1])


def present():
    return _find() is not None


def _read_reply(dev, timeout=8000):
    try:
        reply = bytes(dev.read(0x81, 1 << 20, timeout=timeout))
    except USBError:
        return b''
    while True:
        try:
            chunk = bytes(dev.read(0x81, 1 << 20, timeout=150))
        except USBError:
            break
        if not chunk:
            break
        reply += chunk
    return reply


def _reopen():
    dev = _find()
    try:
        dev.reset()
    except USBError:
        pass
    for _ in range(20):
        time.sleep(0.4)
        if present():
            break
    time.sleep(0.8)
    dev = _find()
    dev.set_configuration()
    return dev


def _host_key():
    try:
        with open(host_key_path, 'rb') as f:
            return serialization.load_pem_private_key(f.read(), password=None)
    except (FileNotFoundError, ValueError):
        key = ec.generate_private_key(ec.SECP256R1())
        with open(host_key_path, 'wb') as f:
            f.write(
                key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                  serialization.NoEncryption()))
        os.chmod(host_key_path, 0o600)
        return key


def _build_take_ownership(priv):
    nums = priv.public_key().public_numbers()
    body = bytearray(take_ownership_body)
    body[0x04:0x24] = nums.x.to_bytes(0x20, 'little')
    body[0x48:0x68] = nums.y.to_bytes(0x20, 'little')
    signer = ec.derive_private_key(hs_key(), ec.SECP256R1())  # hardcoded Synaptics key
    sig = signer.sign(bytes(body), ec.ECDSA(hashes.SHA256()))
    payload = bytearray(401)
    payload[0] = 0x93
    payload[1:1 + len(body)] = body
    pack_into('<H', payload, 0x8f, len(sig))
    payload[0x91:0x91 + len(sig)] = sig
    return bytes(payload)


def _pair(dev, priv):
    dev.write(1, b'\x01')
    _read_reply(dev, 3000)
    dev.write(1, b'\x19')
    _read_reply(dev, 3000)
    dev.write(1, _build_take_ownership(priv))
    reply = _read_reply(dev, 10000)
    if reply[:2] != b'\x00\x00':
        raise Exception('Take-ownership (0x93) failed: %s' % hexlify(reply[:2]).decode())
    # Device static ECDH public key (little-endian) for the TLS key exchange.
    device_x = int.from_bytes(reply[0x196:0x1b6], 'little')
    device_y = int.from_bytes(reply[0x1da:0x1fa], 'little')
    return reply[2:2 + 400], device_x, device_y


def _configure_tls(priv, device_x, device_y):
    tls.usb = usb
    tls.priv_key = priv
    tls.ecdh_q = ec.EllipticCurvePublicNumbers(device_x, device_y, ec.SECP256R1()).public_key()
    tls.reset()
    # AES-256-GCM record layer with a mixed SHA256/SHA384 handshake, as captured.
    tls.gcm = True
    tls.prf_hash = sha384
    tls.handshake_hash = sha384()
    tls.cv_hash = sha256()  # CertificateVerify signs the SHA256 handshake hash
    tls.cv_prehash = hashes.SHA256()
    tls.fin_hash = tls.cv_hash  # Finished hashes that digest too, but with the SHA384 PRF
    tls.fin_prf = sha384


def _client_certificate(o93body):
    # Client Certificate = "4487" tag plus the device-signed 0x93 response body.
    inner = pack('>BH', 0, len(o93body)) * 2 + b'\x44\x87' + o93body
    return tls.with_neg_hdr(0x0b, inner)


def _handshake(o93body):
    rsp = usb.cmd(unhexlify('44000000') + tls.make_handshake(tls.make_client_hello()))
    tls.parse_tls_response(rsp)
    tls.make_keys()

    cert = _client_certificate(o93body)
    kex = tls.make_client_kex()
    verify = tls.make_cert_verify()
    msg = (unhexlify('44000000') + tls.make_handshake(cert + kex + verify) +
           tls.make_change_cipher_spec() + tls.make_handshake(tls.make_finish()))
    tls.parse_tls_response(usb.cmd(msg))

    if not (tls.secure_rx and tls.secure_tx):
        raise Exception('TLS handshake did not establish a secure channel')


def open_session():
    os.makedirs(data_dir, exist_ok=True)
    priv = _host_key()
    dev = _reopen()
    usb.dev = dev
    usb.dev.default_timeout = 10000

    o93body, device_x, device_y = _pair(dev, priv)
    logging.info('VeriMark IT paired')

    _configure_tls(priv, device_x, device_y)
    _handshake(o93body)
    logging.info('VeriMark IT secure channel established')
    _install_backend()


# ---------------------------------------------------------------------------
# On-chip enroll / identify / delete
# ---------------------------------------------------------------------------

enroll_max_touches = 40
event_timeout = 8000

# Capture-program / config frames (0x39), event-arm payloads (0x86) and
# capture-start bodies (0x80), captured verbatim from the Windows enroll.
capture_prog = unhexlify('00710200ffff000005050020000000000505000000000000'
                         'ffff000005050020000000000505000000000000'
                         'ffff000005050020000000000505000000000000')
capture_prog += b'\0' * (124 - len(capture_prog))
cfg_c = unhexlify(
    '00000000000000000000002000000000000000000000000000000000000000200000000000000000000000000000000000000020000000000000000000000000000000000000002000000000000000000000000000000000000000200000000000000000000000000000000000000020000000000000000000000000'
)
cfg_a = unhexlify(
    'e80300004b000000070100200101000000000000000000004b000000010000200000000000000000000000004b000000010100200000000000000000000000004b0000000100002000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'
)
cfg_final = unhexlify(
    'f4010000f4010000070500200000000005050000000000000000000000000020000000000000000000000000f401000000050020000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'
)
arm_06 = unhexlify('060000000000000000000000000000000600000000000000000000000000000000000000')
arm_04 = unhexlify('040000000000000000000000000000000400000000000000000000000000000000000000')
arm_00 = unhexlify('000000000000000000000000000000000000000000000000000000000000000004000000')
arm_01 = unhexlify('000000010000000000000000000000000000000100000000000000000000000000000000')
cap_start = unhexlify('0c000000010000000100000801010100')
cap_start_setup = unhexlify('14000000010000000100000801010100')
cap_start_id = unhexlify('14100000010000000100000801010100')
identify_cmd = unhexlify('99010000000000000000000000')
progress_marker = unhexlify('3c000000')

# On-chip store record from the Windows enroll. The firmware keeps it verbatim;
# only the template id at [17:33] names the finger (the SID and trailing DPAPI
# blob are opaque). We swap in the freshly-enrolled id and track which identity
# and finger it belongs to host-side in TudorDb.
enroll_record = unhexlify(
    '00000000000000bb010000000010000000929ddec6a39d4a66f07d98d6c2edcbdc01004c000000030000001c0000000105000000000005150000006ff57d1e90b75cb01feceafce803000000000000000000000000000000000000000000000000000000000000000000000000000000000000020001000000f503004601000001000000d08c9ddf0115d1118c7a00c04fc297eb0100000008ca566ecdff3e4ea771db3c50daaac000000000020000000000106600000001000020000000feacf00c6ff07754dafecacd39796ff9321175e1348af6fa2483a9a6de3f692d000000000e80000000020000200000007d0eda6947522cab327848357db444b907f363450f6102df69d0926841fcdf6b70000000f1506641ffbf55598bdc839db87d9b871c81d1ac34d338dac8a4558a9d442a69661052c398e3bac277f9128fb4ee90cc6c83cd020daaa1c98112a43413bcae37fb355a45a3f63a87cd5730aa2a65bc90085b6f37d4b602583b4d2393f769627aff9af79094871dc7a99f1ca3f4e3e83340000000dde605f36aa30d3ce039fc7c8bcd11576b489debe6bc30de89870ae71b367a8ccade5074d97df7984b52ad042396a8e0a65921fa4ad0d938d49bd4de8a066df0'
)

tudor_db_path = data_dir + 'tudor-fingers.json'


class TudorDb(Db):
    """Host-side identity store mapping a user identity and finger subtype to the
    on-chip template id. The reader only matches biometrics and hands back a
    template id, so which user and finger each print belongs to is kept here.

    Instances come from the class swap in _install_backend, so the fields are set
    up there rather than in __init__."""
    def _ensure_loaded(self):
        if self._loaded:
            return
        try:
            with open(tudor_db_path) as f:
                self.users = json.load(f)
        except (FileNotFoundError, ValueError):
            self.users = []
        self._loaded = True

    def _save(self):
        with open(tudor_db_path, 'w') as f:
            json.dump(self.users, f)

    def _next_id(self):
        used = [u['dbid'] for u in self.users]
        used += [f['dbid'] for u in self.users for f in u['fingers']]
        return max(used) + 1 if used else 1

    def _as_user(self, u):
        user = User(u['dbid'], u['identity'])
        user.fingers = [{
            'dbid': f['dbid'],
            'subtype': f['subtype'],
            'storage': 0,
            'valueSize': 0
        } for f in u['fingers']]
        return user

    def lookup_user(self, identity):
        self._ensure_loaded()
        key = hexlify(identity.to_bytes()).decode()
        return next((self._as_user(u) for u in self.users if u['identity'] == key), None)

    def get_user(self, dbid):
        self._ensure_loaded()
        return next((self._as_user(u) for u in self.users if u['dbid'] == dbid), None)

    def new_user(self, identity):
        self._ensure_loaded()
        dbid = self._next_id()
        self.users.append({
            'dbid': dbid,
            'identity': hexlify(identity.to_bytes()).decode(),
            'fingers': []
        })
        self._save()
        return dbid

    def new_finger(self, userid, subtype, tuid):
        self._ensure_loaded()
        dbid = self._next_id()
        user = next(u for u in self.users if u['dbid'] == userid)
        user['fingers'].append({'dbid': dbid, 'subtype': subtype, 'tuid': hexlify(tuid).decode()})
        self._save()
        return dbid

    def find_by_tuid(self, tuid):
        self._ensure_loaded()
        key = hexlify(tuid).decode()
        for u in self.users:
            for f in u['fingers']:
                if f['tuid'] == key:
                    return u['dbid'], f['subtype']
        return None

    def del_record(self, dbid):
        self._ensure_loaded()
        user = next((u for u in self.users if u['dbid'] == dbid), None)
        if user is None:
            return
        for f in user['fingers']:
            sensor.delete_template(unhexlify(f['tuid']))
        self.users.remove(user)
        self._save()


class TudorSensor(Sensor):
    ectr = 0

    def open(self):
        usb.dev.default_timeout = event_timeout

    def cancel(self):
        usb.cancel = True

    def _cmd(self, payload, check=True, label=None):
        rsp = tls.app(payload)
        status = int.from_bytes(rsp[:2], 'little')
        if check and status != 0:
            raise Exception('%s failed: status 0x%04x' % (label or '0x%02x' % payload[0], status))
        return rsp

    def _config(self, frame):
        return self._cmd(b'\x39' + frame, label='config')

    def _db_list(self):
        rsp = self._cmd(unhexlify('9f02000000') + b'\xff' * 16, label='db_list')
        n = int.from_bytes(rsp[2:4], 'little')
        return [rsp[4 + i * 16:4 + i * 16 + 16] for i in range(n)]

    def _db_children(self, tuid):
        # 0x9f03 lists a record's children; the Windows driver issues it per
        # template while arming, so we replay it to match the capture.
        return self._cmd(b'\x9f\x03\x00\x00\x00' + tuid, check=False, label='db_children')

    def _arm(self, payload):
        rsp = self._cmd(b'\x86' + payload, label='arm')
        self.ectr = int.from_bytes(rsp[-2:], 'little')
        return rsp

    def _read_event(self, seq=None):
        if seq is None:
            seq = self.ectr
        rsp = self._cmd(b'\x87' + pack('<H', seq) + unhexlify('200001000000'),
                        check=False,
                        label='event')
        kind = hexlify(rsp[6:8]).decode() if len(rsp) >= 8 else '----'
        return kind, rsp

    def _drain_int(self):
        while True:
            try:
                usb.dev.read(0x83, 8, timeout=120)
            except USBError:
                return

    def _wait_finger(self, timeout_s=8):
        deadline = time.time() + timeout_s
        while time.time() < deadline:
            if usb.cancel:
                raise CancelledException()
            try:
                event = bytes(usb.dev.read(0x83, 8, timeout=600))
            except USBError:
                continue
            if event and event[0] == 2:
                return event
        return None

    @staticmethod
    def _parse_progress(rsp):
        i = rsp.find(progress_marker)
        if i < 0:
            return None, None, None
        bitmap = rsp[i + 4] if i + 4 < len(rsp) else None
        coverage = rsp[i + 6] if i + 6 < len(rsp) else None
        tuid = rsp[i - 16:i] if i >= 16 else b''
        return bitmap, coverage, tuid

    def _poll_event(self, seq=None, want=None, timeout_s=2.5):
        deadline = time.time() + timeout_s
        while time.time() < deadline:
            kind, rsp = self._read_event(seq=seq)
            if kind != '----' and (want is None or kind == want):
                return kind, rsp
            time.sleep(0.03)
        return '--', b''

    def _read_progress(self, timeout_s=2.5):
        rsp = b''
        deadline = time.time() + timeout_s
        while time.time() < deadline:
            rsp = self._cmd(unhexlify('9602000000'), check=False, label='progress')
            if rsp.find(progress_marker) >= 0:
                return rsp
            time.sleep(0.04)
        return rsp

    def _enroll_setup(self):
        self._cmd(unhexlify('820000000000000207'), label='opinfo')
        self._cmd(b'\x9e\x01', label='db_info')
        self._cmd(b'\x9e\x01', label='db_info')
        for tuid in self._db_list():
            self._db_children(tuid)
        self._config(cfg_c)
        self._cmd(b'\x19', label='startinfo')
        self._config(cfg_c)
        self._cmd(b'\x19', label='startinfo')
        # finger-less calibration cycle
        self._arm(arm_06)
        self._read_event()
        self._arm(arm_00)
        self._config(capture_prog)
        self._arm(arm_01)
        self._cmd(b'\x80' + cap_start_setup, label='capture_start')
        self._read_event(seq=0)
        self._config(cfg_c)
        self._arm(arm_00)
        self._cmd(b'\x81', check=False, label='trigger')
        self._cmd(identify_cmd, check=False, label='identify')
        self._config(cfg_a)
        self._cmd(b'\x96' + unhexlify('010000000000000000000000'), label='enroll_begin')

    def _capture_enroll(self, finger_timeout=8):
        self._drain_int()
        self._arm(arm_06)
        if self._wait_finger(finger_timeout) is None:
            return None
        # the sensor reports finger-down / image / capture-done asynchronously
        self._poll_event(want='0100')
        self._arm(arm_00)
        self._arm(arm_04)
        self._poll_event(want='0200')
        self._arm(arm_00)
        self._config(capture_prog)
        self._arm(arm_01)
        self._cmd(b'\x80' + cap_start, label='capture_start')
        self._poll_event(seq=0, want='1800', timeout_s=3)
        self._config(cfg_c)
        self._arm(arm_00)
        self._cmd(b'\x81', check=False, label='trigger')
        return self._parse_progress(self._read_progress())

    def _store_template(self, tuid):
        self._config(cfg_final)
        self._cmd(identify_cmd, check=False, label='identify')
        record = bytearray(enroll_record)
        record[17:33] = tuid
        return self._cmd(b'\x96\x03' + bytes(record), check=False, label='store')

    def _enroll_end(self):
        try:
            self._cmd(unhexlify('9604000000'), check=False, label='enroll_end')
            self._config(cfg_c)
        except USBError:
            pass

    def enroll(self, identity, subtype, update_cb):
        self.open()
        usb.cancel = False
        self._enroll_setup()
        tuid = None
        misses = 0
        try:
            for _ in range(enroll_max_touches):
                if usb.cancel:
                    raise CancelledException()
                result = self._capture_enroll()
                if result is None:
                    misses += 1
                    if misses >= 5:
                        break
                    update_cb(None, Exception('no finger detected'))
                    continue
                misses = 0
                bitmap, coverage, captured = result
                logging.debug('enroll progress 0x%02x coverage %s%%', bitmap or 0, coverage)
                update_cb(bitmap, None)
                if bitmap == 0x7f:
                    tuid = captured
                    self._store_template(tuid)
                    break
        finally:
            self._enroll_end()

        if tuid is None:
            raise Exception('Enrollment did not complete')

        user = db.lookup_user(identity)
        userid = user.dbid if user is not None else db.new_user(identity)
        return db.new_finger(userid, subtype, tuid)

    def _identify_setup(self):
        self._cmd(unhexlify('820000000000000207'), label='opinfo')
        self._cmd(b'\x9e\x01', label='db_info')
        for tuid in self._db_list():
            self._db_children(tuid)
        self._config(cfg_c)
        self._cmd(b'\x19', label='startinfo')
        # warm-up capture to arm interrupt-EP finger detection (stays in verify mode)
        self._arm(arm_06)
        self._read_event()
        self._arm(arm_00)
        self._config(capture_prog)
        self._arm(arm_01)
        self._cmd(b'\x80' + cap_start_setup, label='capture_start')
        self._read_event(seq=0)
        self._config(cfg_c)
        self._arm(arm_00)
        self._cmd(b'\x81', check=False, label='trigger')

    def _capture_verify(self, finger_timeout=8):
        self._drain_int()
        self._arm(arm_06)
        if self._wait_finger(finger_timeout) is None:
            return None
        self._poll_event(want='0200')
        self._arm(arm_00)
        self._config(capture_prog)
        self._arm(arm_01)
        self._cmd(b'\x80' + cap_start_id, label='capture_start')
        self._poll_event(seq=0, want='1800', timeout_s=3)
        self._config(cfg_c)
        self._arm(arm_00)
        self._cmd(b'\x81', check=False, label='trigger')
        rsp = self._cmd(identify_cmd, check=False, label='verdict')
        if rsp[:2] == b'\x00\x00' and len(rsp) >= 18 and rsp[2:18] != b'\x00' * 16:
            return rsp[2:18]
        return b''

    def identify(self, update_cb):
        self.open()
        usb.cancel = False
        self._identify_setup()
        while True:
            if usb.cancel:
                raise CancelledException()
            match = self._capture_verify()
            if match is None:
                update_cb(Exception('no finger detected'))
                continue
            break

        if not match:
            raise Exception('Finger not recognized')
        found = db.find_by_tuid(match)
        if found is None:
            raise Exception('Matched an unenrolled template %s' % hexlify(match).decode())
        userid, subtype = found
        return userid, subtype, match

    def delete_template(self, tuid):
        # a4 80 begin txn -> a0 02 resolve tuid to record locator (rsp[20:36])
        # -> a3 01 delete locator -> a4 81 commit txn
        self._cmd(unhexlify('a480'), check=False, label='txn_begin')
        info = self._cmd(unhexlify('a002000000') + tuid, check=False, label='object_info')
        locator = info[20:36]
        self._cmd(unhexlify('a301000000') + locator, check=False, label='delete')
        self._cmd(unhexlify('a481'), check=False, label='txn_commit')


def _install_backend():
    # dbus-service binds the sensor/db singletons at import time, before the
    # device is known, so once the VeriMark IT is up we specialise them in place
    # (it is a different device family) rather than swapping the bound globals.
    sensor.__class__ = TudorSensor
    db.__class__ = TudorDb
    db.users = []
    db._loaded = False
    sensor.open()
