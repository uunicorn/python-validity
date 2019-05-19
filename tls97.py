import re
import hmac
import sys
from hashlib import sha256, md5, sha1
from binascii import *
from struct import pack, unpack
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from fastecdsa.curve import P256
from fastecdsa.point import Point
from fastecdsa.keys import gen_private_key, get_public_key
from fastecdsa.ecdsa import sign
from fastecdsa.encoding.der import DEREncoder


# Info about the host computer
product_name, serial_number='VirtualBox', '0'

hw_key=b'GWK' + \
    bytes(product_name, 'ascii') + b'\0' + \
    bytes(serial_number, 'ascii') + b'\0'

password_hardcoded=unhexlify('717cd72d0962bc4a2846138dbb2c24192512a76407065f383846139d4bec2033')
gwk_sign_hardcoded=unhexlify('47574b5f5349474e3a4c76b76a97981d1274247e166610e77f4d9c9d07d3c728e532916bdd28b454')

def hmac2(key, msg):
    p1=hmac.new(key, msg, sha256).digest()
    p2=hmac.new(key, p1+msg, sha256).digest()
    return p2

# pre-TLS keys
psk_encryption_key=hmac2(password_hardcoded, hw_key)
psk_validation_key=hmac2(psk_encryption_key, gwk_sign_hardcoded)

def with_2bytes_size(chunk):
    return pack('>H', len(chunk)) + chunk

def with_3bytes_size(chunk):
    return pack('>BH', len(chunk) >> 16, len(chunk)) + chunk

def with_1byte_size(chunk):
    return pack('>B', len(chunk)) + chunk

def to_bytes(n):
    b=b''
    while n:
        b += (n & 0xff).to_bytes(1, 'big')
        n >>= 8

    return b

def pad(b):
    l = 16 - (len(b) % 16)
    return b + bytes([l-1])*l

def unpad(b):
    return b[:-1-b[-1]]

def prf(secret, seed, length):
    n = (length + 0x20 - 1) // 0x20
    
    res = b''
    a = hmac.new(secret, seed, sha256).digest()

    while n > 0:
        res += hmac.new(secret, a+seed, sha256).digest()
        a = hmac.new(secret, a, sha256).digest()
        n -= 1

    return res[:length]

    
# TODO assert the right state transitions
class Tls():
    
    def __init__(self, usb):
        self.usb = usb
        self.trace_enabled = False

    def open(self):
        self.parse40(self.usb.cmd(unhexlify('40010100000000000000100000')))

        self.secure_rx = False
        self.secure_tx = False
        self.handshake_hash = sha256()

        rsp=self.usb.cmd(unhexlify('44000000') + self.make_handshake(self.make_client_hello()))
        self.parse_tls_response(rsp)

        self.make_keys()

        rsp=self.usb.cmd(
            unhexlify('44000000') +     
            self.make_handshake(
                    self.make_certs() + 
                    self.make_client_kex() + 
                    self.make_cert_verify()) +
            self.make_change_cipher_spec() +
            self.make_handshake(self.make_finish()))

        self.parse_tls_response(rsp)

    def trace(self, s):
        if self.trace_enabled:
            print(s)

    def app(self, b):
        return self.parse_tls_response(self.usb.cmd(self.make_app_data(b)))

    def update_neg(self, b):
        self.handshake_hash.update(b)

    def make_keys(self):
        #self.session_private=0x2E38AFE3D563398E5962D2CDEA7FE16D3CFEA36656A9DEC412C648EE3A232D21
        self.session_private = gen_private_key(P256)
        self.session_public = get_public_key(self.session_private, P256)

        pre_master_secret = self.session_private*self.ecdh_q
        pre_master_secret = pre_master_secret.x
        pre_master_secret = to_bytes(pre_master_secret)[::-1]

        seed = self.client_random + self.server_random
        self.master_secret = prf(pre_master_secret, b'master secret'+seed, 0x30)

        key_block = prf(self.master_secret, b'key expansion'+seed, 0x120)
        self.sign_key = key_block[0x00:0x20]
        self.validation_key = key_block[0x20:0x20+0x20]
        self.encryption_key = key_block[0x40:0x40+0x20]
        self.decryption_key = key_block[0x60:0x60+0x20]

    def decrypt(self, c):
        iv, c = c[:0x10], c[0x10:]
        aes=AES.new(self.decryption_key, AES.MODE_CBC, iv)
        m=aes.decrypt(c)
        m=unpad(m)
        return m

    def encrypt(self, b):
        #iv = unhexlify('454849acdd075174d6b9e713a957c2e7')
        iv = get_random_bytes(0x10)
        aes=AES.new(self.encryption_key, AES.MODE_CBC, iv)
        b=pad(b)
        c=aes.encrypt(b)
        return iv + c

    def validate(self, t, b):
        b, hs = b[:-0x20], b[-0x20:]

        hdr = pack('>BBBH', t, 3, 3, len(b))
        sig=hmac.new(self.validation_key, hdr+b, sha256).digest()

        if sig != hs:
            raise Exception('Packet signature validation check failed')

        self.trace('<tls< %02x: %s' % (t, hexlify(b).decode()))
        return b
        
    def sign(self, t, b):
        self.trace('>tls> %02x: %s' % (t, hexlify(b).decode()))

        hdr = pack('>BBBH', t, 3, 3, len(b))
        sig=hmac.new(self.sign_key, hdr+b, sha256).digest()
        return b + sig

    def make_finish(self):
        self.secure_tx = True
        hs_hash = self.handshake_hash.copy().digest()
        verify_data = prf(self.master_secret, b'client finished'+hs_hash, 0xc)
        return b'\x14' + with_3bytes_size(verify_data)

    def make_change_cipher_spec(self):
        return unhexlify('140303000101')

    def make_certs(self):
        cert = self.tls_cert
        cert = unhexlify('ac16') + cert # what's this?
        cert = pack('>BH', 0, len(self.tls_cert)) + cert # this seems to violate the standard (should be len(cert))
        cert = pack('>BH', 0, len(self.tls_cert)) + cert # same
        return self.with_neg_hdr(0x0b, cert)

    def with_neg_hdr(self, t, b):
        b = pack('>B', t) + with_3bytes_size(b)
        self.update_neg(b)
        return b

    def make_client_kex(self):
        b = b'\x04' + to_bytes(self.session_public.x)[::-1] + to_bytes(self.session_public.y)[::-1]
        return self.with_neg_hdr(0x10, b)

    def make_cert_verify(self):
        buf=self.handshake_hash.copy().digest()
        s=sign(hexlify(buf).decode(), self.priv_key, prehashed=True)
        b=DEREncoder().encode_signature(s[0], s[1])
        return self.with_neg_hdr(0x0f, b)

    def handle_server_hello(self, p):
        if p[:2] != unhexlify('0303'):
            raise Exception('unexpected TLS version %s' % hexlify(p[:2]).decode())

        p = p[2:]

        self.server_random, p = p[:0x20], p[0x20:]
        l = p[0]
        self.server_sessid, p = p[1:1+l], p[1+l:]

        (suite,), p = unpack('>H', p[:2]), p[2:]

        if suite != 0xc005:
            raise Exception('Server accepted unsupported cipher suite %04x' % suite)

        if p[0] != 0:
            raise Exception('Server selected to enable compression, which we don''t support %02x' % p[0])

        p = p[1:]

        if p != b'':
            raise Exception('Not expecting any more data')

    def handle_cert_req(self, p):
        (sign_and_hash_algo,), p = unpack('>H', p[:2]), p[2:]
        if sign_and_hash_algo != 0x140:
            raise Exception('Server requested a cert with an unsupported sign and hash algo combination %04x' % sign_and_hash_algo)

        (l,), p = unpack('>H', p[:2]), p[2:]
        if l != 0:
            raise Exception('Server requested a cert with non-empty list of CAs')

        if p != b'':
            raise Exception('Not expecting any more data')

    def handle_server_hello_done(self, p):
        if p != b'':
            raise Exeception('Not expecting any body for "server hello done" pkt: %s' % hexlify(p).decode())

    def handle_finish(self, b):
        hs_hash = self.handshake_hash.copy().digest()
        verify_data = prf(self.master_secret, b'server finished'+hs_hash, 0xc)
        if verify_data != b:
            raise Exception('Final handshake check failed')

    def handle_app_data(self, b):
        if not self.secure_rx:
            raise Exception('App payload before secure connection established')

        return self.validate(0x17, self.decrypt(b))

    def handle_handshake(self, handshake):
        if self.secure_rx:
            handshake = self.validate(0x16, self.decrypt(handshake))

        while len(handshake) > 0:
            while len(handshake) < 4:
                handshake += b'\0'

            hdr, handshake = handshake[:4], handshake[4:]
            t, l12, l3 = unpack('>BHB', hdr)
            l = (l12 << 8) | l3
            p, handshake = handshake[:l], handshake[l:]

            if t == 2:
                self.handle_server_hello(p)
            elif t == 0xd:
                self.handle_cert_req(p)
            elif t == 0xe:
                self.handle_server_hello_done(p)
            elif t == 0x14:
                self.handle_finish(p)
            else:
                raise Exception('Unknown handshake packet %02x' % t)

            self.update_neg(hdr+p)

    def parse_tls_response(self, rsp):
        app_data=b''

        while len(rsp) > 0:
            while len(rsp) < 5:
                rsp += b'\0'

            hdr, rsp = rsp[:5], rsp[5:]
            t, mj, mn, sz = unpack('>BBBH', hdr)
            pkt, rsp = rsp[:sz], rsp[sz:]

            if mj != 3 or mn != 3:
                raise Exception('Unexpected TLS version %d %d' % (mj, mn))

            if t == 0x16:
                self.handle_handshake(pkt)

            elif t == 0x14:
                if pkt != unhexlify('01'):
                    raise Exception('Unexpected ChangeCipherSpec payload')
                
                self.secure_rx = True

            elif t == 0x17:
                app_data += self.handle_app_data(pkt)

            else:
                raise Exception('Dont know how to handle message type %02x' % t)

        return app_data

    def make_app_data(self, b):
        if not self.secure_tx:
            raise Exception('App payload before secure connection established')

        b=self.encrypt(self.sign(0x17, b))

        return unhexlify('170303') + with_2bytes_size(b)

    def make_handshake(self, b):
        if self.secure_tx:
            b=self.encrypt(self.sign(0x16, b))

        return unhexlify('160303') + with_2bytes_size(b)

    def make_client_hello(self):
        h = unhexlify('0303') # TLS 1.2
        #self.client_random = unhexlify('bc349559ac16c8f8362191395b4d04a435d870315f519eed8777488bc2b9600c')
        self.client_random = get_random_bytes(0x20)
        h += self.client_random # client's random
        h += with_1byte_size(unhexlify('00000000000000')) # session ID

        suits = b''
        suits += pack('>H', 0xc005) # TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA
        suits += pack('>H', 0x003d) # TLS_RSA_WITH_AES_256_CBC_SHA256
        suits += pack('>H', 0x008d) # TLS_RSA_WITH_AES_256_CBC_SHA256
        h += with_2bytes_size(suits)

        h += with_1byte_size(b'') # no compression options

        exts = b''
        exts += self.make_ext(0x004, pack('>H', 0x0017)) # truncated_hmac = 0x17
        exts += self.make_ext(0x00b, with_1byte_size(unhexlify('00'))) # EC points format = uncompressed
        # h += with_2bytes_size(exts)
        h += pack('>H', len(exts)-2) + exts # -2? WHY?!...

        return self.with_neg_hdr(0x01, h)

    def make_ext(self, id, b):
        return pack('>H', id) + with_2bytes_size(b)

    def parse40(self, reply):
        h, reply = reply[:8], reply[8:]

        if h != unhexlify('0000001000000000'):
            raise Exception('unexpected header: %s' % hexlify(h).decode())

        while len(reply) > 0:
            hdr, reply = reply[:4], reply[4:]
            hs, reply = reply[:0x20], reply[0x20:]
            id, sz = unpack('<HH', hdr)
            body, reply = reply[:sz], reply[sz:]

            if id == 0xffff:
                break

            if id == 4:
                self.handle_priv(body)
            elif id == 6:
                self.handle_ecdh(body)
            elif id == 3:
                self.handle_cert(body)
            elif id == 1:
                self.handle_empty(body)
            elif id == 2:
                self.handle_empty(body)
            else:
                self.trace('unhandled block id %04x (%d bytes): %s' % (id, sz, hexlify(body)))

            m=sha256()
            m.update(body)

            if m.digest() != hs:
                raise Exception('hash mismatch')

    def handle_empty(self, body):
        if body != b'\0' * len(body):
            raise Exception('Expected empty block')

    def handle_cert(self, body):
        # TODO validate cert, check if pub keys match
        self.tls_cert = body
        self.trace('TLS cert pub key: %s' % hexlify(self.tls_cert))

    def handle_ecdh(self, body):
        # TODO check the signature
        x = body[0x8:0x8+0x20]
        y = body[0x4c:0x4c+0x20]

        x, y = [int(hexlify(i[::-1]), 0x10) for i in [x, y]]

        if not P256.is_point_on_curve( (x, y) ):
            raise Exception('Point is not on the curve')

        self.ecdh_q = Point(x, y, P256)
        self.trace('ECDH params:')
        self.trace('x=0x%x' % x)
        self.trace('y=0x%x' % y)
        

    def handle_priv(self, body):
        prefix, body = body[0], body[1:]
        if prefix != 2:
            raise Exception('Unknown private key prefix %02x' % prefix)

        c, hs = body[:-0x20], body[-0x20:]
        sig=hmac.new(psk_validation_key, c, sha256).digest()
        if hs != sig:
            raise Exception('Signature verification failed. This device was probably paired with another computer.')
        
        iv, c = c[:AES.block_size], c[AES.block_size:]
        aes=AES.new(psk_encryption_key, AES.MODE_CBC, iv)
        m=aes.decrypt(c)

        x, m = m[:0x20], m[0x20:]
        y, m = m[:0x20], m[0x20:]
        d, m = m[:0x20], m[0x20:]

        x, y, d = [int(hexlify(i[::-1]), 0x10) for i in [x, y, d]]

        if not P256.is_point_on_curve( (x, y) ):
            raise Exception('Point is not on the curve')

        # TODO check if the priv key belogs to this public key

        self.trace('Private key:')
        self.trace('x=0x%x' % x)
        self.trace('y=0x%x' % y)
        self.trace('d=0x%x' % d)

        self.pub_key = Point(x, y, P256)
        self.priv_key = d

