
from util import assert_status
from time import sleep
from struct import pack, unpack
from binascii import hexlify, unhexlify
from tls97 import Tls
from usb97 import Usb, unhex
from db97 import *
from sid import *

usb = Usb()
tls = Tls(usb)
db = Db(tls)

def open97():
    usb.open()
    usb.send_init()
    tls.open()
    tls.save()
    #usb.trace_enabled = True
    #tls.trace_enabled = True

def load97():
    #usb.trace_enabled = True
    #tls.trace_enabled = True
    usb.open()
    tls.load()

def glow_start_scan():
    cmd=unhexlify('3920bf0200ffff0000019900200000000099990000000000000000000000000020000000000000000000000000ffff000000990020000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000')
    assert_status(tls.app(cmd))

def glow_end_enroll():
    cmd=unhexlify('39f4010000f401000001ff002000000000ffff0000000000000000000000000020000000000000000000000000f401000000ff0020000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000')
    assert_status(tls.app(cmd))

# FIXME this must be very specific to a particular device and constructed on the fly from multiple hardcoded tables:
identify_prg=unhex('''
02980000002300000020000800002000800000010032007000000000802020050024200000502077362820010030200100082170000c210
000482102004c210000582000005c20000060200000682005006c20012970200121742001887820018084202000942001809c200902a020
0b19b4200000b8203b04bc201400c0200200c4200100c82002003300100000000080cc200000f503d0200000a1013200440000000080dc2
0e803e0206401e420d002e8200001f0200500f8200500fc200000b8203b0000080400140800000808000008080000140830000808000014
0831001c081a0032000c0000000080501101004c1126003400080310071d10071d10071d10071d10071c01065810080101000007c8078c0
6100000204f80007f000003070107010c07032c08fc80095a800afc08fb800b5a095b800afb08fa800b5b095c800afa08f9800b5c095d80
0af908f8800b5d095e800af808f7800b5e095f800af708f6800b5f0960800af608f5800b600961800af508f4800b610962800af408f3800
b620963800af308f2800b630964800af208f1800b640965800af108f0800b650966800af008ef800b660967800aef08ee800b670968800a
ee08ed800b68096c800aed08ec800b6c096d800aec08eb800b6d096e800aeb08ea800b6e096f800aea08e9800b6f0970800ae908e8800b7
00971800ae808e7800b710972800ae708e6800b720973800ae608e5800b730974800ae508e4800b740975800ae408e3800b750976800ae3
08e2800b760977800ae208e1800b770978800ae108e0800b780979800ae008df800b79097a800adf08de800b7a097b800ade08dd800b7b0
97c800add08dc800b7c097d800adc08db800b7d097e800adb08da800b7e097f800ada08d9800b7f0980800ad908d8800b800981800ad808
d7800b810982800ad708d6800b820983800ad608d5800b830984800ad508d4800b840985800ad408d3800b850986800ad308d2800b86098
7800ad208d1800b870988800ad108d0800b880989800ad008cf800b89098a800acf08ce800b8a098b800ace08cd800b8b098c800acd08cc
800b8c098d800acc08cb800b8d098e800acb08ca800b8e098f800aca08c9800b8f0990800ac908c8800b900991800ac808c7800b9109928
00ac708c6800b920993800ac608c5800b930994800ac508c4800b940995800ac408c3800b950996800ac308c2800b960997800ac208c180
0b970998800ac108c0800b980999800ac008bf800b99099a800abf08be800b9a099b800abe08bd800b9b099c800abd08bc800b9c099d800
abc08bb800b9d099e800abb08ba800b9e099f800aba08b9800b9f09a0800ab908b8800ba00801800ab808b7800a010802800ab708b6800a
020803800ab608b5800a030804802003070404020000000000002f000400900000002900040000000000350004001000000017000000260
02800fbb20f00f2220f00300000006001020040010a00018000000a0200000b19000050c360ea010910002e001c00020018002300000090
0090004d01000090017c013c323232640a02013000cc0103000000ff0000001d000003ff00000025000003ff00000022000003101112131
415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b
4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f8081828
38485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f2b23203c2d182e1e30182e1c321d341d341e321c301e1e241e201f
201d1c321a301e1c211e21341f1e202024201f1e20201f212221221d221e23341e1d1e1d20341f1d193b341c1d1e35201e201c20221f341
c1e1e1c221f201d21201e1c1f34242221201f20221f201e241e241d2020221e2420231d221e211e1f1e1e341c321e3220301d2d302f2d2c
2b23223a211c7e7f807f8080808080808080808080808080808080808180818081808180808080808180818080808180818081808180818
08180818081808180808081808180808081807f808081808080818081808180808081808180818081808180818080808180818081808180
81808180818081808180818081808180818081808080808080808080807f807f807f807f7f7e7e
''')
# The following blob has only 1 byte difference from the above
enroll_prg=unhex('''
02980000002300000020000800002000800000010032007000000000802020050024200000502077362820010030200100082170000c210
000482102004c210000582000005c20000060200000682005006c20012970200121742001887820018084202000942001809c200902a020
0b19b4200000b8203b04bc201400c0200200c4200100c82002003300100000000080cc200000f503d0200000a1013200440000000080dc2
0e803e0206401e420d002e8200001f0200500f8200500fc200000b8203b0000080400140800000808000008080000140830000808000014
0831001c081a0032000c0000000080501101004c1126003400080310071d10071d10071d10071d10071c01065810080101000007c8078c0
6100000204f80007f000003070107010c07032c08fc80095a800afc08fb800b5a095b800afb08fa800b5b095c800afa08f9800b5c095d80
0af908f8800b5d095e800af808f7800b5e095f800af708f6800b5f0960800af608f5800b600961800af508f4800b610962800af408f3800
b620963800af308f2800b630964800af208f1800b640965800af108f0800b650966800af008ef800b660967800aef08ee800b670968800a
ee08ed800b68096c800aed08ec800b6c096d800aec08eb800b6d096e800aeb08ea800b6e096f800aea08e9800b6f0970800ae908e8800b7
00971800ae808e7800b710972800ae708e6800b720973800ae608e5800b730974800ae508e4800b740975800ae408e3800b750976800ae3
08e2800b760977800ae208e1800b770978800ae108e0800b780979800ae008df800b79097a800adf08de800b7a097b800ade08dd800b7b0
97c800add08dc800b7c097d800adc08db800b7d097e800adb08da800b7e097f800ada08d9800b7f0980800ad908d8800b800981800ad808
d7800b810982800ad708d6800b820983800ad608d5800b830984800ad508d4800b840985800ad408d3800b850986800ad308d2800b86098
7800ad208d1800b870988800ad108d0800b880989800ad008cf800b89098a800acf08ce800b8a098b800ace08cd800b8b098c800acd08cc
800b8c098d800acc08cb800b8d098e800acb08ca800b8e098f800aca08c9800b8f0990800ac908c8800b900991800ac808c7800b9109928
00ac708c6800b920993800ac608c5800b930994800ac508c4800b940995800ac408c3800b950996800ac308c2800b960997800ac208c180
0b970998800ac108c0800b980999800ac008bf800b99099a800abf08be800b9a099b800abe08bd800b9b099c800abd08bc800b9c099d800
abc08bb800b9d099e800abb08ba800b9e099f800aba08b9800b9f09a0800ab908b8800ba00801800ab808b7800a010802800ab708b6800a
020803800ab608b5800a030804802003070404020000000000002f000400900000002900040000000000350004001000000017000000260
02800fbb20f00f2220f00300000006001020040010a00018000000a0200000b19000050c360ea010910002e001c00020018002300000090
0090004d01000090017c013c323232640a02013000cc0103000000ff0000001d000003ff00000025000003ff00000022000003101112131
415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b
4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f8081828
38485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f2b23203c2d182e1e30182e1c321d341d341e321c301e1e241e201f
201d1c321a301e1c211e21341f1e202024201f1e20201f212221221d221e23341e1d1e1d20341f1d193b341c1d1e35201e201c20221f341
c1e1e1c221f201d21201e1c1f34242221201f20221f201e241e241d2020221e2420231d221e211e1f1e1e341c321e3220301d2d302f2d2c
2b23223a211c7e7f807f8080808080808080808080808080808080808180818081808180808080808180818080808180818081808180818
08180818081808180808081808180808081807f808081808080818081808180808081808180818081808180818080808180818081808180
81808180818081808180818081808180818081808080808080808080807f807f807f807f7f7e7e
''')

def start_scan(cmd):
    assert_status(tls.app(cmd))

def wait_for_finger():
    while True:
        b=usb.wait_int()
        if b[0] == 2:
            break

def get_prg_status():
    return tls.app(unhexlify('5100000000'))

def wait_till_finished():
    while True:
        status = get_prg_status()
        
        if status[0] in [0, 7]:
            break

        sleep(0.2)

def stop_prg():
    return tls.app(unhexlify('5100200000'))

def capture(prg):
    start_scan(prg)

    b=usb.wait_int()
    if b[0] != 0:
        raise Exception('Unexpected interrupt type' % hexlify(b).decode())

    wait_for_finger()
    wait_till_finished()

    res=stop_prg()
    
    b=usb.wait_int()
    if b[0] != 3:
        raise Exception('Unexpected interrupt type %s' % hexlify(b).decode())

    assert_status(res)
    res = res[2:]
    
    l, res = res[:4], res[4:]
    l, = unpack('<L', l)

    if l != len(res):
        raise Exception('Response size does not match %d != %d', l, len(res))

    x, y, w1, w2, error = unpack('<HHHHL', res)

    return error

def append_new_image(key=0, prev=b''):
    rsp=tls.app(pack('<BLL', 0x68, key, 0))
    assert_status(rsp)
    new_key, = unpack('<L', rsp[2:])

    usb.wait_int()

    rsp=tls.app(b'\x6b' + prev)
    assert_status(rsp)
    
    usb.wait_int()

    rsp=tls.app(b'\x6b' + prev)
    assert_status(rsp)
    res=rsp[2:]

    rsp=tls.app(unhexlify('6900000000'))
    assert_status(rsp)

    l, res = res[:2], res[2:]
    l, = unpack('<H', l)
    if l != len(res):
        raise Exception('Response size does not match %d != %d', l, len(res))

    # FIXME check how it's done rather than using a hardcoded offsets
    res, new = res[:0x6c], res[0x6c:]

    return (new_key, res, new)

def parse_template(subtype, template):
    # This number is very odd. It seems to be always a multiple of 0x10,
    # which probably means that this is not a size of the plain text.
    # On the other hand it is exactly 0x30 bytes less than the size of the payload.
    # If we assume algos are all the same, 0x30 could be 0x10 for AES IV and
    # 0x20 for SHA256 MAC
    ciphertext_size, = unpack('<H', template[2:4])
    template_size = 8+ciphertext_size+0x30
    template, rest = template[:template_size], template[template_size:]

    template = pack('<H', len(template)) + template

    # FIXME this is most likely wrong, need to do a proper code dive to figure out
    # how enrollment update response is handled in the dll
    hs, rest = rest[-0x20:], rest[:-0x20]
    hs = pack('<H', len(hs)) + hs

    tinfo = pack('<H', 1) + template
    tinfo += pack('<H', 2) + hs

    tinfo = pack('<HHHH', subtype, 3, len(tinfo), 0x20) + tinfo
    tinfo += b'\0' * 0x20

    return tinfo

def enroll(identity, subtype):
    key=0
    template=b''

    print('Waiting for a finger...')

    while True:
        glow_start_scan()

        err = capture(enroll_prg)
        if err != 0:
            print('Error %08x, try again' % err)
            continue
        
        key, rsp, template = append_new_image(key, template)

        print('Progress: %d %% done' % rsp[0x3c])
        
        if rsp[0x3c] == 100:
            break

    # FIXME check for duplicates

    tinfo = parse_template(subtype, template)

    usr=db.lookup_user(identity)
    if usr == None:
        usr = db.new_user(identity)
    else:
        usr = usr.dbid
    
    recid = db.new_finger(usr, tinfo)

    glow_end_enroll()

    print('All done')

    return recid

def parse_dict(x):
    rc={}

    while len(x) > 0:
        (t, l), x = unpack('<HH', x[:4]), x[4:]
        rc[t], x = x[:l], x[l:]

    return rc

    
def identify():
    glow_start_scan()
    err = capture(identify_prg)
    if err != 0:
        raise Exception('Capture failed: %08x' % err)

    try:
        # which finger?
        stg_id=0 # match against any storage
        usr_id=0 # match against any user
        cmd=pack('<BBBHHHHH', 0x5e, 2, 0xff, stg_id, usr_id, 1, 0,0)
        rsp=tls.app(cmd)
        assert_status(rsp)

        b = usb.wait_int()
        if b[0] != 3:
            raise Exception('Identification failed: %s' % hexlify(b).decode())

        rsp = tls.app(unhexlify('6000000000'))
        assert_status(rsp)
        rsp = rsp[2:]

    finally:
        # finish
        assert_status(tls.app(unhexlify('6200000000')))

    (l,), rsp = unpack('<H', rsp[:2]), rsp[2:]
    if l != len(rsp):
        raise Exception('Response size does not match')

    rsp=parse_dict(rsp)


    #for k in rsp:
    #    print('%04x: %s (%d)' % (k, hexlify(rsp[k]).decode(), len(rsp[k])))
    
#0001: 09000000 (4)
#0003: f500 (2)
#0004: 8dee792532d3432d41c872fd4d6d590fbc855ad449cf2753cd919eb9c94675c6 (32)
#0005: 0000000000000000000000000000000000000000000000000000000000000000 (32)
#0008: 0a00 (2)
#0002: 010b0000 (4)
#0006: 00000000000000000000000000000000000000000000000000000000000000000000000000000000 (40)
    usrid, subtype, hsh, fingerid = rsp[1], rsp[3], rsp[4], rsp[8]
    usrid, = unpack('<L', usrid)
    subtype, = unpack('<H', subtype)
    fingerid, = unpack('<H', fingerid)

    usr = db.get_user(usrid)
    finger_record = db.get_record_children(fingerid)

    # Device won't let you add more than one data blob
    if len(finger_record.children) > 1:
        raise Exception('Expected only one child record for finger')

    print('Recognised finger %02x (%s) from user %s' % (subtype, subtype_to_string(subtype), repr(usr.identity)))
    print('Template hash: %s' % hexlify(hsh).decode())

    if len(finger_record.children) > 0:
        if finger_record.children[0]['type'] != 8:
            raise Exception('Expected data blob as a finger child')
        
        blob_id = finger_record.children[0]['dbid']
        blob = db.get_record_value(blob_id).value

        tag, sz = unpack('<HH', blob[:4])
        val = blob[4:4+sz]

        print('Data blob associated with the finger: %04x: %s' % (tag, hexlify(val).decode()))
        
    return rsp

