
from .tls import tls
from .usb import usb
from .db import db, subtype_to_string
from .flash import write_enable, flush_changes
from time import sleep
from struct import pack, unpack
from binascii import hexlify, unhexlify
from .util import assert_status, unhex
from .hw_tables import dev_info_lookup
from .blobs import identify_prg, enroll_prg, reset_blob

def glow_start_scan():
    cmd=unhexlify('3920bf0200ffff0000019900200000000099990000000000000000000000000020000000000000000000000000ffff000000990020000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000')
    assert_status(tls.app(cmd))

def glow_end_enroll():
    cmd=unhexlify('39f4010000f401000001ff002000000000ffff0000000000000000000000000020000000000000000000000000f401000000ff0020000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000')
    assert_status(tls.app(cmd))

def start_scan(cmd):
    assert_status(tls.app(cmd))

def cancel_capture():
    usb.queue.put(b'')
    #sleep(0.2)
    #rsp=tls.app(b'\x04')
    #assert_status(rsp)
    usb.read_82()
    
def wait_for_finger():
    while True:
        b=usb.wait_int()
        
        if len(b) == 0:
            raise Exception('Cancelled')

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
    usb.purge_int_queue()

    start_scan(prg)

    b=usb.wait_int()
    if b[0] != 0:
        raise Exception('Unexpected interrupt type %s' % hexlify(b).decode())

    try:
        wait_for_finger()
        #wait_till_finished()
    
        while True:
            b=usb.wait_int()
            if b[0] != 3:
                raise Exception('Unexpected interrupt type %s' % hexlify(b).decode())

            if b[2] & 4:
                break
    finally:
        res=stop_prg()

    assert_status(res)
    res = res[2:]
    
    l, res = res[:4], res[4:]
    l, = unpack('<L', l)

    if l != len(res):
        raise Exception('Response size does not match %d != %d', l, len(res))

    x, y, w1, w2, error = unpack('<HHHHL', res)

    return error

def enrollment_update_start(key=0):
    rsp=tls.app(pack('<BLL', 0x68, key, 0))
    assert_status(rsp)
    new_key, = unpack('<L', rsp[2:])

    usb.wait_int()

    return new_key

def enrollment_update_end():
    assert_status(tls.app(pack('<BL', 0x69, 0)))

def enrollment_update(prev):
    write_enable()
    rsp=tls.app(b'\x6b' + prev)
    assert_status(rsp)
    flush_changes()

    return rsp[2:]

def append_new_image(key=0, prev=b''):
    enrollment_update(prev)
    
    usb.wait_int()

    res = enrollment_update(prev)

    l, res = res[:2], res[2:]
    l, = unpack('<H', l)
    if l != len(res):
        raise Exception('Response size does not match %d != %d', l, len(res))

    magic_len = 0x38 # hardcoded in the DLL
    template = header = tid = None

    while len(res) > 0:
        tag, l = unpack('<HH', res[:4])

        if tag == 0:
            template = res[:magic_len+l]
        elif tag == 1:
            header = res[magic_len:magic_len+l]
        elif tag == 3:
            tid = res[magic_len:magic_len+l]
        else:
            print('Ignoring unknown tag %x' % tag)
            
        res=res[magic_len+l:]

    return (header, template, tid)

def make_finger_data(subtype, template, tid):
    template = pack('<HH', 1, len(template)) + template
    tid = pack('<HH', 2, len(tid)) + tid

    tinfo = template + tid

    tinfo = pack('<HHHH', subtype, 3, len(tinfo), 0x20) + tinfo
    tinfo += b'\0' * 0x20

    return tinfo

def enroll(identity, subtype):
    key=0
    template=b''

    print('Waiting for a finger...')

    while True:
        glow_start_scan()

        try:
            err = capture(enroll_prg)
            if err != 0:
                print('Error %08x, try again' % err)
                continue
        except Exception as e:
            print('Capture failed (%s), try again' % repr(e))
            sleep(1)
            continue
        
        key = enrollment_update_start(key)
        header, template, tid = append_new_image(key, template)
        enrollment_update_end()

        print(hexlify(header))

        if tid:
            break

    # TODO check for duplicates

    tinfo = make_finger_data(subtype, template, tid)

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
    try:
        err = capture(identify_prg)
        if err != 0:
            raise Exception('Capture failed: %08x' % err)

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
    
#on 0097
#0001: 09000000 (4)
#0003: f500 (2)
#0004: 8dee792532d3432d41c872fd4d6d590fbc855ad449cf2753cd919eb9c94675c6 (32)
#0005: 0000000000000000000000000000000000000000000000000000000000000000 (32)
#0008: 0a00 (2) <-- finger record db id
#0002: 010b0000 (4)
#0006: 00000000000000000000000000000000000000000000000000000000000000000000000000000000 (40)

#on 009a (no finger record db id)
#0000 8a00
# 0100 0400 05000000
# 0300 0200 f500
# 0400 2000 b147dd1eda8da322fb7a2a51d0eab6fe94bef46c05204fbefb1fd16360903791
# 0500 2000 0000000000000000000000000000000000000000000000000000000000000000
# 0200 0400 650a0000
# 0600 2800 00000000000000000000000000000000000000000000000000000000000000000000000000000000

    usrid, subtype, hsh = rsp[1], rsp[3], rsp[4]
    usrid, = unpack('<L', usrid)
    subtype, = unpack('<H', subtype)

    usr = db.get_user(usrid)
    fingerids = [f['dbid'] for f in usr.fingers if f['subtype'] == subtype]
    if len(fingerids) != 1:
        raise Exception('Unexpected matching finger count')
    finger_record = db.get_record_children(fingerids[0])

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


def read_hw_reg32(addr):
    rsp=tls.cmd(pack('<BLB', 7, addr, 4))
    assert_status(rsp)
    rsp, = unpack('<L', rsp[2:])
    return rsp

def write_hw_reg32(addr, val):
    rsp=tls.cmd(pack('<BLLB', 8, addr, val, 4))
    assert_status(rsp)


def reboot():
    assert_status(tls.cmd(unhex('050200')))

def factory_reset():
    assert_status(usb.cmd(reset_blob))
    assert_status(usb.cmd(b'\x10' + b'\0'*0x61))
    reboot()

def identify_sensor():
    rsp=tls.cmd(b'\x75')
    assert_status(rsp)
    rsp=rsp[2:]

    zeroes, minor, major = unpack('<LHH', rsp)

    if zeroes != 0:
        raise Exception('This was not expected')

    return dev_info_lookup(major, minor)

