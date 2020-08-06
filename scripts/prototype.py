from binascii import hexlify

from validitysensor.sensor import sensor

# usb.trace_enabled = True
# tls.trace_enabled = True


def identify():
    def update_cb(e):
        print('Capture error: %s, try again' % repr(e))

    usrid, subtype, hsh = sensor.identify(update_cb)

    print('Got finger %x for user recordid %d. Hash: %s' % (subtype, usrid, hexlify(hsh).decode()))


def enroll(sid, finger):
    def update_cb(x, e):
        if e is not None:
            print('Enroll error: %s, try again' % repr(e))
        else:
            print('Enroll progress: %s' % hexlify(x).decode())

    recid = sensor.enroll(sid, finger, update_cb)

    print('Created a finger record with dbid %d' % recid)
