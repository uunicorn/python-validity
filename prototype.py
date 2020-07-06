
from proto9x.tls import tls
from proto9x.usb import usb
from proto9x.db import db
from proto9x.flash import read_flash
from proto9x.sensor import *
from proto9x.sid import *
from proto9x.init import open as open9x
from threading import Condition
from time import sleep
import code

#usb.trace_enabled = True
#tls.trace_enabled = True

def identify():
    cv=Condition()
    result=[]

    def update_cb(e):
        print('Capture error: %s, try again' % repr(e))

    def complete_cb(rsp, e):
        cv.acquire()
        try:
            result.append((rsp, e))
            cv.notify()
        finally:
            cv.release()

    sensor.identify(update_cb, complete_cb)

    cv.acquire()
    try:
        cv.wait()
        rsp, e = result[0]
        if e is not None: raise e

    except:
        sensor.cancel()
        raise
    finally:
        cv.release()

    usrid, subtype, hsh = rsp

    print('Got finger %x for user recordid %d. Hash: %s' % (subtype, usrid, hexlify(hsh).decode()))

def enroll(sid, finger):
    cv=Condition()
    result=[]

    def update_cb(x, e):
        if e is not None:
            print('Enroll error: %s, try again' % repr(e))
        else:
            print('Enroll progress: %s' % hexlify(x).decode())

    def complete_cb(rsp, e):
        cv.acquire()
        try:
            result.append((rsp, e))
            cv.notify()
        finally:
            cv.release()

    sensor.enroll(sid, finger, update_cb, complete_cb)

    cv.acquire()
    try:
        cv.wait()
        recid, e = result[0]
        if e is not None: raise e

    except:
        sensor.cancel()
        raise
    finally:
        cv.release()

    print('Created a finger record with dbid %d' % recid)

# can't use atexit as it conflicts with atexit installed by libusb
class Blah:
    def __init__(self):
        self.tls=tls

    def __del__(self):
        if usb.dev is not None:
            print('Rebooting device...')
            try:
                reboot()
            except:
                pass

blah=Blah()
