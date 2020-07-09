from validitysensor.tls import tls
from validitysensor.usb import usb
from validitysensor.db import db
from validitysensor.flash import read_flash
from validitysensor.sensor import *
from validitysensor.sid import *
from validitysensor.init import open as open9x
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

