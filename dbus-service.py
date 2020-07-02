
from threading import Thread
from gi.repository import GLib
from pydbus import SystemBus
from pydbus.generic import signal
import pkg_resources
from time import sleep
from prototype import *
from proto9x.db import subtype_to_string
from proto9x.sensor import cancel_capture
import pwd

print("Starting up")

loop = GLib.MainLoop()

usb.quit = lambda e: loop.quit()

bus = SystemBus()

def uid2identity(uid):
    sidstr='S-1-5-21-111111111-1111111111-1111111111-%d' % uid
    return sid_from_string(sidstr)

class AlreadyInUse(Exception):
    __name__ = 'net.reactivated.Fprint.Error.AlreadyInUse'

class Device():
    name = 'Validity sensor'

    def __init__(self):
        setattr(self, 'num-enroll-stages', 7)
        setattr(self, 'scan-type', 'press')
        self.capturing = False

    def Claim(self, usr):
        print('In Claim %s' % usr)

    def Release(self):
        print('In Release')
        self.caimed = False
        
    def ListEnrolledFingers(self, usr, dbus_context):
        try:
            print('In ListEnrolledFingers %s' % usr)

            if len(usr) > 0:
                pw=pwd.getpwnam(usr)
                uid=pw.pw_uid
            else:
                sender=dbus_context.sender
                uid=bus.dbus.GetConnectionUnixUser(dbus_context.sender)

            usr=db.lookup_user(uid2identity(uid))

            if usr == None:
                print('User not found on this device')
                return []
            
            rc = [subtype_to_string(f['subtype']) for f in usr.fingers]
            print(repr(rc))
            return rc
        except Exception as e:
            loop.quit()
            raise e

    def do_scan(self):
        if self.capturing:
            return

        try:
            self.capturing = True
            z=identify()
            self.VerifyStatus('verify-match', True)
        except Exception as e:
            self.VerifyStatus('verify-no-match', True)
            #loop.quit();
            raise e
        finally:
            self.capturing = False

    def VerifyStart(self, finger_name):
        print('In VerifyStart %s' % finger_name)
        Thread(target=lambda: self.do_scan()).start()
        #self.do_scan()

    def VerifyStop(self):
        print('In VerifyStop')
        if self.capturing:
            cancel_capture()

    def DeleteEnrolledFingers(self, user):
        print('In DeleteEnrolledFingers %s' % user)
        pw=pwd.getpwnam(user)
        usr=db.lookup_user(uid2identity(pw.pw_uid))

        if usr == None:
            print('User not found on this device')
            return

        db.del_record(usr.dbid)

    def do_enroll(self, finger_name, uid):
        # it is pointless to try and remember username passed in claim as Gnome does not seem to be passing anything useful anyway
        try:
            # TODO hardcode the username and finger for now
            z=enroll(uid2identity(uid), 0xf5)
            print('Enroll was successfull')
            self.EnrollStatus('enroll-completed', True)
        except Exception as e:
            self.EnrollStatus('enroll-failed', True)
            #loop.quit();
            raise e

    def EnrollStart(self, finger_name, dbus_context):
        sender=dbus_context.sender
        uid=bus.dbus.GetConnectionUnixUser(dbus_context.sender)
        print('In EnrollStart %s for %d' % (finger_name, uid))
        Thread(target=lambda: self.do_enroll(finger_name, uid)).start()

    def EnrollStop(self):
        print('In EnrollStop')

    VerifyFingerSelected = signal()
    VerifyStatus = signal()
    EnrollStatus = signal()

class Manager():
    def GetDevices(self):
        print('In GetDevices')
        return ['/net/reactivated/Fprint/Device/0']

    def GetDefaultDevice(self):
        print('In GetDefaultDevice')
        return '/net/reactivated/Fprint/Device/0'


def readif(fn):
    with open('/usr/share/dbus-1/interfaces/' + fn, 'rb') as f:
        # for some reason Gio can't seem to handle XML entities declared inline
        return f.read().decode('utf-8') \
                .replace('&ERROR_CLAIM_DEVICE;', 'net.reactivated.Fprint.Error.ClaimDevice') \
                .replace('&ERROR_ALREADY_IN_USE;', 'net.reactivated.Fprint.Error.AlreadyInUse') \
                .replace('&ERROR_INTERNAL;', 'net.reactivated.Fprint.Error.Internal') \
                .replace('&ERROR_PERMISSION_DENIED;', 'net.reactivated.Fprint.Error.PermissionDenied') \
                .replace('&ERROR_NO_ENROLLED_PRINTS;', 'net.reactivated.Fprint.Error.NoEnrolledPrints') \
                .replace('&ERROR_NO_ACTION_IN_PROGRESS;', 'net.reactivated.Fprint.Error.NoActionInProgress') \
                .replace('&ERROR_INVALID_FINGERNAME;', 'net.reactivated.Fprint.Error.InvalidFingername') \
                .replace('&ERROR_NO_SUCH_DEVICE;', 'net.reactivated.Fprint.Error.NoSuchDevice')

Device.dbus=[readif('net.reactivated.Fprint.Device.xml')]
Manager.dbus=[readif('net.reactivated.Fprint.Manager.xml')]


bus.publish('net.reactivated.Fprint', 
        ('/net/reactivated/Fprint/Manager', Manager()), 
        ('/net/reactivated/Fprint/Device/0', Device())
    )

open97()

usb.trace_enabled = True
tls.trace_enabled = True

loop.run()

print("Normal exit")
