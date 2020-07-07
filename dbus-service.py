
import dbus
import dbus.mainloop.glib
import dbus.service
dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)
from gi.repository import GObject, GLib
import logging

from proto9x import init
from proto9x.tls import tls
from proto9x.usb import usb
from proto9x.sid import sid_from_string
from proto9x.db import subtype_to_string, db
from proto9x.sensor import sensor, reboot
import pwd
import atexit
import signal

GLib.threads_init()

INTERFACE_NAME='io.github.uunicorn.Fprint.Device'

logging.basicConfig(level=logging.DEBUG)


bus = dbus.SystemBus()
bus_name = dbus.service.BusName('io.github.uunicorn.Fprint', bus)

loop = GObject.MainLoop()

usb.quit = lambda e: loop.quit()


def uid2identity(uid):
    sidstr='S-1-5-21-111111111-1111111111-1111111111-%d' % uid
    return sid_from_string(sidstr)

class Device(dbus.service.Object):
    def __init__(self):
        dbus.service.Object.__init__(self, bus_name, '/io/github/uunicorn/Fprint/Device')

    @dbus.service.method(dbus_interface=INTERFACE_NAME,
                     in_signature="s",
                     out_signature="as")
    def ListEnrolledFingers(self, usr):
        try:
            logging.debug('In ListEnrolledFingers %s' % usr)

            pw=pwd.getpwnam(usr)
            uid=pw.pw_uid
            usr=db.lookup_user(uid2identity(uid))

            if usr == None:
                return []
            
            rc = [subtype_to_string(f['subtype']) for f in usr.fingers]
            print(repr(rc))
            return rc
        except Exception as e:
            raise e

    @dbus.service.method(dbus_interface=INTERFACE_NAME,
                     in_signature='s',
                     out_signature='')
    def DeleteEnrolledFingers(self, user):
        logging.debug('In DeleteEnrolledFingers %s' % user)
        pw=pwd.getpwnam(user)
        usr=db.lookup_user(uid2identity(pw.pw_uid))

        if usr == None:
            return

        db.del_record(usr.dbid)

    def do_scan(self):
        if self.capturing:
            return

        try:
            self.capturing = True
            z=identify()
        except Exception as e:
            #loop.quit();
            raise e
        finally:
            self.capturing = False

    @dbus.service.method(dbus_interface=INTERFACE_NAME,
                         in_signature='ss',
                         out_signature='')
    def VerifyStart(self, user, finger):
        logging.debug('In VerifyStart %s' % finger)

        def complete_cb(rsp, e):
            if e is not None:
                self.VerifyStatus('verify-no-match', True)
            else:
                self.VerifyStatus('verify-match', True)
                usrid, subtype, hsh = rsp
                # TODO pass down the user DB id
                # check that a correct finger was identified

        def update_cb(e):
            self.VerifyStatus('verify-retry-scan', False)

        sensor.identify(update_cb, complete_cb)

    @dbus.service.method(dbus_interface=INTERFACE_NAME,
                         in_signature='',
                         out_signature='')
    def Cancel(self):
        sensor.cancel()

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

    @dbus.service.method(dbus_interface=INTERFACE_NAME,
                         in_signature='ss',
                         out_signature='')
    def EnrollStart(self, user, finger_name):
        logging.debug('In EnrollStart %s for %s' % (finger_name, user))
        pw=pwd.getpwnam(user)
        uid=pw.pw_uid
        def update_cb(rsp, e):
            if e is not None:
                self.EnrollStatus('enroll-retry-scan', False)
            else:
                self.EnrollStatus('enroll-stage-passed', False)

        def complete_cb(rsp, e):
            if e is not None:
                self.EnrollStatus('enroll-failed', True)
            else:
                self.EnrollStatus('enroll-completed', True)

        sensor.enroll(uid2identity(uid), 0xf5, update_cb, complete_cb) # TODO parse the finger name

    @dbus.service.signal(dbus_interface=INTERFACE_NAME, signature='sb')
    def VerifyStatus(self, result, done):
        logging.debug('VerifyStatus')

    @dbus.service.signal(dbus_interface=INTERFACE_NAME, signature='sb')
    def EnrollStatus(self, result, done):
        logging.debug('EnrollStatus')


init.open()

usb.trace_enabled = True
tls.trace_enabled = True

svc = Device()
loop.run()

print("Normal exit")
