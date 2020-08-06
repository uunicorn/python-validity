#!/usr/bin/env python3

import sys

import dbus.mainloop.glib

dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)

bus = dbus.SystemBus()
o = bus.get_object('net.reactivated.Fprint', '/net/reactivated/Fprint/Manager', introspect=False)
o = o.GetDefaultDevice()
o = bus.get_object('net.reactivated.Fprint', o, introspect=False)
o = dbus.Interface(o, 'net.reactivated.Fprint.Device')
print(o.RunCmd(sys.argv[1]))
