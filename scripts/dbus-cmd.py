#!/usr/bin/env python3

import argparse
import re
import dbus
import dbus.mainloop.glib
dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)
from gi.repository import GObject, GLib
import sys

bus = dbus.SystemBus()
o = bus.get_object('net.reactivated.Fprint', '/net/reactivated/Fprint/Manager', introspect=False)
o = o.GetDefaultDevice()
o = bus.get_object('net.reactivated.Fprint', o, introspect=False)
o = dbus.Interface(o, 'net.reactivated.Fprint.Device')
print(o.RunCmd(sys.argv[1]))
