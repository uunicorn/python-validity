#!/usr/bin/env python3

import dbus.mainloop.glib
dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)

bus = dbus.SystemBus()
o = bus.get_object('org.freedesktop.DBus', '/org/freedesktop/DBus')
o = dbus.Interface(o, 'org.freedesktop.DBus')
ls = o.ListNames()
for n in ls:
    if n[0] != ':':
        continue

    pid = o.GetConnectionUnixProcessID(n)

    with open('/proc/%d/cmdline' % pid) as f:
        s = f.read()
        s = s.split('\0')
        print('%-10s %-5d %s' % (n, pid, ' '.join(s)))
