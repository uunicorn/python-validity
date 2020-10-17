#!/usr/bin/python3

from setuptools import setup

setup(name='python-validity',
      version='0.12',
      py_modules=[],
      packages=['validitysensor'],
      scripts=[
          'bin/validity-led-dance',
          'bin/validity-sensors-firmware',
      ],
      install_requires=['cryptography >= 2.1.4', 'pyusb >= 1.0.0', 'pyyaml >= 3.12'],
      data_files=[
          ('share/dbus-1/system.d/', ['dbus_service/io.github.uunicorn.Fprint.conf']),
          ('lib/python-validity/', ['dbus_service/dbus-service']),
          ('share/python-validity/playground/', [
              'scripts/dbus-cmd.py', 'scripts/lsdbus.py', 'scripts/factory-reset.py',
              'scripts/prototype.py'
          ]),
      ])
