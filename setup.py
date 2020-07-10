#!/usr/bin/python3

from setuptools import setup

setup(name='python-validity',
    version='0.1',
    py_modules = [],
    packages=['validitysensor'],
    scripts=[
        'bin/validity-led-dance',
        'bin/validity-sensors-initializer',
    ],
    install_requires=[
        'cryptography >= 2.1.4',
        'pyusb >= 1.0.2'
    ],
    data_files=[
        ('share/python-validity/playground/', ['factory-reset.py', 'pair.py', 'prototype.py']),
        ('lib/python-validity/', ['dbus_service/dbus-service']),
    ]
)
