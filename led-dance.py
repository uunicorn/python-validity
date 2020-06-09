#!/usr/bin/env python3

import os

from binascii import unhexlify
from enum import Enum
from proto9x.flash import read_flash
from proto9x.sensor import *
from proto9x.tls import tls as vfs_tls
from proto9x.usb import usb as vfs_usb
from time import sleep
from usb import core as usb_core

class VFS(Enum):
    DEV_90 = 0x0090
    DEV_97 = 0x0097


if __name__ == "__main__":
    if os.geteuid() != 0:
        raise Exception('This script needs to be executed as root')

    usb_dev = None
    for d in VFS:
        dev = usb_core.find(idVendor=0x138a, idProduct=d.value)
        if dev:
            usb_dev = dev

    if not usb_dev:
        raise Exception('No supported validity device found')

    vfs_usb.open(product=usb_dev.idProduct)
    vfs_usb.send_init()

    try:
        with open('/sys/class/dmi/id/product_name', 'r') as node:
            product_name = node.read().strip()
        with open('/sys/class/dmi/id/product_serial', 'r') as node:
            product_serial = node.read().strip()
    except:
        product_name = 'VirtualBox'
        product_serial = '0'

    vfs_tls.set_hwkey(product_name=product_name, serial_number=product_serial)

    # try to init TLS session from the flash
    vfs_tls.parseTlsFlash(read_flash(1, 0, 0x1000))
    vfs_tls.open()

    for i in range(0, 10):
        glow_start_scan()
        sleep(0.05)
        glow_end_enroll()
        sleep(0.05)

    led_script = unhexlify(
        '39ff100000ff03000001ff002000000000ffff0000ffff0000ff03000001ff00' \
        '200000000000000000ffff0000ff03000001ff002000000000ffff0000000000' \
        '0000000000000000000000000000000000000000000000000000000000000000' \
        '0000000000000000000000000000000000000000000000000000000000')

    assert_status(tls.app(led_script))
