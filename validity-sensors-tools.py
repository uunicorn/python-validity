#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# 2020 - Marco Trevisan
#
# Initializer for ThinkPad's validity sensors 0090 and 0097
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import argparse
import io
import os
import subprocess
import sys
import tempfile
import urllib.request

from binascii import unhexlify
from enum import Enum, auto
from time import sleep
from usb import core as usb_core

from proto9x.calibrate import calibrate
from proto9x.db import db
from proto9x.flash import read_flash
from proto9x.init_db import init_db
from proto9x.init_flash import init_flash
from proto9x.sensor import factory_reset, glow_start_scan, glow_end_enroll
from proto9x.tls import tls as vfs_tls
from proto9x.upload_fwext import upload_fwext
from proto9x.usb import usb as vfs_usb
from proto9x.util import assert_status


VALIDITY_VENDOR_ID = 0x138a

class VFS(Enum):
    DEV_90 = 0x0090
    DEV_97 = 0x0097

DEFAULT_URIS = {
    VFS.DEV_90: {
        'driver': 'https://download.lenovo.com/pccbbs/mobiles/n1cgn08w.exe',
        'referral': 'https://support.lenovo.com/us/en/downloads/DS120491',
    },
    VFS.DEV_97: {
        'driver': 'https://download.lenovo.com/pccbbs/mobiles/n1mgf03w.exe',
        'referral': 'https://download.lenovo.com/pccbbs/mobiles/n1mgf03w.exe'
    }
}

DEFAULT_FW_NAMES = {
    VFS.DEV_90: '6_07f_Lenovo.xpfwext',
    VFS.DEV_97: '6_07f_lenovo_mis.xpfwext',
}


class VFSTools():
    def __init__(self, args, usb_dev, dev_type):
        self.args = args
        self.usb_dev = usb_dev
        self.dev_type = dev_type
        self.dev_str = repr(usb_dev)

        print('Found device {}'.format(self.dev_str))

        try:
            if self.args.simulate_virtualbox:
                raise(Exception())

            with open('/sys/class/dmi/id/product_name', 'r') as node:
                self.product_name = node.read().strip()
            with open('/sys/class/dmi/id/product_serial', 'r') as node:
                self.product_serial = node.read().strip()
        except:
            self.product_name = 'VirtualBox'
            self.product_serial = '0'

        if self.args.host_product:
            self.product_name = self.args.host_product

        if self.args.host_serial:
            self.product_serial = self.args.host_serial

        vfs_tls.set_hwkey(product_name=self.product_name,
            serial_number=self.product_serial)

    def retry_command(self, command, max_retries=3):
        for i in range(max_retries):
            try:
                command()
                break
            except Exception as e:
                err = e
                self.sleep()
                print('Try {} failed with error: {}'.format(i+1, e))

            if i == max_retries-1:
                print('Device didn\'t reply in time...')
                raise(err)

    def open_device(self, init=False):
        print('Opening device',hex(self.dev_type.value))
        try:
            vfs_usb.dev.reset()
        except:
            pass

        vfs_usb.open(product=self.dev_type.value)

        if init:
            self.retry_command(vfs_usb.send_init)

            # try to init TLS session from the flash
            vfs_tls.parseTlsFlash(read_flash(1, 0, 0x1000))
            vfs_tls.open()

    def restart(self, init=True):
        vfs_tls.reset()
        self.open_device(init=init)

    def download_and_extract_fw(self, fwdir, fwuri=None):
        fwuri = fwuri if fwuri else DEFAULT_URIS[self.dev_type]['driver']
        fwarchive = os.path.join(fwdir, 'fwinstaller.exe')
        fwname = DEFAULT_FW_NAMES[self.dev_type]

        try:
            subprocess.check_call(['innoextract', '--version'],
                stdout=subprocess.DEVNULL)
        except Exception as e:
            print('Impossible to run innoextract: {}'.format(e))
            raise(e)

        print('Downloading {} to extract {}'.format(fwuri, fwname))

        req = urllib.request.Request(fwuri)
        req.add_header('Referer', DEFAULT_URIS[self.dev_type].get('referral', ''))
        req.add_header('User-Agent', 'Mozilla/5.0 (X11; U; Linux)')

        with urllib.request.urlopen(req) as response:
            with open(fwarchive, 'wb') as out_file:
                out_file.write(response.read())

        subprocess.check_call(['innoextract',
            '--output-dir', fwdir,
            '--include', fwname,
            '--collisions', 'overwrite',
            fwarchive
        ])

        fwpath = subprocess.check_output([
            'find', fwdir, '-name', fwname]).decode('utf-8').strip()
        print('Found firmware at {}'.format(fwpath))

        if not fwpath:
            raise Exception('No {} found in the archive'.format(fwname))

        return fwpath

    def sleep(self, sec=3):
        print('Sleeping...')
        sleep(sec)

    def factory_reset(self):
        print('Factory reset...')
        self.retry_command(factory_reset)

    def flash_firmware(self, fwpath):
        print('Uploading firmware...')
        upload_fwext(fw_path=fwpath)

    def calibrate(self, calib_data=None):
        if isinstance(calib_data, io.IOBase):
            calib_data_file = calib_data.name
        elif calib_data:
            calib_data_file = calib_data
        else:
            calib_data_file = 'calib-data.bin'

        use_device = False
        if os.path.exists(calib_data_file):
            print('Calibrating, using data from {}'.format(calib_data_file))
        else:
            print('Calibrating using device data')
            calib_data_file = os.path.join(tempfile.mkdtemp(), 'calib-data.bin')
            use_device = True

        calibrate(calib_data_path=calib_data_file)

        if use_device:
            print('Calibration data saved at {}'.format(calib_data_file))

    def init_db(self):
        print('Init database...')
        init_db()

    def dump_db(self):
        print('Dumping database...')
        db.dump_all()

    def pair(self, fwpath, calib_data=None):
        print('Pairing the sensor with device {}'.format(self.product_name))

        def init_flash_command():
            self.open_device()
            print('Initializing flash...')
            init_flash()
        self.retry_command(init_flash_command, max_retries=5)

        self.sleep()
        self.restart()

        self.flash_firmware(fwpath)

        self.sleep()
        self.restart()

        self.calibrate(calib_data)

        self.init_db()

        print('That\'s it, pairing with {} finished'.format(self.dev_str))

    def initialize(self, fwpath, calib_data=None):
        self.open_device()

        try:
            self.factory_reset()
        except Exception as e:
            print('Factory reset failed with {}, this should not happen, but ' \
                'we can ignore it, if pairing works...'.format(e))

        vfs_tls.reset()
        vfs_usb.dev.reset()
        self.sleep()

        self.pair(fwpath, calib_data)

    def led_dance(self):
        print('Let\'s glow the led!')

        for i in range(10):
            glow_start_scan()
            sleep(0.05)
            glow_end_enroll()
            sleep(0.05)

        led_script = unhexlify(
            '39ff100000ff03000001ff002000000000ffff0000ffff0000ff03000001ff00' \
            '200000000000000000ffff0000ff03000001ff002000000000ffff0000000000' \
            '0000000000000000000000000000000000000000000000000000000000000000' \
            '0000000000000000000000000000000000000000000000000000000000')

        assert_status(vfs_tls.app(led_script))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('-d', '--driver-uri')
    parser.add_argument('-f', '--firmware-path', type=argparse.FileType('r'))
    parser.add_argument('-c', '--calibration-data', type=argparse.FileType('r'))
    parser.add_argument('--host-product')
    parser.add_argument('--host-serial')
    parser.add_argument('--simulate-virtualbox', action='store_true')
    parser.add_argument('-t', '--tool',
        choices=(
            'initializer',
            'factory-reset',
            'flash-firmware',
            'pair',
            'calibrate',
            'dump-db',
            'erase-db',
            'led-dance',
        ),
        default='initializer',
        help='Tool to launch (default: %(default)s)')

    args = parser.parse_args()

    if os.geteuid() != 0:
        raise Exception('This script needs to be executed as root')

    if args.simulate_virtualbox and (args.host_product or args.host_serial):
        parser.error("--simulate-virtualbox is incompatible with host params.")

    usb_dev = None
    for d in VFS:
        dev = usb_core.find(idVendor=VALIDITY_VENDOR_ID, idProduct=d.value)
        if dev:
            dev_type = d
            usb_dev = dev

    if not usb_dev:
        raise Exception('No supported validity device found')

    vfs_tools = VFSTools(args, usb_dev, dev_type)

    if args.tool == 'initializer' or args.tool == 'pair':
        with tempfile.TemporaryDirectory() as fwdir:
            if args.firmware_path:
                fwpath = args.firmware_path.name
            else:
                fwpath = vfs_tools.download_and_extract_fw(fwdir,
                    fwuri=args.driver_uri)

            input('The device will be now reset to factory and associated to ' \
                'the current laptop.\nPress Enter to continue (or Ctrl+C to ' \
                'cancel)...')

            if args.tool == 'pair':
                vfs_tools.pair(fwpath, args.calibration_data)
            else:
                vfs_tools.initialize(fwpath, args.calibration_data)

    elif args.tool == 'factory-reset':
        input('The device will be now reset to factory\n' \
            'Press Enter to continue (or Ctrl+C to cancel)...')
        vfs_tools.open_device()
        vfs_tools.factory_reset()

    elif args.tool == 'flash-firmware':
        with tempfile.TemporaryDirectory() as fwdir:
            if args.firmware_path:
                fwpath = args.firmware_path.name
            else:
                fwpath = vfs_tools.download_and_extract_fw(fwdir,
                    fwuri=args.driver_uri)

            input('The device will be now flashed with {} firmware.\n' \
                'Press Enter to continue (or Ctrl+C to cancel)...'.format(
                    fwpath))

            vfs_tools.open_device(init=True)
            vfs_tools.flash_firmware(fwpath)

    elif args.tool == 'calibrate':
        vfs_tools.open_device(init=True)
        vfs_tools.calibrate(args.calibration_data)

    elif args.tool == 'erase-db':
        vfs_tools.open_device(init=True)
        vfs_tools.init_db()

    elif args.tool == 'dump-db':
        vfs_tools.open_device(init=True)
        vfs_tools.dump_db()

    elif args.tool == 'led-dance':
        vfs_tools.open_device(init=True)
        vfs_tools.led_dance()

    else:
        parser.error('No valid tool selected')
