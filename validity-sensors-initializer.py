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
import os
import subprocess
import sys
import tempfile
import urllib.request

from enum import Enum, auto
from time import sleep
from usb import core as usb_core

from proto9x.calibrate import calibrate
from proto9x.flash import read_flash
from proto9x.init_db import init_db
from proto9x.init_flash import init_flash
from proto9x.sensor import factory_reset
from proto9x.tls import tls as vfs_tls
from proto9x.upload_fwext import upload_fwext
from proto9x.usb import usb as vfs_usb

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


class VFSInitializer():
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

    def open_device(self, init=False):
        print('Opening device',hex(self.dev_type.value))
        vfs_usb.open(product=self.dev_type.value)

        if init:
            vfs_usb.send_init()

            # try to init TLS session from the flash
            vfs_tls.parseTlsFlash(read_flash(1, 0, 0x1000))
            vfs_tls.open()

    def restart(self):
        vfs_tls.reset()
        self.open_device(init=True)

    def download_and_extract_fw(self, fwdir, fwuri=None):
        fwuri = fwuri if fwuri else DEFAULT_URIS[self.dev_type]['driver']
        fwarchive = os.path.join(fwdir, 'fwinstaller.exe')
        fwname = DEFAULT_FW_NAMES[self.dev_type]

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

    def try_factory_reset(self):
        self.open_device()
        try:
            print('Factory reset...')
            factory_reset()
        except Exception as e:
            print('Factory reset failed with {}, this should not happen, but ' \
                    'we can ignore it, if pairing works...'.format(e))

    def pair(self, fwpath):
        print('Pairing the sensor with device {}'.format(self.product_name))

        max_retries = 5
        for i in range(0, max_retries):
            try:
                self.open_device()

                print('Initializing flash...')
                init_flash()
                break
            except Exception as e:
                err = e
                self.sleep()
                print('Try {} failed with error: {}'.format(i+1, e))
            finally:
                max_retries -= 1

            if max_retries == 0:
                print('Device didn\'t show up after reset, retry...')
                raise(err)

        self.sleep()
        self.restart()

        print('Uploading firmware...')
        upload_fwext(fw_path=fwpath)

        self.sleep()
        self.restart()

        if self.args.calibration_data:
            calib_data_file = self.args.calibration_data.name
        else:
            calib_data_file = 'calib-data.bin'

        print('Calibrating, re-using {}, if any...'.format(calib_data_file))
        if os.path.exists(calib_data_file):
            calibrate(calib_data_path=calib_data_file)
        else:
            try:
                calib_data_file = os.path.join(tempfile.mkdtemp(), 'calib-data.bin')
                calibrate(calib_data_path=calib_data_file)
                print('Calibration data saved at {}'.format(calib_data_file))
            except Exception as e:
                print('Calibration failed using device data ({}), ' \
                      'You can try loading a local `calib-data.bin` blob, ' \
                      'the device should work anyway, so skipping...'.format(e))

        print('Init database...')
        init_db()

        vfs_tls.reset()

        print('That\'s it, pairing with {} finished'.format(self.dev_str))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('--driver-uri')
    parser.add_argument('--firmware-path', type=argparse.FileType('r'))
    parser.add_argument('--calibration-data', type=argparse.FileType('r'))
    parser.add_argument('--host-product')
    parser.add_argument('--host-serial')
    parser.add_argument('--simulate-virtualbox', action='store_true')

    args = parser.parse_args()

    if os.geteuid() != 0:
        raise Exception('This script needs to be executed as root')

    if args.simulate_virtualbox and (args.host_product or args.host_serial):
        parser.error("--simulate-virtualbox is incompatible with host params.")

    usb_dev = None
    for d in VFS:
        dev = usb_core.find(idVendor=0x138a, idProduct=d.value)
        if dev:
            dev_type = d
            usb_dev = dev

    if not usb_dev:
        raise Exception('No supported validity device found')

    try:
        subprocess.check_call(['innoextract', '--version'],
            stdout=subprocess.DEVNULL)
    except Exception as e:
        print('Impossible to run innoextract: {}'.format(e))
        sys.exit(1)

    vfs_initializer = VFSInitializer(args, usb_dev, dev_type)

    with tempfile.TemporaryDirectory() as fwdir:
        if args.firmware_path:
            fwpath = args.firmware_path.name
        else:
            fwpath = vfs_initializer.download_and_extract_fw(fwdir,
                fwuri=args.driver_uri)

        input('The device will be now reset to factory and associated to the ' \
                'current laptop.\nPress Enter to continue (or Ctrl+C to cancel)...')

        vfs_initializer.try_factory_reset()
        vfs_initializer.sleep()
        vfs_initializer.pair(fwpath)

    sys.exit(55)
