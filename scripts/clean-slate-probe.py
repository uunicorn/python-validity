#!/usr/bin/python3
"""Collect non-destructive metadata from a zero-partition sensor."""

import json
import sys

import usb.core
import usb.util

from validitysensor.clean_slate_probe import probe
from validitysensor.usb import supported_devices


def find_device():
    devices = list(usb.core.find(
        find_all=True,
        custom_match=lambda candidate: (
            candidate.idVendor, candidate.idProduct) in supported_devices,
    ))
    if len(devices) != 1:
        raise RuntimeError(
            'Expected exactly one supported sensor, found %d' % len(devices))
    return devices[0]


def main():
    device = find_device()
    if device.is_kernel_driver_active(0):
        raise RuntimeError(
            'A kernel driver owns interface 0; refusing to detach it in a '
            'read-only probe')

    try:
        # Do not call set_configuration() or reset(): the service has already
        # configured the USB device, and this probe must preserve its state.
        device.get_active_configuration()
        usb.util.claim_interface(device, 0)

        def command(request):
            device.write(0x01, request)
            return bytes(device.read(0x81, 100 * 1024))

        result = {
            'schema': 1,
            'usb': {
                'vendor_id': device.idVendor,
                'product_id': device.idProduct,
                'bcd_device': device.bcdDevice,
                'bus': device.bus,
                'address': device.address,
            },
            'commands': probe(command),
        }
        print(json.dumps(result, indent=2, sort_keys=True))
    finally:
        try:
            usb.util.release_interface(device, 0)
        finally:
            usb.util.dispose_resources(device)


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print('clean-slate probe failed: %s' % error, file=sys.stderr)
        sys.exit(1)
