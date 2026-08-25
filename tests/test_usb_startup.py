import unittest

from validitysensor.usb import requires_startup_usb_reset


def device(vendor, product):
    return type('UsbDevice', (), {
        'idVendor': vendor,
        'idProduct': product,
    })()


class UsbStartupTests(unittest.TestCase):
    def test_reset_is_limited_to_hardware_with_wedge_evidence(self):
        self.assertTrue(requires_startup_usb_reset(device(0x138a, 0x00ab)))
        self.assertTrue(requires_startup_usb_reset(device(0x06cb, 0x00b7)))

    def test_legacy_and_unrelated_devices_keep_original_startup_path(self):
        for vendor, product in (
                (0x138a, 0x0090),
                (0x138a, 0x0097),
                (0x138a, 0x009d),
                (0x06cb, 0x009a),
                (0x06cb, 0x00cb)):
            with self.subTest(vendor=vendor, product=product):
                self.assertFalse(
                    requires_startup_usb_reset(device(vendor, product)))


if __name__ == '__main__':
    unittest.main()
