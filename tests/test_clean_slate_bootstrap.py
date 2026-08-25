import hashlib
import unittest
from types import SimpleNamespace
from unittest.mock import patch


class CleanSlateBootstrapTests(unittest.TestCase):
    def test_d51_reset_blob_matches_windows_factory_capture(self):
        from validitysensor.blobs_d51 import reset_blob

        self.assertEqual(len(reset_blob), 11973)
        self.assertEqual(
            hashlib.sha256(reset_blob).hexdigest(),
            '7f379b1648326f031753d2d0a974bae75bc59a95f847b9c6478a124f32b3c17a',
        )

    def test_transport_init_precedes_flash_initialisation(self):
        from validitysensor import init

        calls = []
        with patch.object(init, 'init_data_dir'), \
                patch.object(init.usb, 'send_init',
                             side_effect=lambda: calls.append('transport')), \
                patch.object(init, 'init_flash',
                             side_effect=lambda: calls.append('flash')), \
                patch.object(init, 'read_tls_flash', return_value=b''), \
                patch.object(init.tls, 'parse_tls_flash'), \
                patch.object(init.tls, 'open'), \
                patch.object(init, 'upload_fwext'), \
                patch.object(init.sensor, 'open'), \
                patch.object(init, 'init_db'), \
                patch.object(init.atexit, 'register'):
            init.open_common()

        self.assertEqual(calls, ['transport', 'flash'])

    def test_d51_reset_preflight_matches_windows_capture(self):
        from validitysensor import init_flash

        calls = []
        with patch.object(init_flash, 'write_hw_reg32',
                          side_effect=lambda address, value:
                          calls.append(('write', address, value))), \
                patch.object(init_flash, 'read_hw_reg32',
                             side_effect=lambda address:
                             calls.append(('read', address)) or 3), \
                patch.object(init_flash, 'identify_sensor',
                             side_effect=lambda:
                             calls.append(('identify',))), \
                patch.object(init_flash, 'call_cleanups',
                             side_effect=lambda:
                             calls.append(('cleanup',))):
            init_flash.prepare_clean_slate_reset()

        self.assertEqual(calls, [
            ('write', 0x8000205c, 7),
            ('read', 0x80002080),
            ('identify',),
            ('cleanup',),
        ])

    def test_only_captured_complete_identity_has_write_bootstrap(self):
        from validitysensor import init_flash

        captured_rom = {
            'timestamp': 1415491824,
            'build': 164,
            'rom_major': 6,
            'rom_minor': 7,
            'product': 48,
        }
        for vendor, product, name in (
                (0x138a, 0x00ab, '57K0 FM- 154-120'),
                (0x06cb, 0x00b7, '57K0 FM-3439-001')):
            dev = type('UsbDevice', (), {
                'idVendor': vendor,
                'idProduct': product,
            })()
            captured_sensor = {
                'sensor_type': 0xd51,
                'sensor_name': name,
            }
            with self.subTest(vendor=vendor, product=product, name=name):
                self.assertTrue(init_flash.has_validated_clean_slate_bootstrap(
                    dev, captured_rom, captured_sensor))

        dev = type('UsbDevice', (), {
            'idVendor': 0x138a,
            'idProduct': 0x00ab,
        })()
        captured_sensor = {
            'sensor_type': 0xd51,
            'sensor_name': '57K0 FM- 154-120',
        }

        variants = (
            ({**captured_rom, 'build': 165}, captured_sensor),
            (captured_rom, {**captured_sensor, 'sensor_type': 0x969}),
            (captured_rom, {
                **captured_sensor,
                'sensor_name': '57K0 FM- 154-123',
            }),
        )
        for rom, sensor in variants:
            with self.subTest(rom=rom, sensor=sensor):
                self.assertFalse(
                    init_flash.has_validated_clean_slate_bootstrap(
                        dev, rom, sensor))

    def test_adjacent_usb_ids_cannot_use_captured_bootstrap(self):
        from validitysensor import init_flash

        rom = {
            'timestamp': 1415491824,
            'build': 164,
            'rom_major': 6,
            'rom_minor': 7,
            'product': 48,
        }
        sensor = {
            'sensor_type': 0xd51,
            'sensor_name': '57K0 FM- 154-120',
        }
        for vendor, product in ((0x06cb, 0x00cb),):
            dev = type('UsbDevice', (), {
                'idVendor': vendor,
                'idProduct': product,
            })()
            with self.subTest(vendor=vendor, product=product):
                self.assertFalse(
                    init_flash.has_validated_clean_slate_bootstrap(
                        dev, rom, sensor))

    def test_mismatched_ab_identity_is_refused_before_any_reset_write(self):
        from validitysensor import init_flash

        dev = SimpleNamespace(idVendor=0x138a, idProduct=0x00ab)
        rom = {
            'timestamp': 1415491824,
            'build': 164,
            'rom_major': 6,
            'rom_minor': 7,
            'product': 48,
        }
        unvalidated_sensor = {
            'sensor_type': 0x969,
            'sensor_name': '57K0 FM- 154-123',
        }
        with patch.object(
                init_flash, 'get_flash_info',
                return_value=SimpleNamespace(partitions=[])), \
                patch.object(init_flash.usb, 'usb_dev', return_value=dev), \
                patch.object(
                    init_flash, 'read_clean_slate_identity',
                    return_value=(rom, unvalidated_sensor)), \
                patch.object(init_flash, 'reset_blob') as reset:
            with self.assertRaisesRegex(
                    Exception, 'ROM and sensor identity do not match'):
                init_flash.init_flash()

        reset.assert_not_called()

    def test_validated_b7_uses_its_observed_direct_reset_ordering(self):
        from validitysensor import init_flash

        dev = SimpleNamespace(idVendor=0x06cb, idProduct=0x00b7)
        rom = {
            'timestamp': 1415491824,
            'build': 164,
            'rom_major': 6,
            'rom_minor': 7,
            'product': 48,
        }
        sensor = {
            'sensor_type': 0xd51,
            'sensor_name': '57K0 FM-3439-001',
        }
        with patch.object(
                init_flash, 'get_flash_info',
                return_value=SimpleNamespace(partitions=[])), \
                patch.object(init_flash.usb, 'usb_dev', return_value=dev), \
                patch.object(
                    init_flash, 'read_clean_slate_identity',
                    return_value=(rom, sensor)), \
                patch.object(init_flash, 'prepare_clean_slate_reset') as preflight, \
                patch.object(
                    init_flash.usb, 'cmd',
                    side_effect=RuntimeError('reset reached')):
            with self.assertRaisesRegex(RuntimeError, 'reset reached'):
                init_flash.init_flash()

        preflight.assert_not_called()

    def test_b7_969_identity_cannot_use_d51_bootstrap(self):
        from validitysensor import init_flash

        dev = type('UsbDevice', (), {
            'idVendor': 0x06cb,
            'idProduct': 0x00b7,
        })()
        rom = {
            'timestamp': 1415491824,
            'build': 164,
            'rom_major': 6,
            'rom_minor': 7,
            'product': 48,
        }
        sensor = {
            'sensor_type': 0x969,
            'sensor_name': '57K0 FM-3439-002',
        }
        self.assertFalse(init_flash.has_validated_clean_slate_bootstrap(
            dev, rom, sensor))


if __name__ == '__main__':
    unittest.main()
