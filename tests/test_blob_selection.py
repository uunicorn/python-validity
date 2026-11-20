import hashlib
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from validitysensor import blobs, sensor

HP_RESET_BLOB_SHA256 = '7f379b1648326f031753d2d0a974bae75bc59a95f847b9c6478a124f32b3c17a'


class BlobSelectionTests(unittest.TestCase):
    def load(self, vid, pid, name):
        loader = getattr(blobs, '__load_blob')
        saved = blobs.__dict__.get(name)
        dev = SimpleNamespace(idVendor=vid, idProduct=pid)
        try:
            with patch('validitysensor.usb.usb.usb_dev', return_value=dev):
                return loader(name)
        finally:
            # __load_blob caches the bytes in module globals; restore the lazy loader.
            blobs.__dict__[name] = saved

    def test_06cb_00b7_uses_hp_reset_blob(self):
        # Accepted by both 00b7 variants (0xd51 / FM-3439-001, 0x969 /
        # FM-3439-002); the Lenovo blobs_9a reset_blob is rejected with 0404.
        blob = self.load(0x06cb, 0x00b7, 'reset_blob')
        self.assertEqual(hashlib.sha256(blob).hexdigest(), HP_RESET_BLOB_SHA256)

    def test_06cb_00b7_non_reset_blobs_are_unchanged(self):
        from validitysensor import blobs_9a
        for name in ('init_hardcoded', 'init_hardcoded_clean_slate', 'db_write_enable'):
            self.assertEqual(self.load(0x06cb, 0x00b7, name), getattr(blobs_9a, name))


class FactoryResetTests(unittest.TestCase):
    def test_commit_refusal_after_accepted_blob_is_reported(self):
        with patch.object(sensor.usb, 'cmd', side_effect=[b'\x00\x00', b'\x04\x04']), \
                patch.object(sensor, 'reboot') as reboot:
            with self.assertRaisesRegex(Exception, 'refused to apply'):
                sensor.factory_reset()
        reboot.assert_not_called()


if __name__ == '__main__':
    unittest.main()
