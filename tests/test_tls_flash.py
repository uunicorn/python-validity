import unittest

from validitysensor.tls import tls


class TlsFlashTests(unittest.TestCase):
    def test_interrupted_provisioning_reports_missing_pairing_data(self):
        # Partitions exist but the TLS partition holds only the empty blocks,
        # as left behind when a second daemon reset the device mid-write.
        flash = (tls.make_tls_flash_block(0, b'\0') +
                 tls.make_tls_flash_block(1, b'\0' * 0x100) +
                 tls.make_tls_flash_block(2, b'\0' * 0x100))
        flash += b'\xff' * (0x1000 - len(flash))
        with self.assertRaisesRegex(Exception, 'incomplete .*private key.*mask'):
            tls.parse_tls_flash(flash)


if __name__ == '__main__':
    unittest.main()
