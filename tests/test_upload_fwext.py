import unittest
from unittest.mock import patch


class FirmwareRecoveryTests(unittest.TestCase):
    def test_repairs_only_documented_interrupted_upload_signature(self):
        from validitysensor import upload_fwext

        with patch.object(upload_fwext, 'get_fw_info',
                          side_effect=Exception(
                              'Signature validation failed: 044f')), \
                patch.object(upload_fwext, 'erase_flash') as erase:
            self.assertIsNone(upload_fwext.read_or_repair_firmware_info())

        erase.assert_called_once_with(2)

    def test_does_not_erase_firmware_for_other_probe_errors(self):
        from validitysensor import upload_fwext

        with patch.object(upload_fwext, 'get_fw_info',
                          side_effect=Exception('Failed: 0404')), \
                patch.object(upload_fwext, 'erase_flash') as erase:
            with self.assertRaisesRegex(Exception, 'Failed: 0404'):
                upload_fwext.read_or_repair_firmware_info()

        erase.assert_not_called()


if __name__ == '__main__':
    unittest.main()
