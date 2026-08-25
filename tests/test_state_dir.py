import os
import tempfile
import unittest

from validitysensor.init_data_dir import (
    migrate_legacy_calibration,
    migrate_legacy_firmware,
)


class CalibrationMigrationTests(unittest.TestCase):
    def test_migrates_legacy_calibration_once_without_overwrite(self):
        with tempfile.TemporaryDirectory() as root:
            runtime_dir = os.path.join(root, 'run')
            state_dir = os.path.join(root, 'lib')
            os.mkdir(runtime_dir)
            os.mkdir(state_dir)
            legacy_path = os.path.join(runtime_dir, 'calib-data.bin')
            state_path = os.path.join(state_dir, 'calib-data.bin')

            with open(legacy_path, 'wb') as calibration:
                calibration.write(b'original')
            migrate_legacy_calibration(runtime_dir, state_dir)

            with open(state_path, 'rb') as calibration:
                self.assertEqual(calibration.read(), b'original')
            self.assertEqual(os.stat(state_path).st_mode & 0o777, 0o600)

            with open(legacy_path, 'wb') as calibration:
                calibration.write(b'new legacy value')
            migrate_legacy_calibration(runtime_dir, state_dir)
            with open(state_path, 'rb') as calibration:
                self.assertEqual(calibration.read(), b'original')

    def test_migrates_cached_firmware_out_of_runtime_tmpfs(self):
        with tempfile.TemporaryDirectory() as root:
            runtime_dir = os.path.join(root, 'run')
            firmware_dir = os.path.join(root, 'lib', 'firmware')
            os.mkdir(runtime_dir)
            legacy_path = os.path.join(runtime_dir, 'sensor.xpfwext')
            with open(legacy_path, 'wb') as firmware:
                firmware.write(b'firmware')

            migrate_legacy_firmware(runtime_dir, firmware_dir)

            cached_path = os.path.join(firmware_dir, 'sensor.xpfwext')
            with open(cached_path, 'rb') as firmware:
                self.assertEqual(firmware.read(), b'firmware')
            self.assertEqual(os.stat(cached_path).st_mode & 0o777, 0o600)


if __name__ == '__main__':
    unittest.main()
