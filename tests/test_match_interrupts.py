import unittest
from unittest.mock import patch

from validitysensor.sensor import FingerNotMatchedException, sensor


class MatchInterruptTests(unittest.TestCase):
    def assert_no_match_interrupt(self, sensor_type, interrupt):
        original_type = getattr(sensor, 'real_device_type', None)
        sensor.real_device_type = sensor_type
        try:
            with patch('validitysensor.sensor.tls.app', return_value=b'\x00\x00'), \
                    patch('validitysensor.sensor.usb.wait_int',
                          return_value=bytes([interrupt, 0, 1, 0, 0xdb])):
                with self.assertRaises(FingerNotMatchedException):
                    sensor.match_finger()
        finally:
            sensor.real_device_type = original_type

    def test_d51_uses_interrupt_5_for_no_template(self):
        self.assert_no_match_interrupt(0xd51, 5)

    def test_969_uses_interrupt_4_for_no_template(self):
        self.assert_no_match_interrupt(0x969, 4)

    def test_d51_firmware_can_use_interrupt_4_for_no_template(self):
        # Captured on physical 138a:00ab / 0xd51 hardware after reboot.
        self.assert_no_match_interrupt(0xd51, 4)

    def test_969_firmware_can_use_interrupt_5_for_no_template(self):
        self.assert_no_match_interrupt(0x969, 5)

    def test_unrelated_interrupt_4_is_not_misclassified(self):
        original_type = getattr(sensor, 'real_device_type', None)
        sensor.real_device_type = 0xd51
        try:
            with patch('validitysensor.sensor.tls.app', return_value=b'\x00\x00'), \
                    patch('validitysensor.sensor.usb.wait_int',
                          return_value=b'\x04\xff\xff\xff\xff'):
                with self.assertRaisesRegex(Exception, 'Finger not recognized'):
                    sensor.match_finger()
        finally:
            sensor.real_device_type = original_type


if __name__ == '__main__':
    unittest.main()
