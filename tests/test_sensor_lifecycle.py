import unittest
from unittest.mock import patch

from validitysensor.sensor import sensor
from validitysensor.usb import CancelledException


class SensorLifecycleTests(unittest.TestCase):
    @patch('validitysensor.sensor.glow_end_scan')
    @patch('validitysensor.sensor.glow_start_scan')
    def test_identify_always_ends_scan_after_success(self, glow_start, glow_end):
        expected = (12, 3, b'hash')
        with patch.object(sensor, 'capture'), \
                patch.object(sensor, 'match_finger', return_value=expected):
            self.assertEqual(sensor.identify(lambda error: None), expected)

        glow_start.assert_called_once_with()
        glow_end.assert_called_once_with()

    @patch('validitysensor.sensor.glow_end_scan')
    @patch('validitysensor.sensor.glow_start_scan')
    def test_identify_always_ends_scan_after_cancel(self, glow_start, glow_end):
        with patch.object(sensor, 'capture', side_effect=CancelledException):
            with self.assertRaises(CancelledException):
                sensor.identify(lambda error: None)

        glow_start.assert_called_once_with()
        glow_end.assert_called_once_with()

    @patch('validitysensor.sensor.sleep')
    @patch('validitysensor.sensor.glow_end_scan')
    @patch('validitysensor.sensor.glow_start_scan')
    def test_each_rejected_capture_ends_before_retrying(
            self, glow_start, glow_end, _sleep):
        expected = (12, 3, b'hash')
        rejected = RuntimeError('capture quality rejected')
        updates = []
        with patch.object(sensor, 'capture', side_effect=[rejected, None]), \
                patch.object(sensor, 'match_finger', return_value=expected):
            self.assertEqual(sensor.identify(updates.append), expected)

        self.assertEqual(updates, [rejected])
        self.assertEqual(glow_start.call_count, 2)
        self.assertEqual(glow_end.call_count, 2)


if __name__ == '__main__':
    unittest.main()
