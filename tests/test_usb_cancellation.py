import errno
import unittest

from usb.core import USBError

from validitysensor.usb import CancelledException, Usb


class TimeoutDevice:
    def __init__(self):
        self.read_count = 0

    def read(self, endpoint, size, timeout):
        self.read_count += 1
        raise USBError('timed out', errno=errno.ETIMEDOUT)


class UsbCancellationTests(unittest.TestCase):
    def test_early_cancel_is_not_cleared_by_wait(self):
        transport = Usb()
        transport.dev = TimeoutDevice()
        transport.request_cancel()

        with self.assertRaises(CancelledException):
            transport.wait_int()

        self.assertEqual(transport.dev.read_count, 0)

    def test_new_operation_explicitly_clears_previous_cancel(self):
        transport = Usb()
        transport.request_cancel()
        transport.clear_cancel()
        self.assertFalse(transport.cancel_event.is_set())


if __name__ == '__main__':
    unittest.main()
