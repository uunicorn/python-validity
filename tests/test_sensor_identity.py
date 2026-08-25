import unittest

from validitysensor.hw_tables import dev_info_lookup


class SensorIdentityTests(unittest.TestCase):
    def test_lookup_does_not_expose_shared_table_entry(self):
        first = dev_info_lookup(0x190, 0x70)
        first.type = 0x199
        second = dev_info_lookup(0x190, 0x70)

        self.assertIsNot(first, second)
        self.assertEqual(second.type, 0xd51)


if __name__ == '__main__':
    unittest.main()
