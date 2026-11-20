import unittest
from struct import pack

from validitysensor.clean_slate_probe import (
    READ_ONLY_COMMANDS,
    decode_response,
    probe,
)


class CleanSlateProbeTests(unittest.TestCase):
    def test_command_set_is_read_only_and_fixed(self):
        self.assertEqual(
            READ_ONLY_COMMANDS,
            (
                ('flash-info', b'\x3e'),
                ('rom-info', b'\x01'),
                ('sensor-identity', b'\x75'),
                ('firmware-info', b'\x43\x02'),
            ),
        )

    def test_decodes_zero_partition_flash(self):
        response = b'\0\0' + pack(
            '<HHHHHHH', 0xef, 0x40, 256, 1, 4096, 2, 0)
        result = decode_response('flash-info', response)
        self.assertEqual(result['partition_count'], 0)
        self.assertEqual(result['jedec_id'], '00ef:0040')

    def test_decodes_sensor_identity(self):
        response = b'\0\0' + pack('<LHH', 0, 0, 0xd51)
        result = decode_response('sensor-identity', response)
        self.assertEqual(result['sensor_major'], 0xd51)
        self.assertEqual(result['reserved'], 0)

    def test_preserves_error_response_without_guessing_payload(self):
        result = decode_response('sensor-identity', b'\x04\x04')
        self.assertEqual(result['status'], 0x0404)
        self.assertNotIn('sensor_major', result)

    def test_probe_uses_each_allowlisted_command_once(self):
        requests = []

        def command(request):
            requests.append(request)
            return b'\x04\x04'

        results = probe(command)
        self.assertEqual(requests, [item[1] for item in READ_ONLY_COMMANDS])
        self.assertEqual(len(results), len(READ_ONLY_COMMANDS))


if __name__ == '__main__':
    unittest.main()
