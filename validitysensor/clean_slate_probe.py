"""Read-only metadata probe for unprovisioned Synaptics sensors.

This module deliberately contains no reset, erase, write, pairing, or reboot
command. Keep the command allowlist small: clean-slate devices are scarce and
must remain useful as provisioning fixtures.
"""

from binascii import hexlify
from struct import unpack

from .hw_tables import dev_info_lookup


READ_ONLY_COMMANDS = (
    ('flash-info', b'\x3e'),
    ('rom-info', b'\x01'),
    ('sensor-identity', b'\x75'),
    ('firmware-info', b'\x43\x02'),
)


def status(response):
    if len(response) < 2:
        return None
    return unpack('<H', response[:2])[0]


def decode_response(name, response):
    result = {
        'name': name,
        'status': status(response),
        'response': hexlify(response).decode(),
    }

    if result['status'] != 0:
        return result

    payload = response[2:]
    if name == 'flash-info' and len(payload) >= 14:
        jid0, jid1, blocks, unknown0, blocksize, unknown1, partitions = unpack(
            '<HHHHHHH', payload[:14])
        result.update({
            'jedec_id': '%04x:%04x' % (jid0, jid1),
            'blocks': blocks,
            'block_size': blocksize,
            'partition_count': partitions,
            'unknown0': unknown0,
            'unknown1': unknown1,
        })
    elif name == 'rom-info' and len(payload) >= 16:
        timestamp, build, major, minor, product, unknown = unpack(
            '<LLBBxBxxxB', payload[:16])
        result.update({
            'timestamp': timestamp,
            'build': build,
            'rom_major': major,
            'rom_minor': minor,
            'product': product,
            'unknown': unknown,
        })
    elif name == 'sensor-identity' and len(payload) == 8:
        zeroes, minor, major = unpack('<LHH', payload)
        result.update({
            'reserved': zeroes,
            'sensor_major': major,
            'sensor_minor': minor,
        })
        if zeroes == 0:
            device = dev_info_lookup(major, minor)
            if device is not None:
                result.update({
                    'sensor_type': device.type,
                    'sensor_name': device.name.strip(),
                })

    return result


def probe(command):
    """Run only the immutable read-only command set through ``command``."""
    return [decode_response(name, command(request))
            for name, request in READ_ONLY_COMMANDS]
