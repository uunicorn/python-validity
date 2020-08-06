import typing
from binascii import hexlify, unhexlify


class SensorTypeInfo:
    table: typing.List["SensorTypeInfo"] = []

    @classmethod
    def get_by_type(cls, sensor_type: int) -> typing.Optional["SensorTypeInfo"]:
        # noinspection PyUnresolvedReferences
        from . import generated_tables
        for i in cls.table:
            if i.sensor_type == sensor_type:
                return i

    def __init__(self, sensor_type: int, bytes_per_line: int, repeat_multiplier: int,
                 lines_per_calibration_data: int, line_width: int, calibration_blob: str):
        self.sensor_type = sensor_type
        self.repeat_multiplier = repeat_multiplier
        self.lines_per_calibration_data = lines_per_calibration_data
        self.line_width = line_width
        self.bytes_per_line = bytes_per_line
        self.calibration_blob = unhexlify(calibration_blob)

    def __repr__(self):
        calibration_blob = hexlify(self.calibration_blob).decode()
        return 'SensorTypeInfo(sensor_type=0x%04x, bytes_per_line=0x%x, repeat_multiplier=%d, lines_per_calibration_data=%d, line_width=%d, calibration_blob=%s)' % (
            self.sensor_type, self.bytes_per_line, self.repeat_multiplier,
            self.lines_per_calibration_data, self.line_width, repr(calibration_blob))


def fuzzy(expected, actual):
    if expected == actual:
        return 2
    elif expected == 0xffff:
        return 1
    else:
        return 0


def metric(i, rominfo):
    metric = 0
    metric |= fuzzy(i.major, rominfo.major)
    metric <<= 2
    metric |= fuzzy(i.minor, rominfo.minor)
    metric <<= 2
    metric |= fuzzy(i.build, rominfo.build)
    metric <<= 2
    metric |= fuzzy(i.u1, rominfo.u1)

    return metric


class SensorCaptureProg:
    table: typing.List["SensorCaptureProg"] = []

    @classmethod
    def get(cls, rominfo, sensor_type: int, a0: int, a1: int):
        # noinspection PyUnresolvedReferences
        from . import generated_tables

        maximum = 0
        found = None
        for i in SensorCaptureProg.table:
            if i.major != 0xffff and i.major != rominfo.major:
                continue

            if i.dev_type != 0xffff and i.dev_type != sensor_type:
                continue

            if i.a0 != 0xffff and i.a0 != a0:
                continue

            if i.a1 != 0xffff and i.a1 != a1:
                continue

            m = metric(i, rominfo)

            if m > maximum:
                found = i
                maximum = m

        if found is not None:
            return b''.join(found.blobs)

    def __init__(self, major: int, minor: int, build: int, u1: int, dev_type: int, a0: int, a1: int,
                 blobs: typing.Sequence[str]):
        self.major = major
        self.minor = minor
        self.build = build
        self.u1 = u1
        self.dev_type = dev_type
        self.a0 = a0
        self.a1 = a1
        self.blobs = [unhexlify(b) for b in blobs]

    def __repr__(self):
        blobs = [hexlify(b).decode() for b in self.blobs]

        return 'SensorCaptureProg(major=0x%x, minor=0x%x, build=0x%x, u1=0x%x, dev_type=0x%x, a0=0x%x, a1=0x%x, blobs=%s)' % (
            self.major, self.minor, self.build, self.u1, self.dev_type, self.a0, self.a1,
            repr(blobs))
