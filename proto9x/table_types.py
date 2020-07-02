
from binascii import hexlify, unhexlify

class SensorTypeInfo:
    table=[]

    def get_by_type(sensor_type):
        from . import generated_tables
        for i in SensorTypeInfo.table:
            if i.sensor_type == sensor_type:
                return i

    def __init__(self, sensor_type, bytes_per_line, repeat_multiplier, lines_per_calibration_data, line_width, calibration_blob):
        self.sensor_type=sensor_type
        self.repeat_multiplier=repeat_multiplier
        self.lines_per_calibration_data=lines_per_calibration_data
        self.line_width=line_width
        self.bytes_per_line=bytes_per_line
        self.calibration_blob=unhexlify(calibration_blob)

    def __repr__(self):
        calibration_blob=hexlify(self.calibration_blob).decode()
        return 'SensorTypeInfo(sensor_type=0x%04x, bytes_per_line=0x%x, repeat_multiplier=%d, lines_per_calibration_data=%d, line_width=%d, calibration_blob=%s)' % (
            self.sensor_type, self.bytes_per_line, self.repeat_multiplier, self.lines_per_calibration_data, self.line_width, repr(calibration_blob))

class SensorCaptureProg:
    table=[]

    def get(major, minor, sensor_type):
        from . import generated_tables
        for i in SensorCaptureProg.table:
            if i.major == major and i.minor == minor and i.sensor_type == sensor_type:
                return i.blobs
        

    def __init__(self, major, minor, sensor_type, blobs):
        self.major=major
        self.minor=minor
        self.sensor_type=sensor_type
        blobs=[unhexlify(b) for b in blobs]
        self.blobs=blobs

    def __repr__(self):
        blobs=[hexlify(b).decode() for b in self.blobs]
        return 'SensorCaptureProg(major=%d, minor=%d, sensor_type=0x%x, blobs=%s)' % (
            self.major, self.minor, self.sensor_type, repr(blobs))
