
from binascii import hexlify, unhexlify

class SensorTypeInfo:
    table=[]
    sensor_type=None
    lines_per_calibration_data=None
    line_width=None
    calibration_blob=None

    def get_by_type(sensor_type):
        from . import generated_tables
        for i in SensorTypeInfo.table:
            if i.sensor_type == sensor_type:
                return i

    def __init__(self, sensor_type, lines_per_calibration_data, line_width, calibration_blob):
        self.sensor_type=sensor_type
        self.lines_per_calibration_data=lines_per_calibration_data
        self.line_width=line_width
        self.calibration_blob=unhexlify(calibration_blob)

    def __repr__(self):
        calibration_blob=hexlify(self.calibration_blob).decode()
        return 'SensorTypeInfo(sensor_type=0x%04x, lines_per_calibration_data=%d, line_width=%d, calibration_blob="%s")' % (
            self.sensor_type, self.lines_per_calibration_data, self.line_width, calibration_blob)

