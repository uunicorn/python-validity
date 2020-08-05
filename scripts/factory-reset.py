from validitysensor.usb import usb
from validitysensor.sensor import factory_reset, RebootException

try:
    usb.open()
    factory_reset()
except RebootException:
    pass
