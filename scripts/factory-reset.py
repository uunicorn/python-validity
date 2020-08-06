from validitysensor.sensor import factory_reset, RebootException
from validitysensor.usb import usb

try:
    usb.open()
    factory_reset()
except RebootException:
    pass
