
from usb97 import usb
from sensor import reboot

#usb.trace_enabled=True
#tls.trace_enabled=True

usb.open()
reboot()
