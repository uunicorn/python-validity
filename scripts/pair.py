
from time import sleep

from validitysensor.usb import usb
from validitysensor.tls import tls
from validitysensor.flash import read_tls_flash
from validitysensor.init_flash import init_flash
from validitysensor.upload_fwext import upload_fwext
from validitysensor.init_db import init_db
from validitysensor.sensor import sensor, reboot

#usb.trace_enabled=True
#tls.trace_enabled=True

def restart():
    print('Sleeping...')
    sleep(3)
    tls.reset()
    usb.open()
    usb.send_init()
    tls.parseTlsFlash(read_tls_flash())
    tls.open()

try:
    usb.open()
    print('Initializing flash...')
    init_flash()

    restart()
    print('Uploading firmware...')
    upload_fwext()

    restart()
    print('Calibrating...')
    sensor.open(False)
    sensor.calibrate()

    print('Init database...')
    init_db()

    print('That\'s it, pairing\'s finished')
finally:
    sleep(1)
    reboot()
