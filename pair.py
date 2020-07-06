
from time import sleep

from proto9x.usb import usb
from proto9x.tls import tls
from proto9x.flash import read_tls_flash
from proto9x.init_flash import init_flash
from proto9x.upload_fwext import upload_fwext
from proto9x.init_db import init_db
from proto9x.sensor import sensor

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
