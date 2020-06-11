
from time import sleep

from proto9x.usb import usb
from proto9x.tls import tls
from proto9x.flash import read_flash
from proto9x.init_flash import init_flash
from proto9x.upload_fwext import upload_fwext
from proto9x.calibrate import calibrate
from proto9x.init_db import init_db

#usb.trace_enabled=True
#tls.trace_enabled=True

def restart():
    print('Sleeping...')
    sleep(3)
    tls.reset()
    usb.open()
    usb.send_init()
    tls.parseTlsFlash(read_flash(1, 0, 0x1000))
    tls.open()

usb.open()
print('Initializing flash...')
init_flash()

restart()
print('Uploading firmware...')
upload_fwext()

restart()
print('Calibrating...')
calibrate()

print('Init database...')
init_db()

print('That\'s it, pairing\'s finished')
