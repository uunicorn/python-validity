
from binascii import hexlify, unhexlify
from time import ctime
from os.path import basename

from .tls import tls
from .usb import usb
from .sensor import reboot, write_hw_reg32, read_hw_reg32, identify_sensor
from .flash import flush_changes, read_flash, erase_flash, write_flash_all, write_fw_signature, get_fw_info
from .util import assert_status

firmware_home='/usr/share/python-validity'

def default_fwext_name():
    if usb.usb_dev().idVendor == 0x138a:
        if usb.usb_dev().idProduct == 0x0090:
            return '6_07f_Lenovo.xpfwext'

    # It looks like the firmware file must match DLL, not the hardware.
    # Both DLL and xpfwext are universal. 
    # The device dependant code seems to be loaded dynamically (via encrypted blobs).
    # So, it is important that xpfwext file is matching the blobs contents.
    return '6_07f_lenovo_mis_qm.xpfwext'

def upload_fwext(fw_path=None):
    # no idea what this is:
    write_hw_reg32(0x8000205c, 7)
    if read_hw_reg32(0x80002080) not in [2, 3]:
        raise Exception('Unexpected register value')

    dev=identify_sensor()
    print('Sensor: %s' % dev.name)
    # ^ TODO -- what is the real reason to detect HW at this stage?
    #           just a guess: perhaps it is used to construct fwext filename

    default_name = firmware_home + '/' + default_fwext_name()
    if not fw_path:
        fw_path = default_name
    elif basename(fw_path) != default_name:
        print('WARNING: Your device fw is supposed to be called {}'.format(
            default_name))

    with open(fw_path, 'rb') as f:
        fwext=f.read()

    fwext=fwext[fwext.index(b'\x1a')+1:]
    fwext, signature = fwext[:-0x100], fwext[-0x100:]

    fwi=get_fw_info(2)
    if fwi != None:
        raise Exception('FW is already present (version %d.%d (%s))' % (fwi.major, fwi.minor, ctime(fwi.buildtime)))

    #flush_changes()
    write_flash_all(2, 0, fwext)
    write_fw_signature(2, signature)

    fwi=get_fw_info(2)
    if fwi == None:
        raise Exception('No firmware detected')

    print('Loaded FWExt version %d.%d (%s), %d modules' % (fwi.major, fwi.minor, ctime(fwi.buildtime), len(fwi.modules)))

    # Reboot
    reboot()
