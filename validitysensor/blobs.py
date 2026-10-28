def __device_blobs():
    from .usb import usb

    if usb.usb_dev().idVendor == 0x138a:
        if usb.usb_dev().idProduct == 0x0090:
            from . import blobs_90 as blobs
        elif usb.usb_dev().idProduct == 0x0097:
            from . import blobs_97 as blobs
        elif usb.usb_dev().idProduct == 0x009d:
            from . import blobs_9d as blobs
    elif usb.usb_dev().idVendor == 0x06cb:
        if usb.usb_dev().idProduct == 0x009a:
            from . import blobs_9a as blobs
        elif usb.usb_dev().idProduct == 0x00a2:
            from . import blobs_a2 as blobs

    return blobs


def __load_blob(blob: str) -> bytes:
    globals()[blob] = getattr(__device_blobs(), blob)
    return globals()[blob]


init_hardcoded = lambda: __load_blob('init_hardcoded')
init_hardcoded_clean_slate = lambda: __load_blob('init_hardcoded_clean_slate')
reset_blob = lambda: __load_blob('reset_blob')
db_write_enable = lambda: __load_blob('db_write_enable')

# Whether this device should enroll via the byte-exact native pipeline
# (Sensor.enroll_moh) instead of the DLL-style 0x68/0x6b enrollment
# session. Per-device blob modules opt in by defining `moh_enroll`;
# modules that don't define it default to False.
moh_enroll = lambda: bool(getattr(__device_blobs(), 'moh_enroll', False))
