from enum import Enum, auto

class Blobs(Enum):
    init_hardcoded = auto()
    init_hardcoded_clean_slate = auto()
    reset_blob = auto()
    db_write_enable = auto()
    identify_prg = auto()
    enroll_prg = auto()
    calibrate_prg = auto()


def __load_blob(blob):
    from .usb import usb

    if usb.usb_dev().idVendor == 0x138a:
        if usb.usb_dev().idProduct == 0x0090:
            from . import blobs_90 as blobs
        elif usb.usb_dev().idProduct == 0x0097:
            from . import blobs_97 as blobs
    elif usb.usb_dev().idVendor == 0x06cb:
        if usb.usb_dev().idProduct == 0x009a:
            from . import blobs_9a as blobs

    globals()[blob] = getattr(blobs, blob)
    return globals()[blob]

for p in dir(Blobs):
    if isinstance(getattr(Blobs, p), Blobs):
        globals()[p] = lambda bname=p: __load_blob(bname)
