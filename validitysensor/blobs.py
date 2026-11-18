def __load_blob(blob: str) -> bytes:
    from .usb import usb

    if usb.usb_dev().idVendor == 0x138a:
        if usb.usb_dev().idProduct == 0x0090:
            from . import blobs_90 as blobs
        elif usb.usb_dev().idProduct == 0x0097:
            from . import blobs_97 as blobs
        elif usb.usb_dev().idProduct == 0x009d:
            from . import blobs_9d as blobs
        elif usb.usb_dev().idProduct == 0x00ab:
            from . import blobs_d51 as blobs  # HP EliteBook 840 G5; d51 reset family
    elif usb.usb_dev().idVendor == 0x06cb:
        if usb.usb_dev().idProduct == 0x009a:
            from . import blobs_9a as blobs
        elif usb.usb_dev().idProduct == 0x00b7:
            # HP EliteBook x360 1040 G6 (0x969). Same blobs as blobs_9a except
            # reset_blob, and this one is accepted by the chip where the 9a
            # reset_blob is rejected with status 0404.
            from . import blobs_00cb as blobs
        elif usb.usb_dev().idProduct == 0x00cb:
            from . import blobs_00cb as blobs   # HP Pavilion x360 14-dh; 0x969, own reset_blob

    globals()[blob] = getattr(blobs, blob)
    return globals()[blob]


init_hardcoded = lambda: __load_blob('init_hardcoded')
init_hardcoded_clean_slate = lambda: __load_blob('init_hardcoded_clean_slate')
reset_blob = lambda: __load_blob('reset_blob')
db_write_enable = lambda: __load_blob('db_write_enable')
