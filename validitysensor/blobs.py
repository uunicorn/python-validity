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
            # Both 00b7 variants (0xd51 / FM-3439-001 and 0x969 / FM-3439-002)
            # accept the 11973-byte HP reset_blob (byte-identical in
            # blobs_d51 and blobs_00cb); blobs_9a's Lenovo reset_blob is
            # rejected with 0404. The other three blobs are identical across
            # all three sets. Zero-partition provisioning is still gated by
            # sensor identity in init_flash().
            from . import blobs_00cb as blobs
        elif usb.usb_dev().idProduct == 0x00cb:
            from . import blobs_00cb as blobs   # HP Pavilion x360 14-dh; 0x969, own reset_blob

    globals()[blob] = getattr(blobs, blob)
    return globals()[blob]


init_hardcoded = lambda: __load_blob('init_hardcoded')
init_hardcoded_clean_slate = lambda: __load_blob('init_hardcoded_clean_slate')
reset_blob = lambda: __load_blob('reset_blob')
db_write_enable = lambda: __load_blob('db_write_enable')
