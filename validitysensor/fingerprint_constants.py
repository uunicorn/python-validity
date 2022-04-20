# maps fingerprint names from the fprint api to corresponding indices
# for legacy reasons uses ANSI381 naming if no fprint name is specified - see https://github.com/uunicorn/python-validity/pull/23

finger_ids = {
    # fprint https://fprint.freedesktop.org/fprintd-dev/Device.html#fingerprint-names
    "right-thumb": 1,
    "right-index-finger": 2,
    "right-middle-finger": 3,
    "right-ring-finger": 4,
    "right-little-finger": 5,
    "left-thumb": 6,
    "left-index-finger": 7,
    "left-middle-finger": 8,
    "left-ring-finger": 9,
    "left-little-finger": 10,

    # ANSI381 https://github.com/tpn/winsdk-10/blob/9b69fd26ac0c7d0b83d378dba01080e93349c2ed/Include/10.0.16299.0/shared/winbio_types.h#L864-L878
    "WINBIO_ANSI_381_POS_UNKNOWN": 0,
    "WINBIO_ANSI_381_POS_RH_FOUR_FINGERS": 13,
    "WINBIO_ANSI_381_POS_LH_FOUR_FINGERS": 14,
    "WINBIO_ANSI_381_POS_TWO_THUMBS": 15,

    # Microsoft specific extensions https://github.com/tpn/winsdk-10/blob/9b69fd26ac0c7d0b83d378dba01080e93349c2ed/Include/10.0.16299.0/shared/winbio_types.h#L920-L929
    "WINBIO_FINGER_UNSPECIFIED_POS_01": 0xf5,
    "WINBIO_FINGER_UNSPECIFIED_POS_02": 0xf6,
    "WINBIO_FINGER_UNSPECIFIED_POS_03": 0xf7,
    "WINBIO_FINGER_UNSPECIFIED_POS_04": 0xf8,
    "WINBIO_FINGER_UNSPECIFIED_POS_05": 0xf9,
    "WINBIO_FINGER_UNSPECIFIED_POS_06": 0xfa,
    "WINBIO_FINGER_UNSPECIFIED_POS_07": 0xfb,
    "WINBIO_FINGER_UNSPECIFIED_POS_08": 0xfc,
    "WINBIO_FINGER_UNSPECIFIED_POS_09": 0xfd,
    "WINBIO_FINGER_UNSPECIFIED_POS_10": 0xfe
}

# Store the keys in the reverse order for faster lookups
finger_names = {}
for name, index in finger_ids.items():
    finger_names[index] = name
