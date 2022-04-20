finger_ids = {
    # https://fprint.freedesktop.org/fprintd-dev/Device.html#fingerprint-names
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
}

# Store the keys in the reverse order for faster lookups
finger_names = {}
for name, index in finger_ids.items():
    finger_names[index] = name