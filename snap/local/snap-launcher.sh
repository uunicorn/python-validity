#!/bin/bash

if ! $(command -v lsusb) &> /dev/null; then
    echo "Unable to access to USB devices"
    echo " $SNAP_NAME is installed as a snap."
    echo " To allow it to function correctly you may need to run:"
    echo "   sudo snap connect $SNAP_NAME:raw-usb"
    exit 1
fi

led_dance() {
    $(command -v python3) $SNAP/vfs-tools/led-dance.py "$@"
}

if [ "$VFS_TOOL" == "led_dance" ]; then
    led_dance "$@"
    exit $?
else
    $(command -v python3) $SNAP/vfs-tools/validity-sensors-initializer.py "$@"
    ret=$?

    if [ "$ret" -eq 55 ]; then
        ret=0
        echo "May the leds be with you (in 5 seconds)...!"
        (sleep 5 && led_dance &> /dev/null) &
    fi

    exit $ret
fi
