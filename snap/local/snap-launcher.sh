#!/bin/bash

export PYTHONPATH=$SNAP/usr/lib/python3/dist-packages:$PYTHONPATH

for p in $(ls -1d $SNAP/lib/python3*/site-packages); do
    PYTHONPATH=$PYTHONPATH:$p
done

if ! $(command -v lsusb) &> /dev/null; then
    echo "Unable to access to USB devices"
    echo " $SNAP_NAME is installed as a snap."
    echo " To allow it to function correctly you may need to run:"
    echo "   sudo snap connect $SNAP_NAME:raw-usb"
    exit 1
fi

$(command -v python3) $SNAP/vfs-tools/validity-sensors-initializer.py "$@"
ret=$?

if [ "$ret" -eq 0 ]; then
    echo "May the leds be with you (in 5 seconds)...!"
    (sleep 5 && \
     $(command -v python3) $SNAP/vfs-tools/led-dance.py &> /dev/null) &
fi

exit $ret
