#!/bin/bash

export PYTHONPATH=$SNAP/usr/lib/python3/dist-packages:$PYTHONPATH

for p in $(ls -1d $SNAP/lib/python3*/site-packages); do
    PYTHONPATH=$PYTHONPATH:$p
done

if ! $(command -v lsusb) -d 138a: &> /dev/null; then
    echo "Unable to access to USB devices"
    echo " $SNAP_NAME is installed as a snap."
    echo " To allow it to function correctly you may need to run:"
    echo "   sudo snap connect $SNAP_NAME:raw-usb"
    echo "   sudo snap connect $SNAP_NAME:hardware-observe"
    exit 1
fi

run_tool() {
    [ -n "$VFS_TOOL" ] && \
        local args=(--tool "$VFS_TOOL")

    $(command -v python3) $SNAP/vfs-tools/validity-sensors-tools.py \
        "${args[@]}" "$@"
}

run_tool "$@"
ret=$?

if [ "$ret" -eq 0 ] && [[ "$VFS_TOOL" == 'initializer' ]]; then
    unset VFS_TOOL
    echo "May the leds be with you...!"
    (run_tool --tool=led-dance &> /dev/null) &
fi

exit $ret
