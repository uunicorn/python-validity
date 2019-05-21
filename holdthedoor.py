# There seems to be either a bug or a feature which renders the scanner unusable if 
# there were too many attemps to establish TLS connection with it. While device
# seems to magically fix itself after a while (8 hours?) it is extremely annoying
# when hacking.
#
# It is probably not that bad if all communication is done by a single service process which
# only initiates TLS connection once during system startup and then simply serves
# requests via DBus, DCOM or whatever. It is not that nice when you have a 
# standalone program which you are hacking and restarting all the time.
#
# So, to workaround the problem I'm trying to save and restore the TLS state
# between the prototype invocation. This works fine with one exception. As soon as 
# you close the last file descriptor associated with a USB device, the kernel automatically
# resets the device, effectively killing the established TLS state.
#
# This script helps to work around this last problem. It keeps an open descriptor which 
# prevents kernel from resetting the device configuration. It does not interfere with
# the main process and does not hold the claim on the inface. It just sits there
# doing nothing until you decide to quit.
#
# The same can be achived by running something like "read 4</dev/bus/usb/001/011" from
# a command line, but in this case you need to figure out what is the current bus/device 
# number yourself.

import usb.core
from usb.util import claim_interface, release_interface
from time import sleep

dev = usb.core.find(idVendor=0x138a, idProduct=0x0097)

# make sure we at least opened device descriptor
claim_interface(dev, 0)

sleep(0.2)

# release the iface, but keep the device open
release_interface(dev, 0)

# sit here, until the user press enter
raw_input()
