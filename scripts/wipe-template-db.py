"""Erase the template partition (4) of a 06cb:00a2 sensor.

Deleted records never free their space and factory-reset.py leaves this
partition alone, so after ~22 enrollments (deleted ones included) every store
fails with status 0x04b5. The next open() recreates an empty StgWindsor.
Stop the python3-validity service first.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from validitysensor.init import open as open_device
from validitysensor.flash import erase_flash
from validitysensor.db import db

open_device()
print('before:', db.db_info())
erase_flash(4)
print('template partition erased; sensor reboots on exit')
