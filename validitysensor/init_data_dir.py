import os

PYTHON_VALIDITY_DATA_DIR = '/var/run/python-validity/'

# Persistent state for the flashless sensors, which keep on the host what the others keep
# in their flash: the pairing, the calibration, the enrolled prints and the blobs extracted
# from the Windows driver.
PYTHON_VALIDITY_STATE_DIR = '/var/lib/python-validity/'

def init_data_dir():
    if not os.path.isdir(PYTHON_VALIDITY_DATA_DIR):
        os.mkdir(PYTHON_VALIDITY_DATA_DIR)

def init_state_dir():
    if not os.path.isdir(PYTHON_VALIDITY_STATE_DIR):
        os.makedirs(PYTHON_VALIDITY_STATE_DIR, mode=0o700)
