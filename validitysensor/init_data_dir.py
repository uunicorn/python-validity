import os

PYTHON_VALIDITY_DATA_DIR = '/var/run/python-validity/'

def init_data_dir():
    if not os.path.isdir(PYTHON_VALIDITY_DATA_DIR):
        os.mkdir(PYTHON_VALIDITY_DATA_DIR)

