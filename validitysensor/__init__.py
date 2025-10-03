import os

# Path to the directory containing firmware files
PYTHON_VALIDITY_DATA_DIR = "/var/lib/python-validity"

# Ensure the directory exists
os.makedirs(PYTHON_VALIDITY_DATA_DIR, exist_ok=True)
