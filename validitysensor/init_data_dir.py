import os
import shutil

PYTHON_VALIDITY_DATA_DIR = '/var/run/python-validity/'
PYTHON_VALIDITY_STATE_DIR = '/var/lib/python-validity/'
PYTHON_VALIDITY_FIRMWARE_DIR = os.path.join(PYTHON_VALIDITY_STATE_DIR, 'firmware')


def migrate_legacy_calibration(runtime_dir=PYTHON_VALIDITY_DATA_DIR,
                               state_dir=PYTHON_VALIDITY_STATE_DIR):
    legacy_path = os.path.join(runtime_dir, 'calib-data.bin')
    state_path = os.path.join(state_dir, 'calib-data.bin')
    if os.path.isfile(legacy_path) and not os.path.exists(state_path):
        temporary_path = state_path + '.migrating'
        shutil.copyfile(legacy_path, temporary_path)
        os.chmod(temporary_path, 0o600)
        os.replace(temporary_path, state_path)


def migrate_legacy_firmware(runtime_dir=PYTHON_VALIDITY_DATA_DIR,
                            firmware_dir=PYTHON_VALIDITY_FIRMWARE_DIR):
    if not os.path.isdir(runtime_dir):
        return
    os.makedirs(firmware_dir, mode=0o700, exist_ok=True)
    os.chmod(firmware_dir, 0o700)
    for name in os.listdir(runtime_dir):
        if not name.endswith('.xpfwext'):
            continue
        source = os.path.join(runtime_dir, name)
        destination = os.path.join(firmware_dir, name)
        if not os.path.isfile(source) or os.path.exists(destination):
            continue
        temporary_path = destination + '.migrating'
        shutil.copyfile(source, temporary_path)
        os.chmod(temporary_path, 0o600)
        os.replace(temporary_path, destination)


def init_data_dir():
    for path in (PYTHON_VALIDITY_DATA_DIR, PYTHON_VALIDITY_STATE_DIR,
                 PYTHON_VALIDITY_FIRMWARE_DIR):
        os.makedirs(path, mode=0o700, exist_ok=True)
        os.chmod(path, 0o700)
    migrate_legacy_calibration()
    migrate_legacy_firmware()
