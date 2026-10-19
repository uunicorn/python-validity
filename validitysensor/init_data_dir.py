import os

PYTHON_VALIDITY_DATA_DIR = '/var/lib/python-validity/'

def init_data_dir():
    global PYTHON_VALIDITY_DATA_DIR
    candidates = [
        '/var/lib/python-validity/',
        os.path.expanduser('~/.cache/python-validity/'),
        '/tmp/python-validity/'
    ]
    for d in candidates:
        try:
            if not os.path.isdir(d):
                os.makedirs(d, mode=0o755, exist_ok=True)
            templates_dir = os.path.join(d, 'templates')
            if not os.path.isdir(templates_dir):
                os.makedirs(templates_dir, mode=0o755, exist_ok=True)
            PYTHON_VALIDITY_DATA_DIR = d
            return
        except PermissionError:
            continue
        except Exception:
            continue

init_data_dir()

