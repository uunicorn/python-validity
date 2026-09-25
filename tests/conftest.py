import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))


@pytest.fixture
def state_dir(tmp_path, monkeypatch):
    """Point everything that keeps flashless-sensor state at a temporary directory."""
    from validitysensor import init_flashless, sensor_2449

    d = str(tmp_path) + '/'
    monkeypatch.setattr(init_flashless, 'pairing_path', d + 'pairing.bin')
    monkeypatch.setattr(sensor_2449, 'PYTHON_VALIDITY_STATE_DIR', d)
    for m in (init_flashless, sensor_2449):
        monkeypatch.setattr(m, 'init_state_dir', lambda: None)
    return tmp_path
