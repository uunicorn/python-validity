"""Smoke tests for the native (float) MoH pipeline.

These do NOT pin byte-exact output (this branch is intentionally non-byte-exact
— see the commit that introduced the float rewrite). They guard the contract
that the chip parses literally: keypoint bounds, descriptor length, the v30
record layout, the envelope framing, and the TID round-trip.

Run: PYTHONPATH=. python -m pytest tests/test_moh_native_smoke.py
"""
import numpy as np
import pytest

from validitysensor import moh_native as m


def _synthetic_frame(seed=7):
    """A textured 112x112 uint8 frame (gaussian blobs + noise) → Q16."""
    rng = np.random.default_rng(seed)
    yy, xx = np.mgrid[0:112, 0:112]
    img = np.full((112, 112), 128.0)
    for _ in range(60):
        cy, cx = rng.integers(8, 104, 2)
        amp = rng.uniform(-90, 90)
        r = rng.uniform(2, 6)
        img += amp * np.exp(-((yy - cy) ** 2 + (xx - cx) ** 2) / (2 * r * r))
    img = np.clip(img + rng.normal(0, 8, img.shape), 0, 255).astype(np.uint8)
    return img.astype(np.int32) << 16


def test_extract_frame_native_shape_and_bounds():
    kps = m.extract_frame_native(_synthetic_frame())
    assert kps, "expected at least one keypoint on a textured frame"
    assert len(kps) <= m.FRAME_KP_CAP
    for gx, gy, orient, desc in kps:
        assert 3 <= gx < 109 and 3 <= gy < 109, "keypoint outside the A960 bound"
        assert 0.0 <= orient < m.TWO_PI
        assert len(desc) == m.V30_DESC_LEN == 16


def test_serialize_v30_section_layout():
    desc = bytes(range(16))
    sec = m.serialize_v30_section([(5, 7, desc)], n_slots=m.V30_SECTION_RECORDS)
    assert len(sec) == m.V30_SECTION_BYTES
    assert sec[0:16] == desc          # [16B desc]
    assert sec[16] == 5 and sec[17] == 7  # [x][y]
    assert sec[18:36] == bytes(18)    # tail zero-padded


def test_native_template_envelope_and_tid():
    env = m.native_template(_synthetic_frame(), subtype=0x00f5)
    assert len(env) == 23136
    ws = env[12:12 + m.WS_SIZE]
    assert len(ws) == m.WS_SIZE
    # TID is recomputable from the WS body alone (no device secret).
    assert env[23072:23104] == m.compute_tid(ws)


def test_compute_tid_rejects_wrong_size():
    with pytest.raises(ValueError):
        m.compute_tid(b"\x00" * 100)


def test_subpix_refine_rejects_out_of_range():
    resp = np.zeros((57, 57))
    assert m.subpix_refine_kp(resp, 0, 10) is None    # x on the border
    assert m.subpix_refine_kp(resp, 10, 0) is None    # y on the border
    assert m.subpix_refine_kp(resp, 10, 10) is None   # flat → singular Hessian
