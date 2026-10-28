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


def test_extract_frame_native_stats():
    stats = {}
    kps = m.extract_frame_native(_synthetic_frame(), stats=stats)
    assert stats['n_pool'] >= len(kps), "pool is pre-cap, can't be smaller"
    assert stats['med_score'] > 0
    # cap_score > 0 iff the 250-cap was actually hit
    assert (stats['cap_score'] > 0) == (stats['n_pool'] >= m.FRAME_KP_CAP)
    # the stats keyword must not change the extraction result
    assert kps == m.extract_frame_native(_synthetic_frame())


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


def test_ws_scaffold_is_prepatched_near_identity():
    # The near-identity sec0_pre transforms are applied once when the scaffold
    # is loaded; re-running the patcher must be a byte-level no-op.
    scaffold = m._load_ws_scaffold()
    patched, n = m.patch_pre_v30_near_identity(scaffold, m.NATIVE_WS_V30_REGIONS)
    assert n == 6
    assert patched == scaffold


def test_make_finger_data_matches_build_envelope():
    from validitysensor.sensor import Sensor
    ws, tid = bytes(range(256)) * 3, bytes(range(32))
    assert Sensor().make_finger_data(0xf5, ws, tid) == m.build_envelope(0xf5, ws, tid)


def test_assemble_template_cycles_frames_over_sections():
    a = [(10, 11, 0.0, bytes([1] * 16))]
    b = [(20, 21, 0.0, bytes([2] * 16))]
    env = m.assemble_template([a, b], subtype=0xf5)
    ws = env[12:12 + m.WS_SIZE]
    recs = [ws[base - m.V30_DESC_LEN:base + 2] for base in m.NATIVE_WS_V30_REGIONS]
    assert recs[0] == recs[2] == bytes([1] * 16) + bytes([10, 11])
    assert recs[1] == recs[3] == bytes([2] * 16) + bytes([20, 21])
    assert env[23072:23104] == m.compute_tid(ws)
