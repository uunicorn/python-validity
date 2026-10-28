"""Match-on-Host (MoH) enrollment driver.

Isolated from sensor.py so the generic Sensor class stays device-agnostic.
`Sensor.enroll()` delegates here for devices whose blob sets `moh_enroll = True`
(see blobs_a2.py): instead of the DLL-style 0x68/0x6b enrollment session, MoH
devices build a template with the native feature pipeline (moh_native.py)
and store it via the raw 0x47 new_record protocol.

Three stages, each usable on its own:
    capture_frames()  — N placements → per-frame keypoints (retries captures)
    build_template()  — keypoints → 23136-byte envelope (pure)
    store_template()  — envelope → chip (0x47, no retry)
`enroll_moh()` chains them; `Sensor.enroll_moh` forwards `self` as `sensor`.
"""
import logging
import typing
from time import sleep

from usb import core as usb_core

from .db import db
from .usb import usb, CancelledException

UpdateCb = typing.Callable[[typing.Any, typing.Optional[Exception]], None]


def capture_frames(sensor, num_frames: int = 6,
                   update_cb: UpdateCb = lambda *a, **k: None,
                   max_attempts: int = 6,
                   min_frame_pool: typing.Optional[int] = None):
    """Capture `num_frames` placements and extract features from each.

    Returns a list of (kps, n_pool) per frame, in capture order. `kps` is the
    extract_frame_native() output, `n_pool` its UNCAPPED keypoint-pool size
    (the frame-quality rank — see enroll_moh docstring).

    A failed capture (sensor error mid-scan, finger lifted early) or a frame
    weaker than `min_frame_pool` is retried up to `max_attempts` times for
    THAT frame only; each failure is reported as update_cb(None, exc) so the
    OS can show a retry cue. USB errors and cancellation propagate at once.

    Cancellation is also checked before every capture: Sensor.cancel() sets
    usb.cancel, but usb.wait_int() clears that flag on entry, so a cancel that
    lands during the (host-side) feature extraction between two placements
    would otherwise be lost and the next capture would block on the sensor."""
    import numpy as np

    # Imported here (not at module top) to avoid a circular import:
    # sensor.py imports this module lazily from enroll(), so by the time we
    # run, sensor.py is fully loaded.
    from .sensor import CaptureMode, glow_start_scan, glow_end_scan
    from .moh_native import extract_frame_native, FRAME_KP_CAP

    if min_frame_pool is None:
        min_frame_pool = FRAME_KP_CAP

    # open-fprintd sends Cancel after every verify/enroll and only wait_int()
    # clears the flag, so a stale one would trip the check below at once.
    usb.cancel = False
    logging.info(f'enroll_moh: capturing {num_frames} frame(s)...')
    frames = []
    for f in range(num_frames):
        kps, stats = None, None
        for frame_attempt in range(max_attempts):
            if usb.cancel is True:
                raise CancelledException()
            glow_start_scan()
            logging.info(f'  frame {f+1}/{num_frames}: place finger')
            try:
                x, y, w1, w2, img_data = sensor.capture(CaptureMode.ENROLL)
            except (usb_core.USBError, CancelledException):
                glow_end_scan()
                raise
            except Exception as e:
                glow_end_scan()
                logging.warning(f'  frame {f+1} capture failed '
                                f'(attempt {frame_attempt+1}/{max_attempts}): {e}')
                update_cb(None, e)
                if frame_attempt + 1 == max_attempts:
                    raise
                sleep(0.1)
                continue
            glow_end_scan()
            img = np.frombuffer(img_data, dtype=np.uint8).reshape(x, y)
            img_q16 = img.astype(np.int32) << 16

            logging.info(f'  frame {f+1}: extracting features...')
            stats = {}
            kps = extract_frame_native(img_q16, h=x, w=y, stats=stats)
            logging.info(f"  frame {f+1}: {len(kps)} kp(s), "
                         f"pool={stats['n_pool']} "
                         f"cap_score={stats['cap_score']:.0f} "
                         f"med_score={stats['med_score']:.0f}")
            if stats['n_pool'] >= min_frame_pool:
                break
            # Quality gate: the frame did not even fill the 250 template
            # slots — severely degraded placement. On the last attempt keep
            # it anyway (the ranking in build_template deprioritizes it)
            # rather than failing the enrollment.
            logging.warning(
                f"  frame {f+1} too weak (pool={stats['n_pool']} "
                f'< {min_frame_pool}), recapture '
                f'(attempt {frame_attempt+1}/{max_attempts})')
        frames.append((kps, stats['n_pool']))
        # Report percentage complete after each frame is processed, via the
        # OS update_cb(progress_bytes, error) contract (see
        # scripts/prototype.py) — the percent is a single byte.
        update_cb(bytes([int((f + 1) * 100 / num_frames)]), None)
    return frames


def build_template(frames, subtype: int) -> bytes:
    """Build the 23136-byte envelope from capture_frames() output.

    The best len(NATIVE_WS_V30_REGIONS) frames (largest uncapped pool) are
    kept in capture order and each fills one v30 section, so every section
    holds one geometrically consistent placement. Frames are ranked by the
    UNCAPPED pool size — NOT by len(kps), which saturates at the 250 cap on
    every healthy frame (real placements pool ~500). See dev/FRAME-QUALITY.md.

    NOTE: this is a structural APPROXIMATION of the Windows DLL, not a
    reproduction of it. The DLL (EnrollmentUpdate → commit) folds every
    placement into a persistent session accumulator, culls keypoints by
    cross-frame CONSENSUS (sub_180008ec0 coord histograms — the source of the
    per-tile survivor counts), and builds each v30 section from a frame chosen
    by a learned QUALITY regression (sub_180008980 score vs the 0x699=1689
    gate). That regression's coefficients live in a runtime ctx object and are
    not statically portable, and we have no cross-frame consensus step, so we
    substitute: distinct placement per section, ranked by detector pool size.
    The chip's voting matcher tolerates this (enroll + recognize confirmed on
    hardware), but the exact DLL section<->frame mapping was never
    RE-confirmed."""
    from .moh_native import NATIVE_WS_V30_REGIONS, assemble_template

    logging.info('enroll_moh: building envelope...')
    n_sections = len(NATIVE_WS_V30_REGIONS)
    per_frame_kps = [kps for kps, _ in frames]
    if len(frames) > n_sections:
        best = sorted(range(len(frames)), key=lambda i: frames[i][1],
                      reverse=True)[:n_sections]
        logging.info(f'  keeping frames {sorted(best)} '
                     f'(pools: {[n for _, n in frames]})')
        per_frame_kps = [per_frame_kps[i] for i in sorted(best)]
    envelope = assemble_template(per_frame_kps, subtype)
    logging.info(f'  envelope: {len(envelope)} bytes')
    return envelope


def store_template(parent_dbid: int, envelope: bytes) -> int:
    """Store the envelope on the chip as a type-6 finger under `parent_dbid`.

    Raw 0x47 store: typ=6 direct, storage=3, 1-byte trailer appended — NOT
    the db.new_finger() type=0xb-becomes-6 magic path, which doesn't work
    without an active 0x68/0x6b enrollment session. No wait_int(): the
    typ=6-direct path doesn't emit an interrupt the way that path does.

    Storing under a non-existent dbid may succeed at the storage layer BUT
    the chip's matcher will silently fail to find the enrollment — callers
    must pass a real user dbid. A full partition or a chip rejection raises;
    both are deterministic, so callers must not retry by recapturing."""
    logging.info('enroll_moh: storing on chip...')
    # The chip answers 0x04b5 when the envelope does not fit; deleted records
    # keep their space (no compaction), so say what actually happened.
    info = db.db_info()
    if info.free < len(envelope):
        raise RuntimeError(
            f'template storage full: {info.free} bytes free, need {len(envelope)} '
            f'({info.records} records incl. deleted); wipe with scripts/wipe-template-db.py')
    recid = db.new_record(parent_dbid, 6, 3, envelope, trailer=b'\x00')
    logging.info(f'enroll_moh: stored recid={recid}')
    return recid


def enroll_moh(sensor, parent: typing.Union[int, typing.Callable[[], int]],
               subtype: int,
               update_cb: UpdateCb = lambda *a, **k: None,
               max_attempts: int = 6,
               num_frames: int = 6,
               min_frame_pool: typing.Optional[int] = None) -> int:
    """Enroll a finger using the native feature pipeline (no DLL):
    capture_frames() → build_template() → store_template().

    Args:
        sensor: the Sensor instance (provides capture()).
        parent: the user dbid the new finger attaches to, or a zero-arg
            callable returning it. The callable is invoked only AFTER all
            placements were captured, so a cancelled or failed enrollment
            never leaves a freshly created, finger-less user on the chip.
        subtype: the WinBio subtype (= finger position) for the record.
        update_cb: progress callback update_cb(progress_bytes, error)
            matching enroll()'s OS contract (see scripts/prototype.py).
            Called after each frame with a 1-byte percentage (0-100), or
            (None, exception) on a failed capture attempt.
        max_attempts: per-frame capture retries on transient errors.
        num_frames: how many placements to capture (default 6). The
            template has 4 v30 sections, each holding one placement; the
            best 4 frames (largest uncapped keypoint pool) fill them, so
            extra captures let weak placements be dropped.
        min_frame_pool: minimum UNCAPPED keypoint-pool size for a frame
            to be accepted; weaker frames are recaptured (within the
            per-frame retry budget). Defaults to FRAME_KP_CAP (250): a
            healthy placement yields a pool of ~500 (measured on real
            captures — see dev/FRAME-QUALITY.md), so a frame that cannot
            even fill its 250 template slots is severely degraded
            (partial contact / smear / light press). Note the CAPPED
            keypoint count is NOT a usable quality signal — even a
            half-empty frame still saturates the 250 cap.

    Returns: the recid created in the chip's storage."""
    frames = capture_frames(sensor, num_frames=num_frames, update_cb=update_cb,
                            max_attempts=max_attempts,
                            min_frame_pool=min_frame_pool)
    envelope = build_template(frames, subtype)
    parent_dbid = parent() if callable(parent) else parent
    return store_template(parent_dbid, envelope)
