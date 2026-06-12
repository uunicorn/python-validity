"""Match-on-Host (MoH) enrollment driver.

Isolated from sensor.py so the generic Sensor class stays device-agnostic.
`Sensor.enroll()` delegates here for devices whose blob sets `moh_enroll = True`
(see blobs_a2.py): instead of the DLL-style 0x68/0x6b enrollment session, MoH
devices build a template with the native feature pipeline (moh_native.py)
and store it via the raw 0x47 new_record protocol.

The single entry point is `enroll_moh(sensor, ...)`; `Sensor.enroll_moh` is a
thin wrapper that forwards `self` as `sensor`.
"""
import logging
import typing
from struct import pack, unpack
from time import sleep

from usb import core as usb_core

from .db import db
from .flash import write_enable, call_cleanups
from .tls import tls
from .usb import CancelledException


def enroll_moh(sensor, parent_dbid: int, subtype: int,
               update_cb: typing.Callable[[typing.Any, typing.Optional[Exception]], None] = lambda *a, **k: None,
               max_attempts: int = 6,
               num_frames: int = 6):
    """Enroll a finger using the native feature pipeline (no DLL).

    Captures `num_frames` placements, builds a 23136-byte template via the
    native pipeline (our keypoints into the baked WS-body framing scaffold,
    recompute TID), and stores it via the raw 0x47 store protocol:
        typ=6 direct, storage=3, 1-byte trailer appended — NOT the
    db.new_finger() / type=0xb-becomes-6 magic path which doesn't actually
    work without an active 0x68/0x6b enrollment session.

    Args:
        sensor: the Sensor instance (provides capture()).
        parent_dbid: the existing user dbid the new finger attaches to.
            Use `db.dump_raw()` to see what users exist. Storing under
            a non-existent dbid succeeds at the storage layer BUT the
            chip's matcher will silently fail to find the enrollment.
        subtype: the WinBio subtype (= finger position) for the record.
        update_cb: progress callback update_cb(progress_bytes, error)
            matching enroll()'s OS contract (see scripts/prototype.py).
            Called after each frame with a 1-byte percentage (0-100), or
            (None, exception) on a failed attempt.
        max_attempts: how many capture retries on transient errors.
        num_frames: how many placements to capture (default 6). The
            template has 4 v30 sections, each holding one placement; the
            best 4 frames (most keypoints) fill them, so extra captures
            let weak placements be dropped.

    Returns: the recid created in the chip's storage."""
    import numpy as np

    # Imported here (not at module top) to avoid a circular import:
    # sensor.py imports this module lazily from enroll(), so by the time we
    # run, sensor.py is fully loaded.
    from .sensor import CaptureMode, glow_start_scan, glow_end_scan
    from .moh_native import (extract_frame_native, _load_ws_scaffold,
                             NATIVE_WS_V30_REGIONS,
                             patch_pre_v30_near_identity,
                             serialize_v30_section, V30_DESC_LEN,
                             compute_tid, _build_envelope)

    last_err = None
    for attempt in range(max_attempts):
        try:
            # 1. Capture N frames; multi-frame enrollment fills the WS
            # body's 4 v30 sections with different per-frame data.
            logging.info(f'enroll_moh: capturing {num_frames} frame(s)...')
            per_frame_kps = []
            for f in range(num_frames):
                # Per-frame retry: if the sensor errors mid-capture
                # (e.g. "Scanning problem: 8080000" — finger lifted too
                # early), retry JUST this frame instead of restarting
                # the whole enrollment.
                for frame_attempt in range(max_attempts):
                    glow_start_scan()
                    logging.info(f'  frame {f+1}/{num_frames}: place finger')
                    try:
                        x, y, w1, w2, img_data = sensor.capture(CaptureMode.ENROLL)
                        break
                    except usb_core.USBError:
                        glow_end_scan()
                        raise
                    except CancelledException:
                        glow_end_scan()
                        raise
                    except Exception as e:
                        glow_end_scan()
                        logging.warning(f'  frame {f+1} capture failed '
                                          f'(attempt {frame_attempt+1}/'
                                          f'{max_attempts}): {e}')
                        if frame_attempt + 1 == max_attempts:
                            raise
                        sleep(0.1)
                glow_end_scan()
                img = np.frombuffer(img_data, dtype=np.uint8).reshape(x, y)
                img_q16 = img.astype(np.int32) << 16

                logging.info(f'  frame {f+1}: extracting features...')
                kps = extract_frame_native(img_q16, h=112, w=112)
                logging.info(f'  frame {f+1}: {len(kps)} kp(s)')
                per_frame_kps.append(kps)
                # Report percentage complete after each frame is processed,
                # via the OS update_cb(progress_bytes, error) contract (see
                # scripts/prototype.py) — the percent is a single byte.
                # Fires before the store, so a raising callback retries a
                # capture (harmless) rather than duplicating a stored record.
                update_cb(bytes([int((f + 1) * 100 / num_frames)]), None)

            # 2. Build envelope. Distribute frames across the v30 sections
            # (round-robin if num_frames != #sections). The baked scaffold's
            # WS framing bytes stay (header, anchors, section counts).
            logging.info('enroll_moh: building envelope...')
            ws_body = bytearray(_load_ws_scaffold())
            regions = list(NATIVE_WS_V30_REGIONS)
            # sec0_pre must be NEAR-identity (load-bearing): the matcher skips
            # pure-identity records as the 'unmatched' sentinel, so near-identity
            # (tx=ty=1) makes each section a valid candidate alignment at verify.
            ws_body = bytearray(
                patch_pre_v30_near_identity(bytes(ws_body), regions)[0])
            # Keep the best len(regions) frames (most keypoints — a frame-
            # quality proxy) in capture order; each section then holds one
            # geometrically consistent placement.
            #
            # NOTE: this is a structural APPROXIMATION of the Windows DLL, not
            # a reproduction of it. The DLL (EnrollmentUpdate → commit) folds
            # every placement into a persistent session accumulator, culls
            # keypoints by cross-frame CONSENSUS (sub_180008ec0 coord
            # histograms — the source of the per-tile survivor counts), and
            # builds each v30 section from a frame chosen by a learned QUALITY
            # regression (sub_180008980 score vs the 0x699=1689 gate), not by
            # keypoint count. That regression's coefficients live in a runtime
            # ctx object and are not statically portable, and we have no
            # cross-frame consensus step, so we substitute: distinct placement
            # per section, ranked by keypoint count. The chip's voting matcher
            # tolerates this (enroll + recognize confirmed on hardware), but the
            # exact DLL section<->frame mapping was never RE-confirmed.
            if len(per_frame_kps) > len(regions):
                best = sorted(range(len(per_frame_kps)),
                              key=lambda i: len(per_frame_kps[i]),
                              reverse=True)[:len(regions)]
                per_frame_kps = [per_frame_kps[i] for i in sorted(best)]
            for idx, base in enumerate(regions):
                src_frame = per_frame_kps[idx % len(per_frame_kps)]
                # v30 records are [16B desc][x][y]; the record area starts
                # V30_DESC_LEN before the (x,y) anchor. The per-section trailer
                # is enroll-only bookkeeping the matcher ignores — leave it.
                section = serialize_v30_section(
                    [(gx, gy, desc) for (gx, gy, _o, desc) in src_frame[:250]])
                start = base - V30_DESC_LEN
                ws_body[start:start + len(section)] = section
            ws_body_bytes = bytes(ws_body)
            tid = compute_tid(ws_body_bytes)
            envelope = _build_envelope(subtype, ws_body_bytes, tid)
            logging.info(f'  envelope: {len(envelope)} bytes')

            # 3. Store via the proven replay protocol.  No wait_int()
            # — the typ=6-direct path doesn't emit an interrupt the
            # way db.new_finger's typ=0xb-magic path does.
            logging.info('enroll_moh: storing on chip...')
            db.db_info()
            write_enable()
            try:
                msg = (pack('<BHHHH', 0x47, parent_dbid, 6, 3, len(envelope))
                       + envelope + b'\x00')
                rsp = tls.cmd(msg)
                status, = unpack('<H', rsp[:2])
                if status != 0:
                    raise RuntimeError(
                        f'chip rejected new_finger: status=0x{status:04x}')
                recid, = unpack('<H', rsp[2:4])
            finally:
                call_cleanups()

            logging.info(f'enroll_moh: stored recid={recid}')
            return recid

        except usb_core.USBError:
            glow_end_scan()
            raise
        except CancelledException:
            glow_end_scan()
            raise
        except Exception as e:
            last_err = e
            update_cb(None, e)
            logging.exception('enroll_moh attempt %d failed', attempt)
            sleep(0.1)

    glow_end_scan()
    raise RuntimeError(f'enroll_moh: all {max_attempts} attempts failed; '
                        f'last error: {last_err}')
