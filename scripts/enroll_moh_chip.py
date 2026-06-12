"""Debug/CLI tool: native enrollment on a 06cb:00a2 sensor.

Captures N frames from the connected sensor, runs the native feature
pipeline (validitysensor/moh_native.py), builds a chip-storable template
from the baked-in framing scaffold (blobs_a2.build_ws_scaffold) — no
captured reference template needed — stores it via raw 0x47, then
optionally tries to identify the finger to verify the chip accepts our
template.

Run on a machine with the sensor plugged in and python-validity
initialised (i.e., the usual `validity-sensors-firmware` & TLS handshake
have already been done — same prerequisites as the existing `enroll`
script in this repo).

Usage:
  sudo python3 scripts/enroll_moh_chip.py \\
      --parent <user_dbid> \\
      [--match]                          # try to identify after enroll

  --subtype N     WinBio subtype (= finger position). Defaults to 0xf5
                  (right index, common test). Look at validitysensor/
                  fingerprint_constants.py for the full list.

  --match         after storing, capture a fresh frame and ask the chip
                  to identify (sensor.match_finger). If the chip matches
                  it back to the userid we just enrolled, the pipeline
                  is end-to-end working.
"""
import argparse
import logging
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))


def _try_match(log):
    """Capture a fresh frame and ask the chip to identify. Returns True on a
    match, False on 'not recognized' (logged cleanly, no traceback)."""
    from validitysensor.sensor import sensor as Sensor
    log.info('LIFT FINGER, then place the SAME finger to verify the chip matches ...')
    try:
        usrid, subtype_out, hsh = Sensor.identify(
            lambda e: log.warning(f'identify capture retry: {e}'))
        log.info(f'✓ CHIP MATCHED: usrid={usrid}, subtype=0x{subtype_out:x}')
        return True
    except Exception as e:
        log.warning(f'✗ NO MATCH ({e})')
        return False


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--subtype', default='0xf5',
                    help='WinBio subtype, hex or decimal (default 0xf5)')
    ap.add_argument('--parent', type=int, default=5,
                    help='parent user dbid (use --list-users to find the '
                         'StgWindsor user dbid; default 5)')
    ap.add_argument('--frames', type=int, default=6,
                    help='number of DISTINCT placements to capture (default 6); '
                         'the best 4 (most keypoints) fill the template\'s 4 v30 '
                         'sections. Vary finger placement between captures for '
                         'coverage.')
    ap.add_argument('--match', action='store_true',
                    help='after enroll, capture again and try to identify')
    ap.add_argument('--dry-run', action='store_true',
                    help='build the envelope but DO NOT store on chip; '
                         'write it to /tmp/native_envelope.bin instead')
    ap.add_argument('--match-only', action='store_true',
                    help='do NOT enroll; just run the chip identify against '
                         'whatever is already stored.')
    ap.add_argument('--delete-dbid', type=int, default=None,
                    help='delete the FINGER record with this dbid (see '
                         '--list-users), then exit. '
                         'Refuses to delete a USER record (would orphan fingers) '
                         'unless --force.')
    ap.add_argument('--force', action='store_true',
                    help='allow --delete-dbid to delete a non-finger record')
    ap.add_argument('--user-sid', default=None,
                    help='enroll under this user SID, creating the user if it '
                         'does not exist (self-contained: no pre-existing '
                         'user needed). Overrides --parent.')
    ap.add_argument('--list-users', action='store_true',
                    help='dump the chip DB tree (db.dump_raw) and exit; '
                         'use to find a real parent dbid to pass via --parent')
    args = ap.parse_args()

    logging.basicConfig(level=logging.INFO,
                        format='%(asctime)s %(levelname)s %(message)s')
    log = logging.getLogger('enroll_moh_chip')

    # Imports that need the venv + libusb actually wired
    from validitysensor.init import open as open_device
    from validitysensor.sensor import sensor as Sensor, RebootException
    from validitysensor.db import db

    subtype = int(args.subtype, 0)
    parent = args.parent

    log.info('reference-free: using baked-in WS-body framing scaffold')

    try:
        open_device()
    except RebootException:
        log.info('sensor rebooted — re-opening')
        open_device()

    if args.delete_dbid is not None:
        try:
            rec = db.get_record_value(args.delete_dbid)
            rtype = rec.type
        except Exception:
            rtype = None
        if rtype is not None and rtype != 6 and not args.force:
            log.error(f'dbid={args.delete_dbid} is type {rtype} '
                      f'({"USER" if rtype == 5 else "non-finger"}), not a FINGER '
                      f'(type 6). Deleting it would orphan its children. Pick a '
                      f'FINGER dbid from --list-users, or pass --force.')
            return 2
        log.info(f'deleting record dbid={args.delete_dbid} (type {rtype}) ...')
        try:
            db.del_record(args.delete_dbid)
            log.info(f'✓ deleted dbid={args.delete_dbid}')
        except Exception as e:
            log.error(f'delete failed: {e}')
            return 2
        return 0

    if args.match_only:
        ok = _try_match(log)
        log.info('MATCH-ONLY (chip identify against stored fingers): '
                 + ('MATCHED.' if ok else 'NO MATCH.'))
        return 0 if ok else 3

    if args.list_users:
        log.info('chip user storage + enrolled users (find parent dbid here):')
        try:
            stg = db.get_user_storage(name='StgWindsor')
            log.info(f'  StgWindsor: dbid={stg.dbid}, '
                      f'{len(stg.users)} user(s)')
            for u_meta in stg.users:
                udbid = u_meta['dbid']
                try:
                    u = db.get_user(udbid)
                    log.info(f'    user dbid={udbid} '
                              f'identity={u.identity!r} '
                              f'fingers={len(u.fingers)}')
                    for f in u.fingers:
                        log.info(f'      finger dbid={f["dbid"]} '
                                  f'subtype=0x{f["subtype"]:02x}')
                except Exception as e:
                    log.info(f'    user dbid={udbid} (could not parse: {e})')
        except Exception as e:
            log.error(f'get_user_storage failed: {e}')
            log.info('try dumping all roots 1..16:')
            for r in range(1, 17):
                try:
                    rec = db.get_record_value(r)
                    val = bytes(rec.value)
                    log.info(f'  root {r}: type={rec.type} '
                              f'val[:32]={val[:32].hex()}')
                except Exception:
                    pass
        return 0

    if args.dry_run:
        # Capture + build envelope but don't talk to the chip.
        from validitysensor.sensor import CaptureMode, glow_start_scan, glow_end_scan
        from validitysensor.moh_native import native_template
        import numpy as np
        glow_start_scan()
        log.info('place finger now (dry-run, will not store)')
        x, y, w1, w2, img_data = Sensor.capture(CaptureMode.ENROLL)
        glow_end_scan()
        img = np.frombuffer(img_data, dtype=np.uint8).reshape(x, y)  # NO transpose (feature frame)
        if img.shape != (112, 112):
            ys = (np.arange(112) * img.shape[0] // 112)
            xs = (np.arange(112) * img.shape[1] // 112)
            img112 = img[ys[:, None], xs[None, :]]
        else:
            img112 = img
        img_q16 = img112.astype(np.int32) << 16
        # Log frame stats + save the raw frame for offline inspection.
        # A good capture looks like: 112x112, min=0 max=255 mean~135 std~75.
        log.info(f'  CAPTURE: raw dims {x}x{y} ({len(img_data)}B); 112x112 '
                 f'min={int(img112.min())} max={int(img112.max())} '
                 f'mean={float(img112.mean()):.1f} std={float(img112.std()):.1f}')
        _p = f'/tmp/native_capture_{x}x{y}.bin'
        with open(_p, 'wb') as fp:
            fp.write(img112.astype(np.uint8).tobytes())
        log.info(f'  saved capture -> {_p}')
        from validitysensor.moh_native import extract_frame_native as _ext
        log.info(f'  pipeline on live frame: {len(_ext(img_q16))} keypoints')
        envelope = native_template(img_q16, subtype=subtype)
        with open('/tmp/native_envelope.bin', 'wb') as f:
            f.write(envelope)
        log.info(f'✓ wrote /tmp/native_envelope.bin ({len(envelope)} bytes)')
        return 0

    if args.user_sid:
        usr = db.lookup_user(args.user_sid)
        if usr is None:
            parent = db.new_user(args.user_sid)
            log.info(f'created user {args.user_sid!r} → dbid {parent}')
        else:
            parent = usr.dbid
            log.info(f'using existing user {args.user_sid!r} → dbid {parent}')

    log.info(f'enrolling subtype 0x{subtype:x} under parent dbid {parent} '
              f'with {args.frames} frame(s)...')
    recid = Sensor.enroll_moh(parent, subtype,
                                   num_frames=args.frames)
    log.info(f'✓ native enrollment stored, recid={recid}')

    if args.match:
        # identify() = capture(IDENTIFY) (waits for finger-present) + match.
        if _try_match(log):
            log.info('  → native pipeline produces chip-acceptable templates!')
            return 0
        return 3

    return 0


if __name__ == '__main__':
    sys.exit(main())
