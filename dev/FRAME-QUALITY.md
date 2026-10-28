# Frame-quality metric for native MoH enrollment (06cb:00a2)

**Question** (2026-06-12): `enroll_moh` captured N frames and kept the "best 4
by keypoint count" — but on hardware every frame returns the maximum 250
keypoints, so the selection was a no-op. Is a quality threshold needed, and on
what metric?

**Answer: yes — but on the *uncapped* detector pool size, not the capped
count.** Implemented in `moh_enrollment.enroll_moh` (rank by `n_pool`, gate at
`min_frame_pool = FRAME_KP_CAP = 250` with per-frame recapture).

## Why the capped count cannot rank frames

`extract_frame_native` caps its keypoint pool at `FRAME_KP_CAP = 250`
(matching the DLL's `sub_18000AAB0` 0xfa cap). Synthetic degradations of a
real captured frame (`dev/analyze_frame_quality.py`, frame from
`scripts/enroll_moh_chip.py --dry-run`):

| variant            | n_pool | capped | cap_score | med_score | tiles |
|--------------------|-------:|-------:|----------:|----------:|------:|
| original           |    495 |    250 |     37894 |     72677 |     9 |
| half-right-empty   |    250 |    250 |       757 |     45782 |     6 |
| two-thirds-empty   |    168 |    168 |         0 |     39979 |     3 |
| bottom-half-empty  |    258 |    250 |       985 |     24753 |     6 |
| blur-r1            |    417 |    250 |     17404 |     39653 |     9 |
| blur-r2            |    308 |    250 |      2904 |     12452 |     9 |
| blur-r3            |    213 |    213 |         0 |      2895 |     9 |
| contrast-0.5       |    455 |    250 |      9531 |     18160 |     9 |
| contrast-0.25      |    382 |    250 |      2357 |      4522 |     9 |
| contrast-0.1       |    146 |    146 |         0 |       927 |     8 |
| empty              |      0 |      0 |         0 |         0 |     0 |

Even a **half-empty** or **25%-contrast** frame still saturates the cap. The
capped count only drops once the frame is unusable.

- `n_pool` (uncapped pool) falls monotonically with degradation.
- `cap_score` (|resp| of the weakest *kept* keypoint) is the most sensitive
  discriminator (37894 → 757 at half-empty); it is 0 iff `n_pool < 250`.
- `med_score` also works but conflates "partial but sharp" with "weak".

## Real-capture calibration

`dev/analyze_real_captures.py` runs our detector front-end on the raw working
image tiles captured (gdb, `GDB_DUMP_F250`) from a real 8-placement Windows
driver enrollment (`/media/sf_vbox-rw/finger/frida_dumps/f250_raw_tile_*`,
session 1780170*):

| frame | n_pool | cap_score | med_score |
|------:|-------:|----------:|----------:|
| 0–7   | 493–516 | 47290–59479 | 76175–89021 |

The healthy band is tight: **pool ≈ 500 ≈ 2× the cap**. A frame that cannot
even fill its 250 template slots is therefore severely degraded (cf. the
synthetic table: the <250 cluster is ⅔-empty / heavy blur / 10% contrast).

The DLL's own minutia tables (`minutia_table_*_250.bin`, 3 sessions × 8–9
frames) confirm the DLL never ranks by count either: after its cross-frame
consensus cull it keeps only **108–150 active** keypoints per frame, and frame
selection uses a learned quality regression (`sub_180008980`, score clamped to
[0, 3000], gate `0x699 = 1689`) whose inputs are cross-frame inlier counts —
not portable to our single-frame pipeline.

## What was implemented (branch `moh-frame-quality`)

1. `moh_native.extract_frame_native(..., stats=None)` — optional dict out:
   `n_pool`, `cap_score`, `med_score` (computed in phase 2, before the cap).
2. `moh_enrollment.enroll_moh`:
   - ranks frames by `n_pool` (was: saturated `len(kps)`);
   - new `min_frame_pool` gate (default `FRAME_KP_CAP`): a frame with
     `n_pool < 250` is recaptured within the per-frame retry budget; on
     exhaustion it is kept (ranking deprioritizes it) rather than failing
     the enrollment;
   - logs `pool/cap_score/med_score` per frame so future hardware runs keep
     producing calibration data.

## Threshold choice & caveats

- `min_frame_pool = 250` is deliberately conservative: zero false rejects on
  the real healthy band (~500), and it has a structural meaning ("can fill
  the v30 section"). The gap between degraded (≤308) and healthy (≥493)
  synthetic/real clusters would tolerate up to ~400, but that is calibrated
  on ONE real finger — collect more `pool=` log lines from hardware before
  raising it.
- The degradation study uses synthetic perturbations of one real frame; real
  bad placements (dry finger, edge-of-sensor) should be spot-checked on
  hardware via the new per-frame log line.
- If a stronger discriminator is ever wanted, `cap_score` is the candidate
  (most dynamic range); thresholding it needs more real bad-frame data.
