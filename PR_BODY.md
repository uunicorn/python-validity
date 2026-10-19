### Summary
This PR introduces native Linux driver support for the **Synaptics WBDI 06cb:008a** fingerprint sensor (Viper family, ASIC 57K0 FM-154-124, ROM 6.20), as found on Toshiba / Dynabook Tecra X40-D, Portégé, and related models.

Resolves #4

### Background & Hardware Reality
1. **Match-on-Host (MoH) Architecture**:
   Unlike the 0090/0097/009a devices, the 008a sensor is strictly Match-on-Host. `GetFirmwareInfo (0x4302)` returns `0x04af` ("no firmware detected"), and Match-on-Chip commands (`0x68`, `0x5e`) return error `0401` (invalid command). The sensor does not require or use a `.xpfwext` firmware extension.
2. **Flash Disconnect Avoidance**:
   Attempting to write biometric templates directly to the SPI flash table triggers bus contention and USB device disconnects (`USBError 19: No such device`). Moving template storage to the host filesystem completely stabilizes the device.

### Implementation Details
- **Frame Acquisition**: Calibrated using sensor initialization sequence and passive interrupt awaiting on EP `0x83` to stream full 56×144 8-bit grayscale matrix frames (8,064 bytes).
- **Matching Engine**: 2D Phase Correlation (`numpy.fft.fft2`) with 2D Hann window filtering (eliminating boundary edge step artifacts) and an angular tilt search (`[-12° .. +12°]`) with calibrated threshold `0.12`.
- **Multi-Touch Template Storage**: Host filesystem persistence in `/var/lib/python-validity/templates/{uid}_{subtype}.dat`.
- **Backward Compatibility**: Fully preserved for existing 0090, 0097, 009a, and 009d devices (conditioned on `device_info.type in [0x121, 0x2449]`).
- **Dependencies**: Added `numpy` to `setup.py` and `python3-numpy` to `debian/control`.

### Hardware Verification
Tested and fully verified on Ubuntu 24.04 LTS (Toshiba Tecra X40-D, `PT474U-06P001`). Native `fprintd-enroll`, `fprintd-verify`, and PAM authentication (`sudo -k && sudo whoami`, lock screen) are working reliably.
