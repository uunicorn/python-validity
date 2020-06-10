# python-validity
Validity fingerprint sensor library.
Originally designed to capture some of my findings for 138a:0097, but if you manage to get it working for some other Validity sensor - pull requests are welcome.

## Setting up

To install Python dependencies run
```
$ pip3 install -r requirements.txt
```

## Initialization

### Automatic factory reset, pairing and firmware flashing

This repo includes `validity-sensors-initializer.py`, a simple tool that
helps initializing Validity fingerprint readers under linux, loading their
binary firmware and initializing them.

This tool currently only supports these sensors:
- 138a:0090 Validity Sensors, Inc. VFS7500 Touch Fingerprint Sensor
- 138a:0097 Validity Sensors, Inc.
Which are present in various ThinkPad and HP laptops.

These devices communicate with the laptop via an encrypted protocol and they
need to be paired with the host computer in order to work and compute the
TLS keys.
Such initialization is normally done by the Windows driver, however thanks to
the amazing efforts of Viktor Dragomiretskyy (uunicorn), and previously of
Nikita Mikhailov, we have reverse-engineerd the pairing process, and so it's
possible to do it under Linux with only native tools as well.

The procedure is quite simple:
- Device is factory-reset and its flash repartitioned
- A TLS key is negotiated, generated via host hw ID and serial
- Windows driver is downloaded from Lenovo to extract the device firmware
- The device firmware is uploaded to the device
- The device is calibrated

Once the chip is paired with the computer via this tool, it's possible to use
it in libfprint using the driver at
- https://github.com/3v1n0/libfprint/

#### Installing it as [snap](https://snapcraft.io/)

This tool can be easily installed [almost every linux distribution](https://snapcraft.io/docs/installing-snapd)
with all its dependencies as snap.

To do so:

```bash
sudo snap install validity-sensors-initializer

# Give it access to the usb devices
sudo snap connect validity-sensors-initializer:raw-usb

# Initialize the device
sudo validity-sensors-initializer
```

[![Get it from the Snap Store](https://snapcraft.io/static/images/badges/en/snap-store-black.svg)](https://snapcraft.io/validity-sensors-initializer)

---

### Getting the firmware

It's possible to just extract [official Lenovo device driver for vfs0097](https://support.lenovo.com/us/en/downloads/DS121407) or [driver for vfs0090](https://support.lenovo.com/us/en/downloads/DS120491) (also [part of the SCCM package](https://support.lenovo.com/ec/th/downloads/DS112113) using [innoextract](https://constexpr.org/innoextract/) (available for all the distros), or `wine`.

The only reason you need to do this is to find `6_07f_lenovo_mis.xpfwext` (for vfs0097) or `6_07f_Lenovo.xpfwext` (for vfs0090) and copy it to this project location.

      innoextract n1mgf03w.exe -e -I 6_07f_lenovo_mis.xpfwext # vfs0097
      innoextract n1cgn08w.exe -e -I 6_07f_Lenovo.xpfwext # vfs0090

### Factory reset
If your device was previously paired with another OS or computer, you need to do a factory reset.
This will erase all fingers from the internal database and make the device ready for pairing.
```
$ python3 factory-reset.py
$
```

### Pairing
After performing a factory reset you need to pair your device with a host computer.
This must be done only once, before you can enroll/identify/verify fingers.
```
$ python3 pair.py
Initializing flash...
Detected Flash IC: W25Q80B, 1048576 bytes
Clean slate
Uploading firmware...
Sensor: VSI 55E  FM209-001
Loaded FWExt version 1.1 (Sat Feb  3 05:07:30 2018), 8 modules
Calibrating...
Sensor: VSI 55E  FM209-001
FWExt version 1.1 (Sat Feb  3 05:07:30 2018), 8 modules
Calibration data loaded from the file.
Init database...
Creating a new user storage object
Creating a host machine GUID record
That's it, pairing's finished
$ 
```

## Examples
Here is a couple of examples of how you can use this library. All examples assume that your device is already paired.

### Initialize a session
Before talking to a device you will need to open it and start a new TLS session
```
$ python3
Python 3.6.7 (default, Oct 22 2018, 11:32:17) 
[GCC 8.2.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> from prototype import *
>>> open97()
>>>
```
Or load previosly saved TLS session (see comments in [holdthedoor.py](holdthedoor.py))
```
$ python3
Python 3.6.7 (default, Oct 22 2018, 11:32:17) 
[GCC 8.2.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> from prototype import *
>>> load97()
>>> 
```

### Enroll a new user
Note: 0xf5 == WINBIO_FINGER_UNSPECIFIED_POS_01 (see [ms docs](https://docs.microsoft.com/en-us/windows/desktop/SecBioMet/winbio-ansi-381-pos-fingerprint-constants))
```
>>> db.dump_all()
 8: User S-1-5-21-111111111-1111111111-1111111111-1000 with 1 fingers:
     9: f5 (WINBIO_FINGER_UNSPECIFIED_POS_01)
>>> enroll(sid_from_string('S-1-5-21-394619333-3876782012-1672975908-3333'), 0xf5)
Waiting for a finger...
Progress: 14 % done
Progress: 28 % done
Progress: 42 % done
Progress: 57 % done
Progress: 71 % done
Progress: 85 % done
Progress: 100 % done
All done
11
>>> db.dump_all()
 8: User S-1-5-21-111111111-1111111111-1111111111-1000 with 1 fingers:
     9: f5 (WINBIO_FINGER_UNSPECIFIED_POS_01)
10: User S-1-5-21-394619333-3876782012-1672975908-3333 with 1 fingers:
    11: f5 (WINBIO_FINGER_UNSPECIFIED_POS_01)
>>> 
```

### Delete database record (user/finger/whatever)
```
>>> db.dump_all()
 8: User S-1-5-21-111111111-1111111111-1111111111-1000 with 1 fingers:
     9: f5 (WINBIO_FINGER_UNSPECIFIED_POS_01)
10: User S-1-5-21-394619333-3876782012-1672975908-3333 with 1 fingers:
    11: f5 (WINBIO_FINGER_UNSPECIFIED_POS_01)
>>> db.del_record(11)
>>> db.dump_all()
 8: User S-1-5-21-111111111-1111111111-1111111111-1000 with 1 fingers:
     9: f5 (WINBIO_FINGER_UNSPECIFIED_POS_01)
10: User S-1-5-21-394619333-3876782012-1672975908-3333 with 0 fingers:
>>> 
```

### Identify a finger (scan)
```
>>> identify()
Recognised finger f5 (WINBIO_FINGER_UNSPECIFIED_POS_01) from user S-1-5-21-111111111-1111111111-1111111111-1000
Template hash: 36bc1fe077e59a3090c816fcf2798c30a85d8a8fbe000ead5c6a946c3bacef7b
```
## DBus service
Sources contain a simple DBus service which can impersonate [fprint](https://www.freedesktop.org/wiki/Software/fprint/) daemon. 
Install fprint, edit /usr/share/dbus-1/system-services/net.reactivated.Fprint.service by commenting out activation info:
```
#Exec=/usr/lib/fprintd/fprintd
#User=root
#SystemdService=fprintd.service
```
start a fake service with something like this:
```
while sleep 1; do
    python3 dbus-service.py
    echo "====restart==="
done
```


## Debugging
If you are curious you can enable tracing to see what flows in and out of device before and after encryption
```
>>> tls.trace_enabled=True
>>> usb.trace_enabled=True
>>> db.dump_all()
>tls> 17: 4b00000b0053746757696e64736f7200
>cmd> 1703030050c00a7ff1cf76e90f168141b4bc519ca9598eacb575ff01b7552a3707be8506b246d5272cb119e7b8b3eccd991cb7d8387245953ff1da62cebfb07fae7e47b9b536fb1a82185cc9399d30625ee3c1451f
<cmd< 1703030050b7a4a39e256bbe5a2589a6fbeec86057bead96f0b79ab6657dd9e851efaccddf9cd0108865aa98c510a1f8cd9b881b3166db553e5b4330c437f09daccbe261b259019774466ddb0d7f97fa67b6337329
<tls< 17: 0000030002000b00000008004c000a004c0053746757696e64736f7200
>tls> 17: 4a080000000000
>cmd> 1703030040ef982e5d6c403ff636c44cd53e7d0f98c21f67ff3b5b80f53555e4547028bd4d17cf5b0539ac0489238f1f066b8ba849120380cf979088d6c63249c873868c95
<cmd< 1703030090f16f4ed027f50103d5cf274a59323e5f25e084e21e4d42d4eab23abc867504ef80a700c775f03c0fafabee2e373fbf551d46e53ca957b86c53853a913e11c8cab98df41afc86af883b4e1b817024b212dbcdf1057a3bcdbc474381c5a5c37162167ff395e8102902c4e0d00b9b4931f0fa986ec3257c6bf2a5b55ea0b5349c035c20ed583522ac7ef9048e97a589a25e
<tls< 17: 00000800010000004c000900f5000300780b030000001c000000010500000000000515000000c76b9f06c7353a42c7353a42e803000000000000000000000000000000000000000000000000000000000000000000000000000000000000
>tls> 17: 4a0a0000000000
>cmd> 1703030040b522c55b73480e0d71a322abf8b65d97c9b55e9930206c463f998886cda4410d1b00ab41ec5b213d2ac18bf3bf61ce817446f27d643f99aba5a1d4cb80d18461
<cmd< 170303009061cef46670a21ca87043f1f4d55153eb46a19757de767d4ddbee736e2a775af63850a89ebe814b7e578979f1fb8a1c2133e0c6fa5b468cff9c731ef3f178b33334bdf64c03903dc2d95e9a16c656f1f8d06fa3431c3971607fec56f104ec7d4e73518705a289fac53fe54ddf33b30dad2b8c1fac67b7decf8c7f86dd843414e7f056a2ea8366611e5094c5491d5ade46
<tls< 17: 00000a00000000004c00030000001c000000010500000000000515000000c5698517bcff12e72496b763050d000000000000000000000000000000000000000000000000000000000000000000000000000000000000
 8: User S-1-5-21-111111111-1111111111-1111111111-1000 with 1 fingers:
     9: f5 (WINBIO_FINGER_UNSPECIFIED_POS_01)
10: User S-1-5-21-394619333-3876782012-1672975908-3333 with 0 fingers:
>>> 
```
