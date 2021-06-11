# python-validity
Validity fingerprint sensor driver.

Table of Contents
=================

   * [python-validity](#python-validity)
      * [Setting up](#setting-up)
         * [Error situations](#error-situations)
            * [list devices failed ](#list-devices-failed)
            * [Errors on startup](#errors-on-startup)
            * [Fingerprint not working after waking up from suspend](#fingerprint-not-working-after-waking-up-from-suspend)
      * [Enabling fingerprint for system authentication](#enabling-fingerprint-for-system-authentication)
         * [The actual change from pam-auth-update](#the-actual-change-from-pam-auth-update)
      * [Windows interoperability](#windows-interoperability)
      * [Playground](#playground)
         * [Initialize a session](#initialize-a-session)
         * [Enroll a new user](#enroll-a-new-user)
         * [Delete database record (user/finger/whatever)](#delete-database-record-userfingerwhatever)
         * [Identify a finger (scan)](#identify-a-finger-scan)
      * [DBus service](#dbus-service)
      * [Debugging](#debugging)

## Setting up

On Ubuntu system:
```
$ sudo apt remove fprintd
$ sudo add-apt-repository ppa:uunicorn/open-fprintd
$ sudo apt-get update
$ sudo apt install open-fprintd fprintd-clients python3-validity
...wait a bit...
$ fprintd-enroll
```

On Arch Linux
(Or Arch Linux based system, not including Artix)
``` 
$ yay -S python-validity
(Press Enter twice when prompted)
$ fprintd-enroll
```

On Fedora Linux

```
$ sudo dnf copr enable tigro/python-validity
$ sudo dnf install open-fprintd fprintd-clients fprintd-clients-pam python3-validity
...wait a bit...
$ fprintd-enroll
```

### Error situations

#### List devices failed

If `fprintd-enroll` returns with `list_devices failed:`, you can check
the logs of the `python3-validity` daemon using `$ sudo systemctl status python3-validity`.
If it's not running, you can enable and/or start it by substituting `status` with `enable` or `start`.

#### Errors on startup

It `systemctl status python3-validity` complains about errors on startup, you may need to factory-reset the fingerprint chip. Do that like so:
```
$ sudo systemctl stop python3-validity
$ sudo validity-sensors-firmware
$ sudo python3 /usr/share/python-validity/playground/factory-reset.py

# At some of the above points you may get a 'device busy' error,
# depending on how systemctl plays along. Kill offending processes if
# necessary, or re-run the systemctl stop python3-validity command, 
# in case it has automatically been restarted, or or kill other
# offending processes.

$ sudo systemctl start python3-validity
$ fprintd-enroll
```

#### Fingerprint not working after waking up from suspend 

Enable *open-fprintd-resume* and *open-fprintd-suspend* services:
```
$ sudo systemctl enable open-fprintd-resume open-fprintd-suspend
```

For even more error procedures, check [this Arch comment thread](https://aur.archlinux.org/packages/python-validity/#comment-755904) or [this python-validity bug comment thread](https://github.com/uunicorn/python-validity/issues/3).

## Enabling fingerprint for system authentication
To enable fingerprint login, if it doesn't come automatically, run
```
$ sudo pam-auth-update
```
and use the space-bar to enable fingerprint authentication.
The change will take effect immediately. At this point, the fingerprint
will be tried first, and only if that fails or times out will you see
a password prompt. Take note of the led-stripe above the fingerprint
sensor to see whether it is active.

### The actual change from pam-auth-update
The above mentioned command `$ sudo pam-auth-update` simply makes a small modification to /etc/pam.d/common-auth:

```
# In /etc/pam.d/common-auth, the following line is added, and the next line changed.
# The end result (apart from other things that may be in the file) is this:
auth  [success=2 default=ignore]  pam_fprintd.so max_tries=1 timeout=10 # debug
auth  [success=1 default=ignore]  pam_unix.so nullok_secure try_first_pass
```

## Windows interoperability

Note: This section is likely only relevant if you will be dual booting.

To be able to use the same set of fingerprints for Windows and Linux, you first
need to extract the Windows user IDs (known as SIDs). To do this, start Windows,
start `cmd.exe` and run `wmic useraccount get name,sid`. This will provide a
list of all users and the corresponding SIDs.

You can then create a mapping from the Linux user names (as written in the
first `:`-separated field of `/etc/passwd`). This mapping is defined in
`/etc/python-validity/dbus-service.yaml`. For example:
```yaml
user_to_sid:
    "myusername": "S-1-5-21-1234567890-1234567890-1234567890-1001"
    "someotheruser": "S-1-5-21-1234567890-1234567890-1234567890-1003"
```
Note the indentation; each entry has to be preceded by at least one space.

## Playground

This package contains a set of scripts you can use to do a low-level debugging of the sensor protocol.
Here is a couple of examples of how you can use them.
Before using the scripts, make sure you've disabled the dbus service shipped with this package.
All examples assume that you are in `/usr/share/python-validity/playground/` directory and your device is already paired.

### Initialize a session
Before talking to a device you will need to open it and start a new TLS session
```
$ python3
Python 3.6.7 (default, Oct 22 2018, 11:32:17) 
[GCC 8.2.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> from prototype import *
>>> open9x()
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

When started, DBus service will first try to initialize the device, then it will try to register itself with the
[open-fprintd](https://github.com/uunicorn/open-fprintd) service. If `open-fprintd` is not available it will wait for it
to come up.

To start DBus service from the sources (useful for debugging):
```
PYTHONPATH=. ./dbus_service/dbus-service
```


## Debugging
If you are curious you can enable tracing to see what flows in and out of device before and after encryption
```
>>> tls.trace_enabled=True
>>> usb.trace_enabled=True
>>> logging.basicConfig(level=logging.DEBUG)
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
