"""Defines various constants for firmware files"""

from .usb import SupportedDevices

FIRMWARE_URIS = {
    SupportedDevices.DEV_90: {
        'driver': 'https://download.lenovo.com/pccbbs/mobiles/n1cgn08w.exe',
        'referral': 'https://support.lenovo.com/us/en/downloads/DS120491',
    },
    SupportedDevices.DEV_97: {
        'driver': 'https://download.lenovo.com/pccbbs/mobiles/nz3gf07w.exe',
        'referral': 'https://download.lenovo.com/pccbbs/mobiles/nz3gf07w.exe'
    },
    SupportedDevices.DEV_9a: {
        'driver': 'https://download.lenovo.com/pccbbs/mobiles/nz3gf07w.exe',
        'referral': 'https://download.lenovo.com/pccbbs/mobiles/nz3gf07w.exe'
    }
}

FIRMWARE_NAMES = {
    SupportedDevices.DEV_90: '6_07f_Lenovo.xpfwext',
    SupportedDevices.DEV_97: '6_07f_lenovo_mis_qm.xpfwext',
    SupportedDevices.DEV_9a: '6_07f_lenovo_mis_qm.xpfwext'
}
