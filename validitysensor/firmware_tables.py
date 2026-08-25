"""Defines various constants for firmware files"""

from .usb import SupportedDevices

FIRMWARE_URIS = {
    SupportedDevices.DEV_90: {
        'driver': 'https://download.lenovo.com/pccbbs/mobiles/n1cgn08w.exe',
        'referral': 'https://support.lenovo.com/us/en/downloads/DS120491',
        'sha512': 'd839fa65adf4c952ecb4a5c4b2fc5b5bdedd8e02a421564bdc7fae1d281be4ea26fcde2333f2ab78d56cef0fdccce0a3cf429300b89544cdc9cfee6d0fe0db55'
    },
    SupportedDevices.DEV_97: {
        'driver': 'https://download.lenovo.com/pccbbs/mobiles/nz3gf07w.exe',
        'referral': 'https://download.lenovo.com/pccbbs/mobiles/nz3gf07w.exe',
        'sha512': 'a4a4e6058b1ea8ab721953d2cfd775a1e7bc589863d160e5ebbb90344858f147d695103677a8df0b2de0c95345df108bda97196245b067f45630038fb7c807cd'
    },
    SupportedDevices.DEV_9a: {
        'driver': 'https://download.lenovo.com/pccbbs/mobiles/nz3gf07w.exe',
        'referral': 'https://download.lenovo.com/pccbbs/mobiles/nz3gf07w.exe',
        'sha512': 'a4a4e6058b1ea8ab721953d2cfd775a1e7bc589863d160e5ebbb90344858f147d695103677a8df0b2de0c95345df108bda97196245b067f45630038fb7c807cd'
    },
    SupportedDevices.DEV_9d: {
        'driver': 'https://download.lenovo.com/pccbbs/mobiles/nz3gf07w.exe',
        'referral': 'https://download.lenovo.com/pccbbs/mobiles/nz3gf07w.exe',
        'sha512': 'a4a4e6058b1ea8ab721953d2cfd775a1e7bc589863d160e5ebbb90344858f147d695103677a8df0b2de0c95345df108bda97196245b067f45630038fb7c807cd'
    },
    SupportedDevices.DEV_AB: {
        'driver': 'https://ftp.hp.com/pub/softpaq/sp135501-136000/sp135736.exe',
        'referral': 'https://support.hp.com/us-en/drivers',
        'sha512': 'f9a91e2796a5070f1f40099e2318aa9716e2e6a31b9ba6a93986c450eedbfb0b323dff55c5e4536466946da3e01985f367b1db27bbd7b65f4c333ce0cd47b78c'
    },
    SupportedDevices.DEV_B7: {
        'driver': 'https://ftp.hp.com/pub/softpaq/sp135501-136000/sp135736.exe',
        'referral': 'https://support.hp.com/us-en/drivers',
        'sha512': 'f9a91e2796a5070f1f40099e2318aa9716e2e6a31b9ba6a93986c450eedbfb0b323dff55c5e4536466946da3e01985f367b1db27bbd7b65f4c333ce0cd47b78c'
    },
    SupportedDevices.DEV_CB: {
        'driver': 'https://ftp.hp.com/pub/softpaq/sp138001-138500/sp138431.exe',
        'referral': 'https://support.hp.com/us-en/drivers',
        'sha512': 'b9a268773ac948a4b6bfaa7a5762c58ab482aa47ea321a429ebc8dba3fcdd17ffe750d189791d8e0325b21e95161db5f751c61d7714d7460ee0a406055060a8f'
    }
}

FIRMWARE_NAMES = {
    SupportedDevices.DEV_90: '6_07f_Lenovo.xpfwext',
    SupportedDevices.DEV_97: '6_07f_lenovo_mis_qm.xpfwext',
    SupportedDevices.DEV_9a: '6_07f_lenovo_mis_qm.xpfwext',
    SupportedDevices.DEV_9d: '6_07f_lenovo_mis_qm.xpfwext',
    # 0xd51-sensor variants ship with firmware pre-loaded; xpfwext upload is
    # only needed for factory-reset / unprovisioned chips. The HP softpaq
    # filename matches what extracted from HP's Windows driver (sp135736.exe).
    SupportedDevices.DEV_AB: '6_07f_hp_cmit_mis_qm.xpfwext',  # HP EliteBook 840 G5
    SupportedDevices.DEV_B7: '6_07f_hp_cmit_mis_qm.xpfwext',  # HP G6 series (same chip family)
    SupportedDevices.DEV_CB: '6_07f_hp_mis_qm.xpfwext',  # HP Pavilion x360 14-dh (0x969)
}
