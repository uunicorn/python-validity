
from struct import pack, unpack

from db97 import db
from usb97 import usb
from tls97 import tls
from flash import read_flash

machine_guid='e7260876-58db-4d27-8c40-8d13110d6a71'

#usb.trace_enabled=True
#tls.trace_enabled=True

usb.open()
tls.parseTlsFlash(read_flash(1, 0, 0x1000))
tls.open()

stg=db.get_user_storage(name='StgWindsor')
if stg == None:
    stgid=db.new_record(1, 4, 3, b'StgWindsor\0')
    stg=db.get_user_storage(stgid)
    if stg == None:
        raise Exception('Failed to create StgWindsor')

def stg_data_records():
    rc = db.get_record_children(stg.dbid).children
    return [i['dbid'] for i in rc if i['type'] == 8] # 8 == "data" type

def machine_id_rec_value(b):
    b = b.encode('utf-16le')
    b = b + b'\0' * (0x94 - len(b))
    return pack('<HH', 0x102, len(b)) + b # 0x102 = Machine ID/GUID?

rc = stg_data_records()

if rc == []:
    db.new_record(stg.dbid, 0x8, stg.dbid, machine_id_rec_value(machine_guid))
    rc = stg_data_records()

rc = db.get_record_value(rc[0]).value

if rc != machine_id_rec_value(machine_guid):
    u0, l = unpack('<HH', rc[:4])
    b=rc[4:4+l]
    b=b.decode('utf-16le')
    raise Exception('Machine GUID does not match the DB flash ownership record (%s).' % b)

print('That''s it, pairing''s finished')

