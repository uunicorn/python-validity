import logging
from struct import pack, unpack

from .db import db


def machine_id_rec_value(b):
    b = b.encode('utf-16le')
    b = b + b'\0' * (0x94 - len(b))
    return pack('<HH', 0x102, len(b)) + b  # 0x102 = Machine ID/GUID?


# This function is unused. It simply describes the Windows driver behavior.
# TODO: make this GUID unique!
def init_machine_guid(machine_guid='e7260876-58db-4d27-8c40-8d13110d6a71'):
    rc = db.get_storage_data()

    if rc == []:
        logging.info('Creating a host machine GUID record')
        stg = db.get_user_storage(name='StgWindsor')
        db.new_record(stg.dbid, 0x8, stg.dbid, machine_id_rec_value(machine_guid))
        rc = db.get_storage_data()

    rc = db.get_record_value(rc[0]).value

    if rc != machine_id_rec_value(machine_guid):
        u0, l = unpack('<HH', rc[:4])
        b = rc[4:4 + l]
        b = b.decode('utf-16le')
        raise Exception('Machine GUID does not match the DB flash ownership record (%s).' % b)


def init_db():
    stg = db.get_user_storage(name='StgWindsor')
    if stg == None:
        logging.info('Creating a new user storage object')
        db.new_user_storate()

    #init_machine_guid()
