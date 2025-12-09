from smartcard.System import readers
from smartcard.util import toHexString


# list readers

def list_readers():
    r = readers()
    return r


# 0 for contactless ---- 1 for contacted 
def connect_to_reader_by_type(nmb):
    readers_list = list_readers()
    reader = readers_list[nmb]
    connection = reader.createConnection()
    connection.connect()

    print(f"Connected to card in reader: {reader}")
    print(f"ATR: {toHexString(connection.getATR())}")

    return connection


def print_additional_frames(connection, sw2):
    while sw2 == 0XAF:
        apdu = [0x90, 0xAF, 0x00, 0x00, 0x00]
        data, sw1, sw2 = connection.transmit(apdu)
        print(f"Response: {toHexString(data)}")
        print(f"Status: {sw1:02X} {sw2:02X}")



def get_desfire_ev1_version(nmb):
    connection = connect_to_reader_by_type(nmb)
    apdu = [0x90, 0x60, 0x00, 0x00, 0x00]
    data, sw1, sw2 = connection.transmit(apdu)
    print(f"Response: {toHexString(data)}")
    print(f"Status: {sw1:02X} {sw2:02X}")
    if sw2 == 0XAF:
        print_additional_frames(connection, sw2)



get_desfire_ev1_version(0)