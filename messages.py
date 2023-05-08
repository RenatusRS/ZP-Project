#!/usr/bin/env python3

from typing import Tuple, Union
from utils import SymEnc, AsymEnc, get_key_id, gen_timestamp, generate_session_key
from config import Cfg
from ring import keyrings, PrivateKeyRow, PublicKeyRow

import rsa
import zlib
import base64

from Crypto.Cipher import DES3, AES
from Crypto.Random import get_random_bytes

import calendar
import time

import sys


# ------------- Radix64 i de(kompresija) ---------------

def compression(message: bytes) -> bytes:
    return zlib.compress(message)

def decompression(compressed: bytes) -> bytes:
    return zlib.decompress(compressed)

def message_to_radix64(message: bytes) -> bytes:
    return base64.b64encode(message)

def radix64_to_message(radix64: bytes) -> bytes:
    return base64.b64decode(radix64)

# ------------------------------------------------------


# ------------------ Utilities -------------------------

def isBase64(s) -> bool:
    try:
        return base64.b64encode(base64.b64decode(s)) == s
    except Exception:
        return False

# ------------------------------------------------------


def create_message(message: str, encr: Tuple[PublicKeyRow, SymEnc] = None, auth: PrivateKeyRow = None, compr: bool = False, radix64: bool = False) -> bytes:
    '''Kreiranje poruke koja treba da se sačuva negde na disku.
    Parametri:
    message     -- poruka
    encr        -- opcioni argument. Predstavlja torku identifikatora asimetričnog algoritma i javnog ključa primaoca.
    auth        -- opcioni argument. Predstavlja torku identifikatora asimetričnog algoritma i privatnog ključa pošiljaoca.
    compression -- opcioni argument. Predstavlja izbor da li se poruka kompresuje ili ne.
    radix64     -- opcioni argument. Predstavlja izbor da li se poruka konvertuje u radix64 pre slanja ili ne.
    '''
    encoded: bytes = message.encode('utf8')
    encoded = gen_timestamp() + encoded
    if auth:
        # dodajemo zaglavlje ispred poruke (ukupno 42B + veličina ključa u bajtovima)
        encoded = auth.sign(encoded) + encoded
    if compr:
        # kompresujemo poruku
        encoded = compression(encoded)
    if encr:
        # šifrujemo poruku i ispred nje dodajemo zaglavlje sa sesijskim ključem
        encoded = encr[0].encrypt(encoded, encr[1])

    header = b''
    header += auth.algo.value.to_bytes(1, sys.byteorder) if auth else b'0'
    header += encr[0].algo.value.to_bytes(1, sys.byteorder) if encr else b'0'
    header += encr[1].value.to_bytes(1, sys.byteorder) if encr else b'0'
    header += compr.to_bytes(1, sys.byteorder)
    encoded = header + encoded

    if radix64:
        # sve konvertujemo u radix64
        encoded = message_to_radix64(encoded)
    return encoded


def read_message(user: str, message: bytes) -> str:
    '''
    Čitanje poruke u obliku bytearray

    message -- poruka
    decr    -- opciona torka algoritma za dešifrovanje. Sadrži identifikator algoritma
    za dešifrovanje i privatni ključ primaoca
    auth    -- opciona torka za autentikaciju pošiljaoca. Sadrži identifikator algoritma
    za autentikaciju i javni ključ pošiljaoca
    compr   -- opcioni bool koji određuje da li se poruka kompresuje ili ne
    radix64 -- opcioni bool koji određuje da li se poruka konvertuje iz radix64 ili ne

    '''
    if isBase64(message):
        # konvertujemo nazad iz radix64
        message = radix64_to_message(message)

    header = message[:Cfg.MESSAGE_METADATA]
    message = message[Cfg.MESSAGE_METADATA:]

    f_auth = int.from_bytes(header[0:1], sys.byteorder)
    f_asym = int.from_bytes(header[1:2], sys.byteorder)
    f_sym  = int.from_bytes(header[2:3], sys.byteorder)
    f_comp = int.from_bytes(header[3:4], sys.byteorder)

    assert((f_asym and f_sym) or (not f_asym and not f_sym))

    if f_sym and f_asym:
        # sklanjamo zaglavlje
        key_id  = message[:Cfg.KEY_ID_SIZE]
        message = message[Cfg.KEY_ID_SIZE:]

        private_key_ring = keyrings[user].get_by_key(key_id, False)
        assert(private_key_ring is not None)

        # dešifrujemo poruku i sklanjamo zaglavlje ispred nje
        message = private_key_ring.decrypt(message, SymEnc(f_sym))
    if f_comp:
        # dekompresujemo poruku
        message = decompression(message)
    if f_auth:
        # sklanjamo zaglavlje za autentikaciju i proveravamo ispravnost potpisa
        header = message

        timestamp = header[:Cfg.TIMESTAMP_BYTE_SIZE]
        header = header[Cfg.TIMESTAMP_BYTE_SIZE:]
        public_key_id = header[:Cfg.KEY_ID_SIZE]
        header = header[Cfg.KEY_ID_SIZE:]
        octets = header[:2]
        header = header[2:]

        keyrow = keyrings[user].get_by_key(public_key_id, True)
        assert(keyrow is not None)

        message = keyrow.verify(message, header)

    timestamp = message[0:Cfg.TIMESTAMP_BYTE_SIZE]
    # sklanjamo timestamp
    return message[Cfg.TIMESTAMP_BYTE_SIZE:].decode('utf8')


def send_message(msg: bytes, location: str) -> None:
    '''Čuvanje poruke kreirane sa create_message(...) negde na disku.
    Parametri:
    msg      -- poruka kreirana sa create_message(...)
    location -- lokacija poruke na disku
    '''
    with open(location, 'wb') as f:
        f.write(msg)


def receive_message(location: str, user: str) -> str:
    '''Čitanje poruke sa diska
    Parametri:
    location -- lokacija poruke na disku
    '''
    with open(location, 'rb') as f:
        data: bytes = f.read()
        return read_message(user, data)


if __name__ == '__main__':
    pass

