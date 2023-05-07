
from typing import Union

from enum import Enum
from config import Cfg
import calendar, time
import sys

from datetime import datetime

from Crypto.Random import get_random_bytes
import rsa

# ----------------------- Klase ------------------------

'''
Enum za simetrične alogritme šifrovanja
'''
class SymEnc(Enum):
    DES3  = 1
    AES   = 2
    CAST5 = 3
    IDEA  = 4

'''
Enum za asimetrične algoritme šifrovanja
'''
class AsymEnc(Enum):
    RSA     = 1
    ELGAMAL = 2

# --------------------- Funkcije -----------------------

def gen_timestamp() -> bytes:
    '''
    Generiše bytearray za trenutno vreme
    '''
    current_gmt = time.gmtime()
    time_stamp = calendar.timegm(current_gmt)
    return time_stamp.to_bytes(Cfg.TIMESTAMP_BYTE_SIZE, sys.byteorder)


def timestamp_to_string(timestamp: bytes) -> str:
    '''
    Vraća string za timestamp bytearray
    '''
    return str(datetime.fromtimestamp(int.from_bytes(timestamp, sys.byteorder)))


def generate_session_key() -> bytes:
    '''
    Generiše nasumični sesijski ključ uobičajne veličine
    '''
    return get_random_bytes(Cfg.SESSION_KEY_BYTES)


def get_key_id(key: Union[rsa.PrivateKey, rsa.PublicKey]) -> bytes:
    '''
    Uzima 64 najmanje značajnih bita privatnog ili javnog ključa i pretvara ih
    u bytearray veličine 8 bajtova

    key -- ključ za koji se uzima ID
    '''
    return (key.n % 2**64).to_bytes(Cfg.KEY_ID_SIZE, sys.byteorder)

# ------------------------------------------------------

if __name__ == '__main__':
    pass


