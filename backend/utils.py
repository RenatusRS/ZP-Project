from typing import Union
from backend.algorithms import SymEnc, AsymEnc

from backend.config import Cfg
import calendar, time
import sys

from datetime import datetime

from Crypto.Random import get_random_bytes
from Crypto.Cipher import DES3, AES
from Crypto.PublicKey import DSA
import rsa


# --------------------- Funkcije -----------------------

def encrypt_with_session_key(algorithm: SymEnc, session_key: bytes, message: bytes):
    '''
    Šifruje poruku 'message' ključem 'session_key' simetričnim algoritmom 'algorithm'
    '''
    
    assert(algorithm == SymEnc.DES3 or algorithm == SymEnc.AES)
    
    if algorithm == SymEnc.DES3:
        cipher = DES3.new(session_key, DES3.MODE_CFB)
        
    elif algorithm == SymEnc.AES:
        cipher = AES.new(session_key, AES.MODE_CFB)
        

    ciphertext = cipher.encrypt(message)
    
    return ciphertext, cipher.iv


def decrypt_with_session_key(algorithm: SymEnc, session_key: bytes, iv: bytes, message: bytes) -> bytes:
    '''
    Dešifruje poruku 'message' ključem 'session_key' simetričnim algoritmom 'algorithm' i inicijalnim vektorom 'iv'
    '''
    
    assert(algorithm == SymEnc.DES3 or algorithm == SymEnc.AES)
    
    if algorithm == SymEnc.DES3:
        cipher = DES3.new(session_key, DES3.MODE_CFB, iv)
        
    elif algorithm == SymEnc.AES:
        cipher = AES.new(session_key, AES.MODE_CFB, iv)
        

    plaintext = cipher.decrypt(message)
    
    return plaintext



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


def get_key_id_RSA(key: Union[rsa.PrivateKey, rsa.PublicKey]) -> bytes:
    '''
    Uzima 64 najmanje značajnih bita privatnog ili javnog ključa i pretvara ih
    u bytearray veličine 8 bajtova

    key -- ključ za koji se uzima ID
    '''
    
    return (key.n % 2**64).to_bytes(Cfg.KEY_ID_SIZE, sys.byteorder)


def get_key_id_DSA(key) -> bytes:
    n = int.from_bytes(key.export_key(format='DER'), sys.byteorder)
    
    return (n % 2**64).to_bytes(Cfg.KEY_ID_SIZE, sys.byteorder)
