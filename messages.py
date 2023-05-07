#!/usr/bin/env python3

from typing import Tuple, Union
from enum import Enum

import hashlib
import rsa
import zlib
import base64
from Crypto.Cipher import DES3, AES
from Crypto.Random import get_random_bytes

import calendar
import time

import sys

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

# --------------------- Konstante ----------------------

TIMESTAMP_BYTE_SIZE: int         = 32
KEY_ID_SIZE: int                 = 8
RSA_BITS: int                    = 1024
ENCRYPTED_SESSION_KEY_BYTES: int = int(RSA_BITS/8)
SESSION_KEY_BYTES: int           = 16
SHA1_BYTE_SIZE: int              = int(RSA_BITS/8)
MESSAGE_METADATA: int            = 4

AUTH_HEADER_SIZE: int            = TIMESTAMP_BYTE_SIZE + KEY_ID_SIZE + 2 + SHA1_BYTE_SIZE

# ------------------------------------------------------

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
def gen_timestamp() -> bytes:
    '''
    Generiše bytearray za trenutno vreme
    '''
    current_gmt = time.gmtime()
    time_stamp = calendar.timegm(current_gmt)
    return time_stamp.to_bytes(TIMESTAMP_BYTE_SIZE, sys.byteorder)


def generate_session_key() -> bytes:
    '''
    Generiše nasumični sesijski ključ uobičajne veličine
    '''
    return get_random_bytes(SESSION_KEY_BYTES)


def get_key_id(key: Union[rsa.PrivateKey, rsa.PublicKey]) -> bytes:
    '''
    Uzima 64 najmanje značajnih bita privatnog ili javnog ključa i pretvara ih
    u bytearray veličine 8 bajtova

    key -- ključ za koji se uzima ID
    '''
    return (key.n % 2**64).to_bytes(KEY_ID_SIZE, sys.byteorder)


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


def isBase64(s) -> bool:
    try:
        return base64.b64encode(base64.b64decode(s)) == s
    except Exception:
        return False
# ------------------------------------------------------


def gen_private_key(username: str, mail: str, asym_algo: AsymEnc, keysize: int, masterkey: str) -> None:
    '''Generisanje novog privatnog ključa
    Parametri:
    username  -- identifikator osobe čiji je ključ
    mail      -- mejl za koji koristimo privatni ključ
    asym_algo -- asimetrični algoritam koji se koristi
    keysize   -- veličina ključa u (bitima ili bajtovima?) TODO
    masterkey -- master ključ korisnika
    '''
    pass # TODO


def authentication(message: bytes, auth: Tuple[AsymEnc, rsa.PrivateKey]) -> bytes:
    '''
    Pravi header za autentikaciju.

    message -- poruka pretvorena u bytearray (sa encode('utf8'))
    auth    -- torka identifikatora algoritma za asimetrično šifrovanje i privatnog ključa pošiljaoca
    '''
    assert(auth[0] is AsymEnc.RSA or auth[0] is AsymEnc.ELGAMAL)
    if auth[0] is AsymEnc.RSA:
        header: bytes = b''
        header += gen_timestamp() # timestamp - prvih TIMESTAMP_BYTE_SIZE bajtova
        header += get_key_id(auth[1]) # ID javnog ključa pošiljaoca - 8 bajtova

        hsh = rsa.compute_hash(message, 'SHA-1') # računanje hash-a poruke

        header += hsh[0:2] # prva dva okteta hash-a
        header += rsa.sign_hash(hsh, auth[1], 'SHA-1') # šifrovan hash

        return header

    if auth[0] is AsymEnc.ELGAMAL:
        return message


def auth_check(message: bytes, auth: Tuple[AsymEnc, rsa.PublicKey]) -> None:
    '''
    Sklanja zaglavlje sa poruke i proverava da li je hash ispravan

    message -- dešifrovana poruka
    auth    -- torka identifikatora algoritma za asimetrično šifrovanje i javnog ključa primaoca
    '''
    assert(auth[0] is AsymEnc.RSA or auth[0] is AsymEnc.ELGAMAL)
    if auth[0] is AsymEnc.RSA:
        header = message[:AUTH_HEADER_SIZE]

        timestamp = header[:TIMESTAMP_BYTE_SIZE]
        header = header[TIMESTAMP_BYTE_SIZE:]
        public_key_id = header[:KEY_ID_SIZE]
        header = header[KEY_ID_SIZE:]
        octets = header[:2]
        header = header[2:]
        digest = header[:SHA1_BYTE_SIZE]

        message = message[AUTH_HEADER_SIZE:]
        try:
            rsa.verify(message, digest, auth[1])
        except rsa.pkcs1.VerificationError:
            print("\n>>>Verification Error<<<\n") # TODO
        return
    if auth[0] is AsymEnc.ELGAMAL:
        pass # TODO

def encryption(message: bytes, encr: Tuple[AsymEnc, rsa.PublicKey, SymEnc]) -> bytes:
    '''
    Generiše session_key, šifruje ga javnim ključem primaoca, i pravi zaglavlje od
    šifrovanog session_key i ID javnog ključa primaoca.
    Onda šifruje celu poruku (sa zaglavljima autentikacije ako postoje) i na nju
    dodaje zaglavlje za šifrovanje poruke.
    '''
    assert(encr[0] is AsymEnc.RSA or encr[0] is AsymEnc.ELGAMAL)
    if encr[0] is AsymEnc.RSA:
        header: bytes = b''
        header += get_key_id(encr[1]) # na header dodaje ID javnog ključa primaoca
        session_key = generate_session_key() # generiše sesijski ključ (16B)
        header += rsa.encrypt(session_key, encr[1]) # na header dodaje šifrovan Ks
        message, iv = encrypt_with_session_key(encr[2], session_key, message)
        return header + iv + message # na header dodaje Cipher IV
    if encr[0] is AsymEnc.ELGAMAL:
        return message


def decryption(message: bytes, decr: Tuple[AsymEnc, rsa.PrivateKey, SymEnc]) -> bytes:
    assert(decr[0] is AsymEnc.RSA or decr[0] is AsymEnc.ELGAMAL)
    if decr[0] is AsymEnc.RSA:
        enc_session_key = message[:ENCRYPTED_SESSION_KEY_BYTES]
        message = message[ENCRYPTED_SESSION_KEY_BYTES:]

        block_size = AES.block_size if decr[2] == SymEnc.AES else DES3.block_size

        iv = message[:block_size]
        message = message[block_size:]

        session_key = rsa.decrypt(enc_session_key, decr[1])
        message = decrypt_with_session_key(decr[2], session_key, iv, message)
        return message
    if decr[0] is AsymEnc.ELGAMAL:
        return message


def create_message(message: str, encr: Tuple[AsymEnc, rsa.PublicKey, SymEnc] = None, auth: Tuple[AsymEnc, rsa.PrivateKey] = None, compr: bool = False, radix64: bool = False) -> bytes:
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
        # dodajemo zaglavlje ispred poruke (ukupno 106 bajtova)
        encoded = authentication(encoded, auth) + encoded
    if compr:
        # kompresujemo poruku
        encoded = compression(encoded)
    if encr:
        # šifrujemo poruku i ispred nje dodajemo zaglavlje sa sesijskim ključem
        encoded = encryption(encoded, encr)

    header = b''
    header += auth[0].value.to_bytes(1, sys.byteorder) if auth else b'0'
    header += encr[0].value.to_bytes(1, sys.byteorder) if encr else b'0'
    header += encr[2].value.to_bytes(1, sys.byteorder) if encr else b'0'
    header += compr.to_bytes(1, sys.byteorder)
    encoded = header + encoded

    if radix64:
        # sve konvertujemo u radix64
        encoded = message_to_radix64(encoded)
    return encoded


def send_message(msg: bytes, location: str) -> None:
    '''Čuvanje poruke kreirane sa create_message(...) negde na disku.
    Parametri:
    msg      -- poruka kreirana sa create_message(...)
    location -- lokacija poruke na disku
    '''
    pass


def receieve_message(location: str) -> None:
    '''Čitanje poruke sa diska
    Parametri:
    location -- lokacija poruke na disku
    '''
    pass


def read_message(message: bytes, decr: rsa.PrivateKey = None, auth: rsa.PublicKey = None):
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

    header = message[:MESSAGE_METADATA]
    message = message[MESSAGE_METADATA:]

    f_auth = int.from_bytes(header[0:1], sys.byteorder)
    f_asym = int.from_bytes(header[1:2], sys.byteorder)
    f_sym  = int.from_bytes(header[2:3], sys.byteorder)
    f_comp = int.from_bytes(header[3:4], sys.byteorder)

    assert((f_asym and f_sym and decr) or (not f_asym and not f_sym and not decr))
    assert((f_auth and auth) or (not f_auth and not auth))

    if f_sym and f_asym and decr:
        # sklanjamo zaglavlje
        key_id  = message[:KEY_ID_SIZE]
        message = message[KEY_ID_SIZE:]
        # private_key = get_private_key(key_id) TODO

        # dešifrujemo poruku i sklanjamo zaglavlje ispred nje
        message = decryption(message, (AsymEnc(f_asym), decr, SymEnc(f_sym)))
    if f_comp:
        # dekompresujemo poruku
        message = decompression(message)
    if f_auth and auth:
        # sklanjamo zaglavlje za autentikaciju i proveravamo ispravnost potpisa
        auth_check(message, (AsymEnc(f_auth), auth))
        message = message[AUTH_HEADER_SIZE:]

    timestamp = message[0:TIMESTAMP_BYTE_SIZE]
    # sklanjamo timestamp
    return message[TIMESTAMP_BYTE_SIZE:]


if __name__ == '__main__':
    pu, pr = rsa.newkeys(RSA_BITS)
    pu2, pr2 = rsa.newkeys(RSA_BITS)
    string = "RADIIIIIIIIIIIIII"

    msg = create_message(string, auth=(AsymEnc.RSA, pr2), encr=(AsymEnc.RSA, pu, SymEnc.AES))
    print(msg)
    read = read_message(msg, auth=pu2, decr=pr2)

    print(read.decode('utf8'))

