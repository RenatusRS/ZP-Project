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


def authentication(message: bytes, auth: PrivateKeyRow) -> bytes:
    '''
    Pravi header za autentikaciju.

    message -- poruka pretvorena u bytearray (sa encode('utf8'))
    auth    -- red iz privatnog keyringa
    '''
    assert(auth.algo is AsymEnc.RSA or auth.algo is AsymEnc.ELGAMAL)
    if auth.algo is AsymEnc.RSA:
        private_key = auth.get_private_key()
        assert(private_key is not None)

        header: bytes = b''
        header += gen_timestamp() # timestamp - prvih TIMESTAMP_BYTE_SIZE bajtova
        header += auth.key_id # ID javnog ključa pošiljaoca - 8 bajtova

        hsh = rsa.compute_hash(message, 'SHA-1') # računanje hash-a poruke

        header += hsh[0:2] # prva dva okteta hash-a
        header += rsa.sign_hash(hsh, private_key, 'SHA-1') # šifrovan hash

        return header

    if auth.algo is AsymEnc.ELGAMAL:
        return message


def auth_check(message: bytes, user: str) -> bytes:
    '''
    Sklanja zaglavlje sa poruke i proverava da li je hash ispravan

    message -- dešifrovana poruka
    user    -- string koji identifikuje korisnika koji proverava autentikaciju
    '''

    header = message

    timestamp = header[:Cfg.TIMESTAMP_BYTE_SIZE]
    header = header[Cfg.TIMESTAMP_BYTE_SIZE:]
    public_key_id = header[:Cfg.KEY_ID_SIZE]
    header = header[Cfg.KEY_ID_SIZE:]
    octets = header[:2]
    header = header[2:]

    keyrow = keyrings[user].get_by_key(public_key_id, True)
    assert(keyrow is not None)
    pu = keyrow.public_key
    assert(keyrow.algo is AsymEnc.RSA or keyrow.algo is AsymEnc.ELGAMAL)

    SHA1_BYTE_SIZE = int(keyrow.key_size/8)
    digest = header[:SHA1_BYTE_SIZE]

    message = message[keyrow.auth_header_size():]
    if keyrow.algo is AsymEnc.RSA:
        try:
            rsa.verify(message, digest, pu)
        except rsa.pkcs1.VerificationError:
            print("\n>>>Verification Error<<<\n") # TODO
    elif keyrow.algo is AsymEnc.ELGAMAL:
        raise Exception("Not yet implemented")
    return message


def encryption(message: bytes, encr: Tuple[PublicKeyRow, SymEnc]) -> bytes:
    '''
    Generiše session_key, šifruje ga javnim ključem primaoca, i pravi zaglavlje od
    šifrovanog session_key i ID javnog ključa primaoca.
    Onda šifruje celu poruku (sa zaglavljima autentikacije ako postoje) i na nju
    dodaje zaglavlje za šifrovanje poruke.
    '''
    assert(encr[0].algo is AsymEnc.RSA or encr[0].algo is AsymEnc.ELGAMAL)
    if encr[0].algo is AsymEnc.RSA:
        header: bytes = b''
        header += encr[0].key_id # na header dodaje ID javnog ključa primaoca
        session_key = generate_session_key() # generiše sesijski ključ (16B)
        header += rsa.encrypt(session_key, encr[0].public_key) # na header dodaje šifrovan Ks
        message, iv = encrypt_with_session_key(encr[1], session_key, message)
        return header + iv + message # na header dodaje Cipher IV
    if encr[0].algo is AsymEnc.ELGAMAL:
        return message


def decryption(message: bytes, decr: Tuple[PrivateKeyRow, SymEnc]) -> bytes:
    if decr[0].algo is AsymEnc.RSA:
        ENCRYPTED_SESSION_KEY_BYTES = int(decr[0].key_size/8)

        enc_session_key = message[:ENCRYPTED_SESSION_KEY_BYTES]
        message = message[ENCRYPTED_SESSION_KEY_BYTES:]

        block_size = AES.block_size if decr[1] == SymEnc.AES else DES3.block_size

        iv = message[:block_size]
        message = message[block_size:]

        private_key = decr[0].get_private_key()
        assert(private_key is not None)

        session_key = rsa.decrypt(enc_session_key, private_key)
        message = decrypt_with_session_key(decr[1], session_key, iv, message)
        return message

    if decr[0].algo is AsymEnc.ELGAMAL:
        return message
    raise Exception("Nonexisting branch")


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
        # dodajemo zaglavlje ispred poruke (ukupno 106 bajtova)
        encoded = authentication(encoded, auth) + encoded
    if compr:
        # kompresujemo poruku
        encoded = compression(encoded)
    if encr:
        # šifrujemo poruku i ispred nje dodajemo zaglavlje sa sesijskim ključem
        encoded = encryption(encoded, encr)

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
        message = decryption(message, (private_key_ring, SymEnc(f_sym)))
    if f_comp:
        # dekompresujemo poruku
        message = decompression(message)
    if f_auth:
        # sklanjamo zaglavlje za autentikaciju i proveravamo ispravnost potpisa
        message = auth_check(message, user)

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

