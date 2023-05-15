from tkinter import simpledialog
from typing import List, Dict

from backend.utils import AsymEnc, SymEnc, gen_timestamp, get_key_id_RSA, get_key_id_DSA, timestamp_to_string, generate_session_key, encrypt_with_session_key, decrypt_with_session_key
from backend.config import Cfg
import pickle

import rsa
from Crypto.Cipher import CAST, AES, DES3
from Crypto.PublicKey import DSA
from Crypto.Signature import DSS
from Crypto.Hash import SHA256

import sys

from abc import ABC, abstractmethod

from backend.exceptions import PasswordException, InputException


class PrivateKeyRow(ABC):
    def __init__(self, user_id: str, key_size: int):
        assert(key_size == 1024 or key_size == 2048)

        if len(user_id) == 0:
            raise InputException

        self.timestamp: bytes = gen_timestamp()
        self.user_id: str     = user_id
        self.key_size: int    = key_size


    @staticmethod
    def create_password() -> str:
        pw1: str = ""
        pw2: str = ""
        while True:
            pw1 = input("Unesite master lozinku: ")
            pw2 = input("Unesite master lozinku opet: ")
            l = len(pw1.encode('utf8'))
            if l > 16 or l < 5:
                print("Šifra može biti minimalno 5 a maksimalno 16 bajtova")
            elif pw1 == pw2:
                print("Par privatnih/javnih ključeva je uspešno napravljen")
                break
            else:
                print("Lozinke se ne slažu, pokušajte ponovo.")
        return pw1


    def __repr__(self):
        rpr = '------------ ' + self.user_id +  ' ------------\n'
        rpr += 'timestamp: ' + timestamp_to_string(self.timestamp) + '\n'
        rpr += 'key_id:    ' + str(int.from_bytes(self.key_id, sys.byteorder)) + '\n'
        # rpr += str(self.public_key) + '\n'
        rpr += 'algorithm: ' + self.algo.name + '\n'
        # rpr += str(int.from_bytes(self.enc_private_key, sys.byteorder)) + ')\n'
        rpr += '--------------------------' + '-'*len(self.user_id) + '\n'
        return rpr


    @abstractmethod
    def add_public_key(self, name: str):
        pass


    @abstractmethod
    def decrypt(self, message: bytes, decr: SymEnc) -> bytes:
        pass


    @abstractmethod
    def sign(self, message: bytes):
        pass


    @property
    @abstractmethod
    def algo(self):
        pass


    @property
    @abstractmethod
    def key_id(self):
        pass


    @property
    @abstractmethod
    def public_key(self):
        pass


    @property
    @abstractmethod
    def enc_private_key(self):
        pass


    @abstractmethod
    def get_private_key(self):
        pass


class PrivateKeyRowRSA(PrivateKeyRow):
    def __init__(self, user_id: str, key_size: int, password: str):
        super().__init__(user_id, key_size)
        self._algo = AsymEnc.RSA

        public_key, private_key = rsa.newkeys(key_size)

        cipher = CAST.new(password.encode('utf8'), CAST.MODE_OPENPGP)
        enc_private_key = cipher.encrypt(pickle.dumps(private_key))

        self._key_id: bytes             = get_key_id_RSA(public_key)
        self._public_key: rsa.PublicKey = public_key
        self._enc_private_key: bytes    = enc_private_key


    def decrypt(self, message: bytes, decr: SymEnc) -> bytes:
        ENCRYPTED_SESSION_KEY_BYTES = int(self.key_size/8)

        enc_session_key = message[:ENCRYPTED_SESSION_KEY_BYTES]
        message = message[ENCRYPTED_SESSION_KEY_BYTES:]

        block_size = AES.block_size if decr == SymEnc.AES else DES3.block_size

        iv = message[:block_size]
        message = message[block_size:]

        private_key = self.get_private_key()

        session_key = rsa.decrypt(enc_session_key, private_key)
        message = decrypt_with_session_key(decr, session_key, iv, message)
        return message


    def sign(self, message: bytes) -> bytes:
        private_key = self.get_private_key()

        header: bytes = b''
        header += gen_timestamp() # timestamp - prvih TIMESTAMP_BYTE_SIZE bajtova
        header += self.key_id # ID javnog ključa pošiljaoca - 8 bajtova

        hsh = rsa.compute_hash(message, 'SHA-1') # računanje hash-a poruke

        header += hsh[0:2] # prva dva okteta hash-a
        header += rsa.sign_hash(hsh, private_key, 'SHA-1') # šifrovan hash

        return header


    def add_public_key(self, name: str):
        '''
        Za generisani par ključeva dodaje javni ključ u globalni niz
        '''
        p = PublicKeyRowRSA(self.public_key, name, self.key_size)
        Keyring.public.append(p)



    def get_private_key(self):
        password = simpledialog.askstring(f"Access Private Key [{self.user_id}]", f"Enter password for [{self.user_id}]", show="*")

        try:
            eiv = self.enc_private_key[:CAST.block_size+2]
            temp = self.enc_private_key[CAST.block_size+2:]
            cipher = CAST.new(password.encode('utf8'), CAST.MODE_OPENPGP, eiv)
            priv = pickle.loads(cipher.decrypt(temp))
            return rsa.PrivateKey(priv.n, priv.e, priv.d, priv.p, priv.q)
        except pickle.UnpicklingError:
            raise PasswordException


    @property
    def algo(self):
        return self._algo


    @property
    def key_id(self):
        return self._key_id


    @property
    def public_key(self):
        return self._public_key


    @property
    def enc_private_key(self):
        return self._enc_private_key


class PrivateKeyRowElGamal(PrivateKeyRow):
    def __init__(self, user_id: str, key_size: int, password: str):
        super().__init__(user_id, key_size)
        self._algo = AsymEnc.ELGAMAL

        keypair = DSA.generate(key_size)
        self._public_key = keypair.publickey()
        self._key_id = get_key_id_DSA(self._public_key)

        cipher = CAST.new(password.encode('utf8'), CAST.MODE_OPENPGP)
        enc_private_key = cipher.encrypt(keypair.export_key(format='DER'))

        self._enc_private_key = enc_private_key


    def decrypt(self, message: bytes, decr: SymEnc) -> bytes:
        raise Exception("Not yet implemented")


    def sign(self, message: bytes):
        private_key = self.get_private_key()

        header: bytes = b''
        header += gen_timestamp() # timestamp - prvih TIMESTAMP_BYTE_SIZE bajtova
        header += self.key_id # ID javnog ključa pošiljaoca - 8 bajtova

        hsh = SHA256.new(message)
        signer = DSS.new(private_key, 'fips-186-3')
        signature = signer.sign(hsh)

        header += hsh.digest()[0:2] # prva dva okteta hash-a
        header += signature # šifrovan hash

        return header


    def add_public_key(self, name: str):
        p = PublicKeyRowElGamal(self.public_key, name, self.key_size)
        Keyring.public.append(p)


    def get_private_key(self):
        password = simpledialog.askstring(f"Access Private Key [{self.user_id}]", f"Enter password for [{self.user_id}]", show="*")

        try:
            eiv = self.enc_private_key[:CAST.block_size+2]
            temp = self.enc_private_key[CAST.block_size+2:]
            cipher = CAST.new(password.encode('utf8'), CAST.MODE_OPENPGP, eiv)
            priv = cipher.decrypt(temp)
            return DSA.import_key(priv)
        except ValueError:
            raise PasswordException


    @property
    def algo(self):
        return self._algo


    @property
    def key_id(self):
        return self._key_id


    @property
    def public_key(self):
        return self._public_key


    @property
    def enc_private_key(self):
        return self._enc_private_key


class PublicKeyRow(ABC):
    def __init__(self, user_id: str, key_size: int):
        assert(key_size == 1024 or key_size == 2048)

        if len(user_id) == 0:
            raise InputException

        self.timestamp: bytes = gen_timestamp()
        self.user_id: str     = user_id
        self.key_size: int    = key_size


    def __repr__(self):
        rpr = '------------ ' + self.user_id +  ' ------------\n'
        rpr += 'timestamp: ' + timestamp_to_string(self.timestamp) + '\n'
        rpr += 'key_id:    ' + str(int.from_bytes(self.key_id, sys.byteorder)) + '\n'
        # rpr += str(self.public_key) + '\n'
        rpr += 'algorithm: ' + self.algo.name + '\n'
        rpr += '--------------------------' + '-'*len(self.user_id) + '\n'
        return rpr


    @abstractmethod
    def verify(self, message: bytes, header: bytes) -> bytes:
        pass


    @abstractmethod
    def auth_header_size(self):
        pass


    @abstractmethod
    def encrypt(self, message: bytes, algo: SymEnc) -> bytes:
        pass


    @property
    @abstractmethod
    def algo(self):
        pass


    @property
    @abstractmethod
    def key_id(self):
        pass


    @property
    @abstractmethod
    def public_key(self):
        pass


class PublicKeyRowRSA(PublicKeyRow):
    def __init__(self, public_key: rsa.PublicKey, user_id: str, key_size: int):
        assert(public_key is not None)
        super().__init__(user_id, key_size)
        self._key_id: bytes             = get_key_id_RSA(public_key)
        self._public_key: rsa.PublicKey = public_key
        self._algo: AsymEnc             = AsymEnc.RSA


    def encrypt(self, message: bytes, algo: SymEnc) -> bytes:
        header: bytes = b''
        header += self.key_id # na header dodaje ID javnog ključa primaoca
        session_key = generate_session_key() # generiše sesijski ključ (16B)
        header += rsa.encrypt(session_key, self.public_key) # na header dodaje šifrovan Ks
        message, iv = encrypt_with_session_key(algo, session_key, message)
        return header + iv + message # na header dodaje Cipher IV


    def verify(self, message: bytes, header: bytes) -> bytes:
        '''
        Sklanja zaglavlje sa poruke i proverava da li je hash ispravan

        header  -- kraj zaglavlja (sledeća info je SHA-1 hash)
        message -- dešifrovana poruka
        '''
        pu = self.public_key

        SHA1_BYTE_SIZE = int(self.key_size/8)
        digest = header[:SHA1_BYTE_SIZE]

        message = message[self.auth_header_size():]
        try:
            rsa.verify(message, digest, pu)
        except rsa.pkcs1.VerificationError:
            print("\n>>>Verification Error<<<\n") # TODO

        return message


    def auth_header_size(self):
        return Cfg.TIMESTAMP_BYTE_SIZE + Cfg.KEY_ID_SIZE + 2 + int(self.key_size/8)


    @property
    def algo(self):
        return self._algo


    @property
    def key_id(self):
        return self._key_id


    @property
    def public_key(self):
        return self._public_key


class PublicKeyRowElGamal(PublicKeyRow):
    def __init__(self, public_key, user_id: str, key_size):
        assert(public_key is not None)
        super().__init__(user_id, key_size)
        self._key_id: bytes          = get_key_id_DSA(public_key)
        self._public_key: DSA.DsaKey = public_key
        self._algo: AsymEnc          = AsymEnc.ELGAMAL


    def verify(self, message: bytes, header: bytes) -> bytes:
        pu = self.public_key

        dss_sign_size = 40 if self.key_size == 1024 else 56
        signature = header[:dss_sign_size]

        message = message[self.auth_header_size():]
        hsh = SHA256.new(message)

        verifier = DSS.new(pu, 'fips-186-3')

        try:
            verifier.verify(hsh, signature)
        except ValueError:
            print("\n>>>Verification Error<<<\n") # TODO

        return message


    def encrypt(self, message: bytes, algo: SymEnc) -> bytes:
        raise Exception("Not yet implemented")


    def auth_header_size(self):
        dss_sign_size = 40 if self.key_size == 1024 else 56
        return Cfg.TIMESTAMP_BYTE_SIZE + Cfg.KEY_ID_SIZE + 2 + dss_sign_size


    @property
    def algo(self):
        return self._algo


    @property
    def key_id(self):
        return self._key_id


    @property
    def public_key(self):
        return self._public_key



class Keyring:
    public: List[PublicKeyRow] = []


    def __init__(self):
        self.private: List[PrivateKeyRow] = []


    def get_private_ring(self, key_id: bytes):
        for row in self.private:
            if row.key_id == key_id:
                return row
        return None


    def get_public_ring(self, key_id: bytes):
        for row in Keyring.public:
            if row.key_id == key_id:

                return row
        return None

    def get_private_ring_by_user_id(self, user_id: str):
        for row in self.private:
            if row.user_id == user_id:
                return row

        return None

    def get_public_ring_by_user_id(self, user_id: str):
        for row in Keyring.public:
            if row.user_id == user_id:
                return row

        return None


    def add_private_ring(self, ring: PrivateKeyRow, name: str):
        '''
        Dodaje privatni ključ u tabelu korisnika, a njegov javni
        parnjak dodaje u globalnu tabelu javnih ključeva
        '''
        self.private.append(ring)
        ring.add_public_key(name)


    def __repr__(self):
        rpr = "=================== PRIVATE ====================\n"
        for row in self.private:
            rpr += str(row)
        return rpr


    @staticmethod
    def all_public_keys():
        rpr = "\n============== PUBLIC (GLOBAL) =================\n"
        for row in Keyring.public:

            rpr += str(row)
        return rpr


keyrings: Dict[str, Keyring] = { }


def populate():
    key_size = 1024

    keyrings["fedja"] = Keyring()
    keyrings["lonchar"] = Keyring()
    p = PrivateKeyRowRSA("fedja@fedja", key_size, "fedja")
    keyrings["fedja"].add_private_ring(p, "urosh1")
    p = PrivateKeyRowRSA("djafe@djafe", key_size, "fedja")
    keyrings["fedja"].add_private_ring(p, "urosh2")
    p = PrivateKeyRowRSA("lonchar@lonchar", key_size, "lonchar")
    keyrings["lonchar"].add_private_ring(p, "fedja1")


if __name__ == '__main__':
    pass

