from typing import Union, List, Dict

from utils import AsymEnc, SymEnc, gen_timestamp, get_key_id, timestamp_to_string, generate_session_key, encrypt_with_session_key, decrypt_with_session_key
from config import Cfg
import pickle

import rsa
from Crypto.Cipher import CAST, AES, DES3

import sys

from abc import ABC, abstractmethod


class PrivateKeyRow(ABC):
    def __init__(self, user_id: str, key_size: int):
        assert(len(user_id) > 0)
        assert(key_size == 1024 or key_size == 2048)

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
    def decryption(self, message: bytes, decr: SymEnc) -> bytes:
        pass


    @abstractmethod
    def authentication(self, message: bytes):
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

        self._key_id: bytes             = get_key_id(public_key)
        self._public_key: rsa.PublicKey = public_key
        self._enc_private_key: bytes    = enc_private_key


    def decryption(self, message: bytes, decr: SymEnc) -> bytes:
        ENCRYPTED_SESSION_KEY_BYTES = int(self.key_size/8)

        enc_session_key = message[:ENCRYPTED_SESSION_KEY_BYTES]
        message = message[ENCRYPTED_SESSION_KEY_BYTES:]

        block_size = AES.block_size if decr == SymEnc.AES else DES3.block_size

        iv = message[:block_size]
        message = message[block_size:]

        private_key = self.get_private_key()
        assert(private_key is not None)

        session_key = rsa.decrypt(enc_session_key, private_key)
        message = decrypt_with_session_key(decr, session_key, iv, message)
        return message


    def authentication(self, message: bytes) -> bytes:
        private_key = self.get_private_key()
        assert(private_key is not None)

        header: bytes = b''
        header += gen_timestamp() # timestamp - prvih TIMESTAMP_BYTE_SIZE bajtova
        header += self.key_id # ID javnog ključa pošiljaoca - 8 bajtova

        hsh = rsa.compute_hash(message, 'SHA-1') # računanje hash-a poruke

        header += hsh[0:2] # prva dva okteta hash-a
        header += rsa.sign_hash(hsh, private_key, 'SHA-1') # šifrovan hash

        return header


    def get_private_key(self) -> Union[rsa.PrivateKey, None]:
        try:
            password = input("Unesi master šifru: ")
            eiv = self.enc_private_key[:CAST.block_size+2]
            temp = self.enc_private_key[CAST.block_size+2:]
            cipher = CAST.new(password.encode('utf8'), CAST.MODE_OPENPGP, eiv)
            priv = pickle.loads(cipher.decrypt(temp))
            return rsa.PrivateKey(priv.n, priv.e, priv.d, priv.p, priv.q)
        except pickle.UnpicklingError:
            return None


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

        self._key_id = None
        self._public_key = None
        self._enc_private_key = None
        raise Exception("Not yet implemented")


    def decryption(self, message: bytes, decr: SymEnc) -> bytes:
        raise Exception("Not yet implemented")


    def authentication(self, message: bytes):
        raise Exception("Not yet implemented")


    def get_private_key(self):
        raise Exception("Not yet implemented")


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
        assert(len(user_id) > 0)
        assert(key_size == 1024 or key_size == 2048)

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
    def auth_check(self, message: bytes, header: bytes) -> bytes:
        pass


    @abstractmethod
    def auth_header_size(self):
        pass


    @abstractmethod
    def encryption(self, message: bytes, algo: SymEnc) -> bytes:
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
        self._key_id: bytes             = get_key_id(public_key)
        self._public_key: rsa.PublicKey = public_key
        self._algo: AsymEnc             = AsymEnc.RSA


    def encryption(self, message: bytes, algo: SymEnc) -> bytes:
        header: bytes = b''
        header += self.key_id # na header dodaje ID javnog ključa primaoca
        session_key = generate_session_key() # generiše sesijski ključ (16B)
        header += rsa.encrypt(session_key, self.public_key) # na header dodaje šifrovan Ks
        message, iv = encrypt_with_session_key(algo, session_key, message)
        return header + iv + message # na header dodaje Cipher IV


    def auth_check(self, message: bytes, header: bytes) -> bytes:
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
        self._key_id: bytes             = get_key_id(public_key)
        self._public_key: rsa.PublicKey = public_key
        self._algo: AsymEnc             = AsymEnc.ELGAMAL


    @abstractmethod
    def auth_check(self, message: bytes, header: bytes) -> bytes:
        raise Exception("Not yet implemented")


    @abstractmethod
    def encryption(self, message: bytes, algo: SymEnc) -> bytes:
        raise Exception("Not yet implemented")


    def auth_header_size(self):
        raise Exception("Not yet implemented")


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
    def __init__(self):
        self.keyring: Tuple[List[PrivateKeyRow], List[PublicKeyRow]] = ([], [])

    def __getitem__(self, item):
        return self.keyring[item]


    def get_by_key(self, key_id, public: bool = True):
        for row in self.keyring[public]:
            if row.key_id == key_id:
                return row
        return None


    def get_by_user(self, user_id, public: bool = True):
        for row in self.keyring[public]:
            if row.user_id == user_id:
                return row
        return None


    def insert(self, keyrow: Union[PublicKeyRow, PrivateKeyRow]):
        public: bool = isinstance(keyrow, PublicKeyRow)
        self.keyring[public].append(keyrow)


    def __repr__(self):
        rpr = "=================== PRIVATE ====================\n"
        for row in self.keyring[0]:
            rpr += str(row)
        rpr += "\n==================== PUBLIC ====================\n"
        for row in self.keyring[1]:
            rpr += str(row)
        return rpr


keyrings: Dict[str, Keyring] = { }


def populate():
    key_size = 1024

    keyrings["fedja"] = Keyring()
    keyrings["lonchar"] = Keyring()
    p = PrivateKeyRowRSA("fedja@fedja", key_size, "fedja")
    keyrings["fedja"].insert(p)
    keyrings["lonchar"].insert(PublicKeyRowRSA(p.public_key, "u1", p.key_size))
    p = PrivateKeyRowRSA("djafe@djafe", key_size, "fedja")
    keyrings["fedja"].insert(p)
    keyrings["lonchar"].insert(PublicKeyRowRSA(p.public_key, "u2", p.key_size))
    p = PrivateKeyRowRSA("lonchar@lonchar", key_size, "lonchar")
    keyrings["lonchar"].insert(p)
    keyrings["fedja"].insert(PublicKeyRowRSA(p.public_key, "urosh", p.key_size))


if __name__ == '__main__':
    pass

