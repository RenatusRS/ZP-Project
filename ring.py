from typing import Union, List, Dict

from utils import AsymEnc, gen_timestamp, get_key_id, timestamp_to_string
import pickle

import rsa
from Crypto.Cipher import CAST

import sys

from abc import ABC, abstractmethod


class PrivateKeyRow(ABC):
    def __init__(self, user_id: str, password: str):
        assert(len(user_id) > 0)

        self.timestamp: bytes       = gen_timestamp()
        self.user_id: str           = user_id


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
        assert(key_size == 1024 or key_size == 2048)
        super().__init__(user_id, password)
        self._algo = AsymEnc.RSA

        public_key, private_key = rsa.newkeys(key_size)

        cipher = CAST.new(password.encode('utf8'), CAST.MODE_OPENPGP)
        enc_private_key = cipher.encrypt(pickle.dumps(private_key))

        self._key_id: bytes             = get_key_id(public_key)
        self._public_key: rsa.PublicKey = public_key
        self._enc_private_key: bytes    = enc_private_key


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
        assert(key_size == 1024 or key_size == 2048)

        super().__init__(user_id, password)
        self._algo = AsymEnc.ELGAMAL

        self._key_id = None
        self._public_key = None
        self._enc_private_key = None
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
    def __init__(self, user_id: str):
        assert(len(user_id) > 0)

        self.timestamp: bytes          = gen_timestamp()
        self.user_id: str              = user_id


    def __repr__(self):
        rpr = '------------ ' + self.user_id +  ' ------------\n'
        rpr += 'timestamp: ' + timestamp_to_string(self.timestamp) + '\n'
        rpr += 'key_id:    ' + str(int.from_bytes(self.key_id, sys.byteorder)) + '\n'
        # rpr += str(self.public_key) + '\n'
        rpr += 'algorithm: ' + self.algo.name + '\n'
        rpr += '--------------------------' + '-'*len(self.user_id) + '\n'
        return rpr


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
    def __init__(self, public_key: rsa.PublicKey, user_id: str):
        assert(public_key is not None)
        super().__init__(user_id)
        self._key_id: bytes             = get_key_id(public_key)
        self._public_key: rsa.PublicKey = public_key
        self._algo: AsymEnc             = AsymEnc.RSA


    @property
    @abstractmethod
    def algo(self):
        return self._algo


    @property
    @abstractmethod
    def key_id(self):
        return self._key_id


    @property
    @abstractmethod
    def public_key(self):
        return self._public_key


class PublicKeyRowElGamal(PublicKeyRow):
    def __init__(self, public_key, user_id: str):
        assert(public_key is not None)
        super().__init__(user_id)
        self._key_id: bytes             = get_key_id(public_key)
        self._public_key: rsa.PublicKey = public_key
        self._algo: AsymEnc             = AsymEnc.ELGAMAL


    @property
    @abstractmethod
    def algo(self):
        return self._algo


    @property
    @abstractmethod
    def key_id(self):
        return self._key_id


    @property
    @abstractmethod
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
    keyrings["fedja"] = Keyring()
    keyrings["lonchar"] = Keyring()
    p = PrivateKeyRowRSA("fedja@fedja", 1024, "fedja")
    keyrings["fedja"].insert(p)
    keyrings["lonchar"].insert(PublicKeyRowRSA(p.public_key, "u1"))
    p = PrivateKeyRowRSA("djafe@djafe", 1024, "fedja")
    keyrings["fedja"].insert(p)
    keyrings["lonchar"].insert(PublicKeyRowRSA(p.public_key, "u2"))
    p = PrivateKeyRowRSA("lonchar@lonchar", 1024, "lonchar")
    keyrings["lonchar"].insert(p)
    keyrings["fedja"].insert(PublicKeyRowRSA(p.public_key, "urosh"))


if __name__ == '__main__':
    pass

