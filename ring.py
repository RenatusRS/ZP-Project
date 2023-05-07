import typing

from messages import AsymEnc, gen_timestamp, get_key_id
import pickle

import rsa
from Crypto.Cipher import CAST


class PrivateKeyRow:
    def __init__(self, user_id: str, algo: AsymEnc, key_size: int):
        assert(len(user_id) > 0)
        assert(algo is AsymEnc.RSA or algo is AsymEnc.ELGAMAL)
        assert(key_size == 1024 or key_size == 2048)

        public_key, private_key = rsa.newkeys(key_size)
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

        cipher = CAST.new(pw1.encode('utf8'), CAST.MODE_OPENPGP)
        enc_private_key = cipher.encrypt(pickle.dumps(private_key))
        ''' decryption
        try:
            eiv = enc_private_key[:CAST.block_size+2]
            temp = enc_private_key[CAST.block_size+2:]
            cipher = CAST.new(pw1.encode('utf8'), CAST.MODE_OPENPGP, eiv)
            new_priv = pickle.loads(cipher.decrypt(temp))
        except _pickle.UnpicklingError:
            pass # TODO
        '''

        self.timestamp: bytes       = gen_timestamp()
        self.key_id: bytes          = get_key_id(public_key)
        self.public_key: rsa.PublicKey = public_key
        self.algo: AsymEnc          = algo
        self.enc_private_key: bytes = enc_private_key
        self.user_id: str           = user_id


class PublicKeyRow:
    def __init__(self, public_key: rsa.PublicKey, user_id: str, algo: AsymEnc):
        self.timestamp: bytes          = gen_timestamp()
        self.key_id: bytes             = get_key_id(public_key)
        self.public_key: rsa.PublicKey = public_key
        self.user_id: str              = user_id
        self.algo: AsymEnc             = algo


class Keyring:
    def __init__(self):
        self.keyring = []

    def get_by_key(self, key_id):
        for row in self.keyring:
            if row.key_id == key_id:
                return row
        return None

    def get_by_user(self, user_id):
        for row in self.keyring:
            if row.user_id == user_id:
                return row
        return None

    def insert(self, keyrow):
        self.keyring.append(keyrow)

