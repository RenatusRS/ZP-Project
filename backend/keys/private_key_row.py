from abc import ABC, abstractmethod
import base64
import pickle
import sys
from tkinter import simpledialog

import rsa
from Crypto.Cipher import AES, CAST, DES3
from Crypto.Hash import SHA256
from Crypto.PublicKey import DSA
from Crypto.Signature import DSS

from backend.config import Cfg
from backend.exceptions import *
from backend.keys.keyring import Keyring, keyrings
from backend.keys.public_key_row import PublicKeyRowElGamal, PublicKeyRowRSA
from backend.utils import *

import backend.el_gamal as el_gamal


class PrivateKeyRow(ABC):
	def __init__(self, user_id: str, key_size: int):
		assert(key_size == 1024 or key_size == 2048)

		if len(user_id) == 0:
			raise InputException('Email field is empty')

		self.timestamp: bytes = gen_timestamp()
		self.user_id: str     = user_id
		self.key_size: int    = key_size


	def __repr__(self):
		rpr = '------------ ' + self.user_id +  ' ------------\n'
		rpr += 'timestamp: ' + timestamp_to_string(self.timestamp) + '\n'
		rpr += 'key_id:    ' + str(int.from_bytes(self.key_id, sys.byteorder)) + '\n'
		# rpr += str(self.public_key) + '\n'
		rpr += 'algorithm: ' + self.algo.name + '\n'
		# rpr += str(int.from_bytes(self.enc_private_key, sys.byteorder)) + ')\n'
		rpr += '--------------------------' + '-'*len(self.user_id) + '\n'
		
		return rpr


	@staticmethod
	def cipher_pk(key: bytes, password: str) -> bytes:
		try:
			hsh = SHA256.new(password.encode('utf8')).digest()[:16] if Cfg.HASH_PASSWORD else password.encode('utf8')
			cipher = CAST.new(hsh, CAST.MODE_OPENPGP)

			return cipher.encrypt(key)
		
		except ValueError:
			raise BadPasswordFormat('Password must be 6 to 16 characters long')
		


	def decipher_pk(self, password: str) -> bytes:
		eiv = self.enc_private_key[:CAST.block_size+2]
		temp = self.enc_private_key[CAST.block_size+2:]
		
		try:
			hsh = SHA256.new(password.encode('utf8')).digest()[:16] if Cfg.HASH_PASSWORD else password.encode('utf8')
			cipher = CAST.new(hsh, CAST.MODE_OPENPGP, eiv)

			return cipher.decrypt(temp)
		
		except ValueError:
			raise BadPasswordFormat('Password must be 6 to 16 characters long')
		

	def remove(self, user: str) -> None:
		# assert(Keyring[user])
		
		keyrings[user].private = [x for x in keyrings[user].private if x != self]
		Keyring.public = [x for x in Keyring.public if x.public_key != self.public_key]


	@abstractmethod
	def add_public_key(self, name: str):
		pass


	@abstractmethod
	def decrypt(self, message: bytes, decr: SymEnc) -> bytes:
		pass


	@abstractmethod
	def sign(self, message: bytes, contaminate: bool = False):
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


	@abstractmethod
	def export_key(self, filename: str) -> None:
		pass


class PrivateKeyRowRSA(PrivateKeyRow):
	def __init__(self, user_id: str, key_size: int, password: str):
		super().__init__(user_id, key_size)
		
		self._algo = AsymEnc.RSA

		public_key, private_key = rsa.newkeys(key_size)

		enc_private_key = self.cipher_pk(pickle.dumps(private_key), password)

		self._key_id: bytes             = get_key_id_RSA(public_key)
		self._public_key: rsa.PublicKey = public_key
		self._enc_private_key: bytes    = enc_private_key


	def decrypt(self, message: bytes, decr: SymEnc) -> bytes:
		ENCRYPTED_SESSION_KEY_BYTES = int(self.key_size / 8)

		enc_session_key = message[:ENCRYPTED_SESSION_KEY_BYTES]
		message = message[ENCRYPTED_SESSION_KEY_BYTES:]

		block_size = AES.block_size if decr == SymEnc.AES else DES3.block_size

		iv = message[:block_size]
		message = message[block_size:]

		private_key = self.get_private_key()

		session_key = rsa.decrypt(enc_session_key, private_key)
		message = decrypt_with_session_key(decr, session_key, iv, message)
		
		return message


	def sign(self, message: bytes, contaminate: bool = False) -> bytes:
		private_key = self.get_private_key()
		
		hsh = rsa.compute_hash(message, 'SHA-1') # računanje hash-a poruke

		header: bytes = b''
		header += gen_timestamp() # timestamp - prvih TIMESTAMP_BYTE_SIZE bajtova
		header += self.key_id # ID javnog ključa pošiljaoca - 8 bajtova
		header += hsh[0:2] # prva dva okteta hash-a
		if not contaminate:
			header += rsa.sign_hash(hsh, private_key, 'SHA-1') # šifrovan hash
		else:
			SHA1_BYTE_SIZE = int(self.key_size / 8)
			header += int(0).to_bytes(SHA1_BYTE_SIZE, sys.byteorder)

		return header


	def add_public_key(self, name: str):
		'''
		Za generisani par ključeva dodaje javni ključ u globalni niz
		'''
		
		p = PublicKeyRowRSA(self.public_key, name, self.key_size)
		Keyring.public.append(p)



	def get_private_key(self):
		password = simpledialog.askstring(f"Access Private Key [{self.user_id}]", f"Enter password for [{self.user_id}]\t\t\t\t", show="*")
		
		if not password:
			raise WrongPasswordException('No password provided')

		try:
			temp = self.decipher_pk(password)
			priv = pickle.loads(temp)
			
			return priv
		
		except pickle.UnpicklingError:
			raise WrongPasswordException('Wrong password')
		


	def export_key(self, filename: str) -> None:
		with open(filename, 'wb') as f:
			encoded = base64.b64encode(pickle.dumps(self))
			
			f.write(b"-----BEGIN RSA PRIVATE KEY-----\n")
			f.write(encoded)
			f.write(b"\n")
			f.write(b"-----END RSA PRIVATE KEY-----\n")


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

		enc_private_key = self.cipher_pk(keypair.export_key(format='DER'), password)

		self._enc_private_key = enc_private_key


	def decrypt(self, message: bytes, decr: SymEnc) -> bytes:
		enc_session_key_length = int.from_bytes(message[0:2], sys.byteorder)
		message = message[2:]
		
		enc_session_key = message[:enc_session_key_length]
		message = message[enc_session_key_length:]
		
		block_size = AES.block_size if decr == SymEnc.AES else DES3.block_size
		
		iv = message[:block_size]
		message = message[block_size:]
		
		dsa_keypair = self.get_private_key()
		eg_private_key = el_gamal.generate_private_key(dsa_keypair)

		session_key = el_gamal.decrypt(enc_session_key, eg_private_key)
		message = decrypt_with_session_key(decr, session_key, iv, message)
		
		return message


	def sign(self, message: bytes, contaminate: bool = False):
		private_key = self.get_private_key()

		hsh = SHA256.new(message)
		signer = DSS.new(private_key, 'fips-186-3')
		signature = signer.sign(hsh)

		header: bytes = b''
		header += gen_timestamp() # timestamp - prvih TIMESTAMP_BYTE_SIZE bajtova
		header += self.key_id # ID javnog ključa pošiljaoca - 8 bajtova
		header += hsh.digest()[0:2] # prva dva okteta hash-a
		if not contaminate:
			header += signature # šifrovan hash
		else:
			dss_sign_size = 40 if self.key_size == 1024 else 56
			header += int(0).to_bytes(dss_sign_size, sys.byteorder)

		return header


	def add_public_key(self, name: str):
		p = PublicKeyRowElGamal(self.public_key, name, self.key_size)
		Keyring.public.append(p)


	def get_private_key(self):
		password = simpledialog.askstring(f"Access Private Key [{self.user_id}]", f"Enter password for [{self.user_id}]\t\t\t\t", show="*")
		
		if not password:
			raise WrongPasswordException('No password provided')

		priv = self.decipher_pk(password)
		try:
			return DSA.import_key(priv)
		
		except ValueError:
			raise WrongPasswordException('Wrong password')
		
		
	def export_key(self, filename: str) -> None:
		t = self.public_key
		self._public_key = self.public_key.export_key(format='DER')
		with open(filename, 'wb') as f:
			encoded = base64.b64encode(pickle.dumps(self))

			f.write(b"-----BEGIN ELGAMAL PRIVATE KEY-----\n")
			f.write(encoded)
			f.write(b"\n")
			f.write(b"-----END ELGAMAL PRIVATE KEY-----\n")
		self._public_key = t

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
