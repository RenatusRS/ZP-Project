from abc import ABC, abstractmethod
import base64
import pickle
import sys

import rsa
from Crypto.Hash import SHA256
from Crypto.PublicKey import DSA
from Crypto.Signature import DSS

from backend.exceptions import *
from backend.keys.keyring import Keyring
from backend.utils import *

import backend.el_gamal as el_gamal


class PublicKeyRow(ABC):
	def __init__(self, user_id: str, key_size: int):
		assert(key_size == 1024 or key_size == 2048)

		if len(user_id) == 0:
			raise InputException('Name field is empty')

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


	def remove(self) -> None:
		Keyring.public = [x for x in Keyring.public if x != self]


	@abstractmethod
	def verify(self, message: bytes, header: bytes) -> bytes:
		pass


	@abstractmethod
	def auth_header_size(self):
		pass


	@abstractmethod
	def encrypt(self, message: bytes, algo: SymEnc) -> bytes:
		pass


	@abstractmethod
	def export_key(self) -> None:
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
		session_key = generate_session_key() # generiše sesijski ključ (16B)
		
		header: bytes = b''
		header += self.key_id # na header dodaje ID javnog ključa primaoca
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

		SHA1_BYTE_SIZE = int(self.key_size / 8)
		digest = header[:SHA1_BYTE_SIZE]

		message = message[self.auth_header_size():]
		
		try:
			rsa.verify(message, digest, pu)
			
		except rsa.pkcs1.VerificationError:
			raise VerificationFailed('Verification failed')
			
		return message


	def export_key(self, filename: str) -> None:
		with open(filename, 'wb') as f:
			encoded = base64.b64encode(pickle.dumps(self))
			
			f.write(b"-----BEGIN RSA PUBLIC KEY-----\n")
			f.write(encoded)
			f.write(b"\n")
			f.write(b"-----END RSA PUBLIC KEY-----\n")


	def auth_header_size(self):
		return Cfg.TIMESTAMP_BYTE_SIZE + Cfg.KEY_ID_SIZE + 2 + int(self.key_size / 8)


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
			raise VerificationFailed('Verification failed')

		return message


	def encrypt(self, message: bytes, algo: SymEnc) -> bytes:		
		session_key = generate_session_key() # generiše sesijski ključ (16B)
		
		dsa_public_key = self.public_key
		el_gamal_public_key = el_gamal.generate_public_key(dsa_public_key)
		
		enc_session_key = el_gamal.encrypt(session_key, el_gamal_public_key)
		
		header = b''
		header += self.key_id
		header += len(enc_session_key).to_bytes(2, sys.byteorder)
		header += enc_session_key
		
		message, iv = encrypt_with_session_key(algo, session_key, message)
		
		return header + iv + message
		
		
	def export_key(self, filename: str) -> None:
		with open(filename, 'wb') as f:
			encoded = base64.b64encode(pickle.dumps(self))
			
			f.write(b"-----BEGIN ELGAMAL PUBLIC KEY-----\n")
			f.write(encoded)
			f.write(b"\n")
			f.write(b"-----END ELGAMAL PUBLIC KEY-----\n")


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
