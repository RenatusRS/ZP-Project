import pickle
import random
from Crypto.PublicKey import DSA


class PublicKey:
	def __init__(self, p: int, g: int, h: int):
		self.p = p
		self.g = g
		self.h = h
		
	def __repr__(self) -> str:
		return f"PublicKey({self.p}, {self.g}, {self.h})"


class PrivateKey:
	def __init__(self, p: int, x: int):
		self.p = p
		self.x = x
		
	def __repr__(self) -> str:
		return f"PrivateKey({self.p}, {self.x})"


def generate_private_key(dsa_keypair: DSA.DsaKey) -> PrivateKey:
	p = dsa_keypair.p
	x = dsa_keypair.x
	
	private_key = PrivateKey(p, x)

	return private_key

def generate_public_key(public_key) -> PublicKey:
	p = public_key.p
	g = public_key.g
	h = public_key.y

	public_key = PublicKey(p, g, h)

	return public_key


def encrypt(msg: bytes, key: PublicKey) -> bytes:
	p = key.p
	g = key.g
	h = key.h

	# Convert the message to an integer
	m = int.from_bytes(msg, 'big')

	# Choose a random number between 2 and p-2
	y = random.randint(2, p - 2)

	# Calculate c1 = g^y mod p
	c1 = pow(g, y, p)

	# Calculate s = h^y mod p
	s = pow(h, y, p)

	# Calculate c2 = m * s mod p
	c2 = (m * s) % p

	return pickle.dumps((c1, c2))


def decrypt(ciphertext: bytes, key: PrivateKey) -> bytes:
	p = key.p
	x = key.x
	c1, c2 = pickle.loads(ciphertext)

	# Calculate s = c1^x mod p
	s = pow(c1, x, p)

	# Calculate s_inverse = s^(p-2) mod p using Fermat's little theorem
	s_inverse = pow(s, p - 2, p)

	# Calculate m = c2 * s_inverse mod p
	m = (c2 * s_inverse) % p

	# Convert the decrypted message back to bytes
	decrypted_msg = m.to_bytes((m.bit_length() + 7) // 8, 'big')

	return decrypted_msg


if __name__ == '__main__':
	# Example usage:
	DSA_keypair = DSA.generate(1024)
	private_key = generate_private_key(DSA_keypair)
	public_key = generate_public_key(DSA_keypair.publickey())
	message = b"Hello, ElGamal!"
	
	ciphertext = encrypt(message, public_key)
	print(ciphertext)
	decrypted_message = decrypt(ciphertext, private_key)
	print(decrypted_message)