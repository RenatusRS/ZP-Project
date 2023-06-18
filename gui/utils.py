import sys
from tkinter.filedialog import askopenfile, askopenfilenames, asksaveasfile
from backend.exceptions import InputException
from backend.messages.messages import create_message
from backend.keys.keyring import Keyring, keyrings
from backend.store import Store


def generate_keys(name, email, algorithm, size, password):
		if not name:
			raise InputException('Name is empty')
		
		if not email:
			raise InputException('Email is empty')
		
		if Store.USERNAME not in keyrings:
			keyrings[Store.USERNAME] = Keyring()
			Store.ROOT.add_user(Store.USERNAME)

		keyrings[Store.USERNAME].add_private_ring(algorithm(email, int(size), password), name)
		
		
def set_user(username: str):
	Store.USERNAME = username
	Store.ROOT.refresh()
	
	
def import_key():
	files = askopenfilenames(defaultextension='.rem', filetypes=[('REM file', '*.rem')])
		
	for file in files:
		if Store.USERNAME not in keyrings:
			keyrings[Store.USERNAME] = Keyring()
			Store.ROOT.add_user(Store.USERNAME)
		
		keyrings[Store.USERNAME].import_key(file)
		
	Store.ROOT.refresh()
	
	
def export_key(key, key_type: str):
	key_id = int.from_bytes(key.key_id, sys.byteorder)
		
	file = asksaveasfile(mode='w', defaultextension='.rem', filetypes=[('REM file', '*.rem')], initialfile=f'{key_type} {key_id}.rem')
		
	if file is None:
		return
		
	file.close()
		
	key.export_key(file.name)
		
		
def save_file(name, data, extension, file_type, mode='w'):
	file = asksaveasfile(mode=mode, defaultextension=f'.{extension}', filetypes=[(f'{file_type}', f'*.{extension}')], initialfile=f'{name}.{extension}')
	
	if file is None:
		return None
	
	file.write(data)
	file.close()
	
	return file.name


def read_file(extension, file_type, mode='r'):
	file = askopenfile(mode=mode, defaultextension=f'.{extension}', filetypes=[(f'{file_type}', f'*.{extension}')])
	
	if file is None:
		return None
	
	data = file.read()
	file.close()
	
	return data, file.name
	
	
def send_message(message, encr, auth, compr, radix64):
	if encr and encr[0] is None:
		raise InputException('No public key available')
	
	data = create_message(message, encr, auth, compr, radix64, contaminate=False)
	if auth:
		data2 = create_message(message, encr, auth, compr, radix64, contaminate=True)
		save_file('message_contaminated', data2, 'xtx', 'Encrypted text file', mode='wb')
		
	save_file('message', data, 'xtx', 'Encrypted text file', mode='wb')
	
	
def remove_private_key(key):
	key.remove(Store.USERNAME)
	Store.ROOT.refresh()
	
	
def remove_public_key(key):
	key.remove()
	Store.ROOT.refresh()
	
