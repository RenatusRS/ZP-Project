from backend.store import Store
from gui.components.CEntry import CEntry
from gui.components.CRadiobutton import CRadiobutton
from gui.frames.tab import Tab
from tkinter import *

from backend.ring import Keyring, keyrings, PrivateKeyRowRSA, PrivateKeyRowElGamal


class GenerateKeysTab(Tab):

	def fill(self):
		self.generate_keys_frame()

	def generate_keys_frame(self):
		frame = Frame(self)

		# Name
		frame_name = Frame(frame)

		entry_name = CEntry(frame_name, maxlength=16)

		Label(frame_name, text='Name').pack(side=LEFT)
		entry_name.pack(side=RIGHT)

		# Email
		frame_email = Frame(frame)

		entry_email = CEntry(frame_email, maxlength=16)

		Label(frame_email, text='Email').pack(side=LEFT)
		entry_email.pack(side=RIGHT)

		# Algorithm
		frame_algorithm = Frame(frame)
		
		group_algorithm = 'generate_algorithm'

		radio_algorithm_rsa = CRadiobutton(
			frame_algorithm,
			text='RSA',
			value=PrivateKeyRowRSA,
			group=group_algorithm,
		)

		radio_algorithm_dsa_elgamal = CRadiobutton(
			frame_algorithm,
			text='DSA + El Gamal',
			value=PrivateKeyRowElGamal,
			group=group_algorithm,
		)

		Label(frame_algorithm, text='Algorithm').pack(side=LEFT)
		radio_algorithm_dsa_elgamal.pack(side=RIGHT)
		radio_algorithm_rsa.pack(side=RIGHT)

		# Size
		frame_size = Frame(frame)
		
		group_size = 'generate_size'

		radio_size_1024 = CRadiobutton(frame_size, text='1024', value=1024, group=group_size)
		radio_size_2048 = CRadiobutton(frame_size, text='2048', value=2048, group=group_size)

		Label(frame_size, text='Size').pack(side=LEFT)
		radio_size_2048.pack(side=RIGHT)
		radio_size_1024.pack(side=RIGHT)

		# Password
		frame_password = Frame(frame)

		entry_password = CEntry(frame_password, show='*', maxlength=16)

		Label(frame_password, text='Password').pack(side=LEFT)
		entry_password.pack(side=RIGHT)

		# Generate
		button_generate = Button(
			frame,
			text='Generate Keys',
			command=lambda: self.generate_keys(
				entry_name.get(),
				entry_email.get(),
				CRadiobutton.get(group_algorithm),
				CRadiobutton.get(group_size),
				entry_password.get()
			)
		)

		# Pack
		frame_name.pack(side=TOP, expand=True, fill=BOTH)
		frame_email.pack(side=TOP, expand=True, fill=BOTH)
		frame_algorithm.pack(side=TOP, expand=True, fill=BOTH)
		frame_size.pack(side=TOP, expand=True, fill=BOTH)
		frame_password.pack(side=TOP, expand=True, fill=BOTH)
		button_generate.pack(side=BOTTOM, fill=BOTH)

		frame.pack(fill=BOTH, expand=True)

	def generate_keys(self, name, email, algorithm, size, password):	
		if Store.USERNAME not in keyrings:
			keyrings[Store.USERNAME] = Keyring()

		keyrings[Store.USERNAME].add_private_ring(algorithm(email, int(size), password), name)
