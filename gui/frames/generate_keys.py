from tkinter import LEFT, RIGHT, TOP, BOTTOM, BOTH, W, X
from backend.store import Store
from gui.components.CEntry import CEntry
from gui.components.CRadiobutton import CRadiobutton
from gui.components.CRadiogroup import CRadiogroup
from gui.frames.tab import Tab
from tkinter.ttk import Frame, Label, Button

from backend.ring import Keyring, keyrings, PrivateKeyRowRSA, PrivateKeyRowElGamal
from gui.utils import generate_keys


class GenerateKeysTab(Tab):
	def __init__(self, parent, *args, **kwargs):
		super().__init__(parent, (5, 5, 5, 5), *args, **kwargs)

	def fill(self):
		# Name
		frame_name = Frame(self)
		entry_name = CEntry(frame_name, maxlength=16)

		# Email
		frame_email = Frame(self)
		entry_email = CEntry(frame_email, maxlength=16)

		# Algorithm
		frame_algorithm = Frame(self)
		
		group_algorithm = CRadiogroup()

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

		# Size
		frame_size = Frame(self)
		
		group_size = CRadiogroup()

		radio_size_1024 = CRadiobutton(frame_size, text='1024 B', value=1024, group=group_size)
		radio_size_2048 = CRadiobutton(frame_size, text='2048 B', value=2048, group=group_size)
		
		# Password
		frame_password = Frame(self)
		entry_password = CEntry(frame_password, show='*', maxlength=16)

		# Generate
		button_generate = Button(
			self,
			text='Generate Keys',
			command=lambda: generate_keys(
				entry_name.get(),
				entry_email.get(),
				group_algorithm.get(),
				group_size.get(),
				entry_password.get()
			)
		)

		# Pack
		Label(frame_name, text='Name').pack(side=TOP, anchor="nw")
		entry_name.pack(side=TOP, anchor="nw")
		
		Label(frame_email, text='Email').pack(side=TOP, anchor="nw")
		entry_email.pack(side=TOP, anchor="nw")
		
		Label(frame_algorithm, text='Algorithm').pack(side=TOP, anchor="nw")
		radio_algorithm_rsa.pack(side=TOP, anchor="nw", padx=(5, 0))
		radio_algorithm_dsa_elgamal.pack(side=TOP, anchor="nw", padx=(5, 0))
		
		Label(frame_size, text='Key Size').pack(side=TOP, anchor="nw")
		radio_size_1024.pack(side=TOP, anchor="nw", padx=(5, 0))
		radio_size_2048.pack(side=TOP, anchor="nw", padx=(5, 0))
		
		Label(frame_password, text='Password').pack(side=TOP, anchor="nw")
		entry_password.pack(side=TOP, anchor="nw")
		
		frame_name.pack(side=TOP, anchor=W, fill=X, expand=True)
		frame_email.pack(side=TOP, anchor=W, fill=X, expand=True, pady=(0, 10))
		frame_algorithm.pack(side=TOP, anchor=W, fill=X, expand=True, pady=(0, 10))
		frame_size.pack(side=TOP, anchor=W, fill=X, expand=True, pady=(0, 10))
		frame_password.pack(side=TOP, anchor=W, fill=X, expand=True, pady=(0, 10))
		
		button_generate.pack(side=BOTTOM, anchor=W)


