import sys
from backend.store import Store
from gui.components.CCheckbutton import CCheckbutton
from gui.components.COptionMenu import COptionMenu
from gui.components.CRadiobutton import CRadiobutton
from gui.components.CRadiogroup import CRadiogroup
from gui.components.CText import CText
from gui.frames.tab import Tab
from tkinter.ttk import Label, Button, Separator, Frame
from tkinter import HORIZONTAL, LEFT, TOP, X, BOTTOM, BOTH, W

from backend.keys.keyring import Keyring, keyrings

from backend.utils import SymEnc
from gui.utils import send_message


class SendMessageTab(Tab):
	def __init__(self, parent, *args, **kwargs):
		super().__init__(parent, (5, 5, 5, 5), *args, **kwargs)

	def fill(self):
		# Encrypt
		checkbox_encrypt = CCheckbutton(self, text='Encrypt')

		group_encrypt = CRadiogroup()

		radio_encrypt_triple_des = CRadiobutton(self, text='Triple DES', value=SymEnc.DES3, group=group_encrypt)
		radio_encrypt_aes = CRadiobutton(self, text='AES128', value=SymEnc.AES, group=group_encrypt)

		frame_public_keys = Frame(self)

		option_public_keys = COptionMenu(frame_public_keys, {f'{key.user_id} [{int.from_bytes(key.key_id, sys.byteorder)}]': key for key in Keyring.public})

		# Authentication
		checkbox_authenticate = CCheckbutton(self, text='Authenticate')
		
		frame_private_keys = Frame(self)
		
		option_private_keys = COptionMenu(
			frame_private_keys,
			{
				f'{key.user_id} [{int.from_bytes(key.key_id, sys.byteorder)}]': key
				for key in keyrings[Store.USERNAME].private
			} if Store.USERNAME in keyrings else {}
		)

		# Compression
		checkbox_compress = CCheckbutton(self, text='Compress')

		# Conversion
		checkbox_convert = CCheckbutton(self, text='Convert')

		# Message
		text_message = CText(self, height=1, width=1)

		button_send_message = Button(
			self,
			text='📧 Send Message',
			command=lambda: send_message(
				text_message.data(),
				[option_public_keys.get(), group_encrypt.get()] if checkbox_encrypt.get() else None,
				[option_private_keys.get()] if checkbox_authenticate.get() else None,
				checkbox_compress.get(),
				checkbox_convert.get()
			)
		)
		
		# Pack
		checkbox_encrypt.pack(side=TOP, anchor=W)
		
		Label(self, text='Algorithm').pack(side=TOP, anchor=W, padx=(5, 0))
		radio_encrypt_triple_des.pack(side=TOP, anchor=W, padx=(10, 0))
		radio_encrypt_aes.pack(side=TOP, anchor=W, padx=(10, 0))
		
		Label(frame_public_keys, text='Public Key').pack(side=LEFT, anchor=W)
		option_public_keys.pack(side=LEFT, anchor=W, padx=(5, 0))
		
		frame_public_keys.pack(side=TOP, anchor=W, pady=(10, 0), padx=(5, 0))

		Separator(self, orient=HORIZONTAL).pack(side=TOP, fill=X, pady=10)

		checkbox_authenticate.pack(side=TOP, anchor=W)
		
		Label(frame_private_keys, text='Private Key').pack(side=LEFT, anchor=W)
		option_private_keys.pack(side=LEFT, anchor=W, padx=(5, 0))
		
		frame_private_keys.pack(side=TOP, anchor=W, padx=(5, 0))

		Separator(self, orient=HORIZONTAL).pack(side=TOP, fill=X, pady=10)

		checkbox_compress.pack(side=TOP, anchor=W)

		Separator(self, orient=HORIZONTAL).pack(side=TOP, fill=X, pady=10)

		checkbox_convert.pack(side=TOP, anchor=W)
		
		Separator(self, orient=HORIZONTAL).pack(side=TOP, fill=X, pady=10)

		Label(self, text='Message').pack(side=TOP, anchor=W)
		text_message.pack(side=TOP, anchor=W, expand=True, fill=BOTH)
		
		button_send_message.pack(side=BOTTOM, anchor=W, pady=(10, 0))


