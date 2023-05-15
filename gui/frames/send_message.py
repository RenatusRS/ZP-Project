from tkinter.ttk import Separator
from backend.store import Store
from gui.components.CCheckbutton import CCheckbutton
from gui.components.COptionMenu import COptionMenu
from gui.components.CRadiobutton import CRadiobutton
from gui.frames.tab import Tab
from tkinter import *
from tkinter.filedialog import asksaveasfile

from backend.messages import create_message
from backend.ring import Keyring, keyrings

from backend.utils import SymEnc


class SendMessageTab(Tab):

	def fill(self):
		# Encrypt
		checkbox_encrypt = CCheckbutton(self, text='Encrypt')

		group_encrypt = 'encrypt_algorithm'

		radio_encrypt_triple_des = CRadiobutton(self, text='Triple DES', value=SymEnc.DES3, group=group_encrypt)
		radio_encrypt_aes = CRadiobutton(self, text='AES128', value=SymEnc.AES, group=group_encrypt)

		option_public_keys = COptionMenu(self, [(key.user_id, key) for key in Keyring.public])

		# Authentication
		checkbox_authenticate = CCheckbutton(self, text='Authenticate')
		
		option_private_keys = COptionMenu(self, [(key.user_id, key) for key in keyrings[Store.USERNAME].private] if Store.USERNAME in keyrings else [])

		# Compression
		checkbox_compress = CCheckbutton(self, text='Compress')

		# Conversion
		checkbox_convert = CCheckbutton(self, text='Convert')

		# Message
		text_message = Text(self, height=1, width=1)

		button_send_message = Button(
			self,
			text='Send Message',
			command=lambda: self.send_message(
				text_message.get('1.0', 'end-1c'),
				(option_public_keys.get(), CRadiobutton.get(group_encrypt)) if checkbox_encrypt.get() else None,
				option_private_keys.get() if checkbox_authenticate.get() else None,
				checkbox_compress.get(),
				checkbox_convert.get()
			)
		)
		
		# Pack
		checkbox_encrypt.pack(side=TOP, anchor=W)
		
		Label(self, text='Algorithm').pack(side=TOP, anchor=W)
		radio_encrypt_triple_des.pack(side=TOP, anchor=W)
		radio_encrypt_aes.pack(side=TOP, anchor=W)
		
		Label(self, text='Public Key').pack(side=TOP, anchor=W)
		option_public_keys.pack(side=TOP, anchor=W)

		Separator(self, orient=HORIZONTAL).pack(side=TOP, fill=X, pady=10)

		checkbox_authenticate.pack(side=TOP, anchor=W)
		
		Label(self, text='Private Key').pack(side=TOP, anchor=W)
		option_private_keys.pack(side=TOP, anchor=W)

		Separator(self, orient=HORIZONTAL).pack(side=TOP, fill=X, pady=10)

		checkbox_compress.pack(side=TOP, anchor=W)

		Separator(self, orient=HORIZONTAL).pack(side=TOP, fill=X, pady=10)

		checkbox_convert.pack(side=TOP, anchor=W)

		Label(self, text='Message').pack(side=TOP, anchor=W)
		text_message.pack(side=TOP, anchor=W, expand=True, fill=BOTH)
		button_send_message.pack(side=BOTTOM, fill=X)

	def send_message(self, message, encr, auth, compr, radix64):
		data = create_message(message, encr, auth, compr, radix64)

		file = asksaveasfile(mode='wb', defaultextension='.xtx', filetypes=[('Encrypted text file', '*.xtx')], initialfile=f'message.xtx')

		if file is None:
			return

		file.write(data)
		file.close()
