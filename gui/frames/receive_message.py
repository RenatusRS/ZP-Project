from backend.exceptions import BadPasswordFormat, WrongPasswordException
from backend.store import Store
from gui.components.CFileBrowser import CFileBrowser
from gui.components.CLabel import CLabel
from gui.components.CText import CText
from gui.frames.tab import Tab
from tkinter.ttk import Label, Button
from tkinter import BOTTOM, X, TOP, BOTH, W

from backend.messages.messages import read_message
from gui.utils import read_file, save_file


class ReceiveMessageTab(Tab):
	def __init__(self, parent, *args, **kwargs):
		super().__init__(parent, (5, 5, 5, 5), *args, **kwargs)
	
	def fill(self):
		self.filebrowser_recieve_message = CFileBrowser(self, button_text='📩 Receive Message', file_type=('xtx', 'Encrypted text file'))
		
		button_decrypt = Button(self, text='🔐 Decrypt', command=lambda: self.process_message(self.filebrowser_recieve_message.get_data(mode='rb')))
		
		self.label_convert = CLabel(self, text='⬜ Converted')
		self.label_encrypt = CLabel(self, text='⬜ Decrypted')
		self.label_compress = CLabel(self, text='⬜ Decompressed')
		self.label_verify = CLabel(self, text='⬜ Verified')
		
		self.text_message = CText(self, read_only=True, height=1, width=1)
		
		button_save_message = Button(self, text='💾 Save Message', command=lambda: save_file('message', self.text_message.data(), 'txt', 'Text file'))
		
		self.filebrowser_recieve_message.pack(side=TOP, fill=X)
		
		self.label_convert.pack(side=TOP, fill=X, pady=(10, 0))
		self.label_encrypt.pack(side=TOP, fill=X)
		self.label_compress.pack(side=TOP, fill=X)
		self.label_verify.pack(side=TOP, fill=X)

		button_decrypt.pack(side=TOP, anchor=W)
		
		Label(self, text='Decrypted Message').pack(side=TOP, anchor=W, pady=(10, 0))
		self.text_message.pack(side=TOP, fill=BOTH, expand=True)
		
		button_save_message.pack(side=BOTTOM, anchor=W, pady=(10, 0))
		
		
	def process_message(self, data):
		if data is None:
			self.filebrowser_recieve_message.browse()
			data = self.filebrowser_recieve_message.get_data(mode='rb')
		
		self.label_convert.set('⬜ Converted')
		self.label_encrypt.set('⬜ Decrypted')
		self.label_compress.set('⬜ Decompressed')
		self.label_verify.set('⬜ Verified')
		
		try:
			verification = None
			encryption = None
			compression = None
			conversion = None
			
			data, verification, encryption, compression, conversion = read_message(Store.USERNAME, data)
			
			# message[Cfg.TIMESTAMP_BYTE_SIZE:].decode('utf8'), (public_key_id, valid) if f_auth else None, (SymEnc(f_sym), private_key_ring) if f_sym and f_asym else None, f_comp, f_radix
		except (WrongPasswordException, BadPasswordFormat):
			self.text_message.clear()
			
			self.label_encrypt.set('❎ Decrypted - Wrong Password')
			
			return
		
		except KeyError:
			self.text_message.clear()
			
			self.label_encrypt.set('❎ Decrypted - Missing Key')
			return
		
		finally:
			self.label_convert.set(f'{"✅" if conversion else "⬜"} Converted')
		
		if encryption:	
			self.label_encrypt.set(f'✅ Decrypted - Key {encryption[1]} [{encryption[0].name}]')
			
		self.label_compress.set(f'{"✅" if compression else "⬜"} Decompressed')	
		
		if verification:
			self.label_verify.set(f'{"✅" if verification[1] else "❎"} Verified - Key {verification[0]}')
		
		self.text_message.set(data)

