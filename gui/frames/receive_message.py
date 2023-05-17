from backend.exceptions import BadPasswordFormat, WrongPasswordException
from backend.store import Store
from gui.components.CFileBrowser import CFileBrowser
from gui.components.CLabel import CLabel
from gui.frames.tab import Tab
from tkinter.ttk import Label, Button
from tkinter import BOTTOM, X, TOP, BOTH, W, Text

from backend.messages import read_message
from gui.utils import read_file, save_file


class ReceiveMessageTab(Tab):
	def __init__(self, parent, *args, **kwargs):
		super().__init__(parent, (5, 5, 5, 5), *args, **kwargs)
	
	def fill(self):
		filebrowser_recieve_message = CFileBrowser(self, button_text='Receive Message', file_type=('xtx', 'Encrypted text file'))
		
		button_decrypt = Button(self, text='Decrypt', command=lambda: self.process_message(filebrowser_recieve_message.get_data(mode='rb')))
		
		self.label_convert = CLabel(self, text='[ ] Converted')
		self.label_encrypt = CLabel(self, text='[ ] Decrypted')
		self.label_compress = CLabel(self, text='[ ] Decompressed')
		self.label_verify = CLabel(self, text='[ ] Verified')
		
		self.text_message = Text(self, height=1, width=1)
		
		button_save_message = Button(self, text='Save Message', command=lambda: save_file('message', self.text_message.get('1.0', 'end-1c'), 'txt', 'Text file'))
		
		filebrowser_recieve_message.pack(side=TOP, fill=X)
		
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
			return
		
		try:
			self.label_convert.set('[V] Converted')
			data = read_message(Store.USERNAME, data)
			
		except (WrongPasswordException, BadPasswordFormat):
			self.text_message.delete('1.0', 'end')
			
			self.label_encrypt.set('[X] Decrypted - Wrong Password')
			self.label_compress.set('[ ] Decompressed')
			self.label_verify.set('[ ] Verified')
			
			return
		except KeyError:
			self.text_message.delete('1.0', 'end')
			
			self.label_encrypt.set('[X] Decrypted - Missing Key')
			self.label_compress.set('[ ] Decompressed')
			self.label_verify.set('[ ] Verified')
			return
			
		self.label_encrypt.set('[V] Decrypted')
		self.label_compress.set('[V] Decompressed')
		self.label_verify.set('[V] Verified')
		
		self.text_message.delete('1.0', 'end')
		self.text_message.insert('1.0', data)
