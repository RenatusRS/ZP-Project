import sys
from backend.ring import Keyring, PublicKeyRow
from backend.utils import timestamp_to_string
from gui.components.CTable import Table
from gui.frames.tab import Tab
from tkinter import *


class PublicKeysTab(Tab):

	def fill(self):
		PublicTable(self).pack(side=TOP, anchor=W, expand=True, fill=BOTH)
		
		Button(self, text='Import Public Key', command=self.import_public_key).pack(side=LEFT, anchor=W)
		
	def import_public_key(self):
		pass


class PublicTable(Table):
	def __init__(self, parent):
		super().__init__(parent, ['Timestamp', 'Key ID', 'User ID', 'Public Key'])
		
		for public_key in Keyring.public:
			self.insert(public_key)
			
			
	def insert(self, public_key: PublicKeyRow):
		row = self.table.grid_size()[1]
		
		timestamp = timestamp_to_string(public_key.timestamp)
		key_id = int.from_bytes(public_key.key_id, sys.byteorder)
		
		for ind, col in enumerate([timestamp, key_id, public_key.user_id, public_key.public_key]):
			entry = Entry(self.table)
			entry.insert(0, col)
			entry.config(state='readonly', relief='ridge', readonlybackground='white')
			entry.grid(row=row, column=ind, sticky=NSEW)
			Grid.columnconfigure(self.table, ind, weight=1)
			
		button_export = Button(self.table, text='Export     ', command=lambda: public_key.export())
		button_export.grid(row=row, column=4, sticky=NSEW)
