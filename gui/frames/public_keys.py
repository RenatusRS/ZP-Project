import sys
from backend.keys.keyring import Keyring
from backend.keys.public_key_row import PublicKeyRow

from backend.utils import timestamp_to_string
from gui.components.CTable import Table
from gui.frames.tab import Tab
from tkinter import *

from gui.utils import export_key, remove_public_key


class PublicKeysTab(Tab):
	def __init__(self, parent, *args, **kwargs):
		super().__init__(parent, (0, 0, 0, 0), *args, **kwargs)

	def fill(self):
		PublicTable(self).pack(side=TOP, anchor=W, expand=True, fill=BOTH)


class PublicTable(Table):
	def __init__(self, parent):
		super().__init__(parent, ['Timestamp', 'Key ID', 'User ID', 'Public Key'])
		
		for public_key in Keyring.public:
			self.insert(public_key)
			
			
	def insert(self, key: PublicKeyRow):
		row = self.table.grid_size()[1]
		
		timestamp = timestamp_to_string(key.timestamp)
		key_id = int.from_bytes(key.key_id, sys.byteorder)
		
		for ind, col in enumerate([timestamp, key_id, key.user_id, key.public_key]):
			entry = Entry(self.table)
			entry.insert(0, col)
			entry.config(state='readonly', relief='ridge', readonlybackground='white')
			entry.grid(row=row, column=ind, sticky=NSEW)
			Grid.columnconfigure(self.table, ind, weight=1)
			
		button_export = Button(self.table, text='EXPORT', command=lambda: export_key(key, "PU"))
		button_delete = Button(self.table, text='❌     ', command=lambda: remove_public_key(key))
		
		button_export.grid(row=row, column=4, sticky=NSEW)
		button_delete.grid(row=row, column=5, sticky=NSEW)
