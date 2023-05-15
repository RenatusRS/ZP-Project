import sys
from backend.ring import keyrings, PrivateKeyRow
from backend.store import Store
from backend.utils import timestamp_to_string
from gui.components.CTable import Table
from gui.frames.tab import Tab
from tkinter import *


class PrivateKeysTab(Tab):

	def fill(self):
		PrivateTable(self).pack(side=TOP, anchor=W, expand=True, fill=BOTH)
		
		Button(self, text='Import Private Key', command=self.import_private_key).pack(side=LEFT, anchor=W)

	def import_private_key(self):
		pass
	
	
class PrivateTable(Table):
	def __init__(self, parent):
		super().__init__(parent, ['Timestamp', 'Key ID', 'User ID', 'Public Key', 'Private Key'])
		
		private_keys = keyrings[Store.USERNAME].private if Store.USERNAME in keyrings else []
		
		for private_key in private_keys:
			self.insert(private_key)
			
	
	def insert(self, private_key: PrivateKeyRow):
		row = self.table.grid_size()[1]
		
		timestamp = timestamp_to_string(private_key.timestamp)
		key_id = int.from_bytes(private_key.key_id, sys.byteorder)
		
		for ind, col in enumerate([timestamp, key_id, private_key.user_id, private_key.public_key]):
			entry = Entry(self.table)
			entry.insert(0, col)
			entry.config(state='readonly', relief='ridge', readonlybackground='white')
			entry.grid(row=row, column=ind, sticky=NSEW)
			Grid.columnconfigure(self.table, ind, weight=1)
		
		entry_private_key = Entry(self.table)
		entry_private_key.insert(0, '# CLICK TO REVEAL #')
		entry_private_key.config(state='disabled', readonlybackground='white', relief='ridge', cursor='hand2')
		Grid.columnconfigure(self.table, 4, weight=1)
		
		entry_private_key.bind('<Button-1>', lambda _: self.show(private_key, entry_private_key))
		
		button_export = Button(self.table, text='Export', command=lambda: private_key.export())
		
		button_delete = Button(self.table, text='Delete     ', command=lambda: private_key.delete())

		entry_private_key.grid(row=row, column=4, sticky=NSEW)
		button_export.grid(row=row, column=5, sticky=NSEW)
		button_delete.grid(row=row, column=6, sticky=NSEW)
		
		
	def show(self, private_key: PrivateKeyRow, entry: Entry):
		decrypted_key = private_key.get_private_key()
		
		if decrypted_key is None:
			return
		
		entry.unbind('<Button-1>')
		entry.config(state='normal')
		entry.delete(0, END)
		entry.insert(0, decrypted_key)
		entry.config(state='readonly', cursor='xterm')
