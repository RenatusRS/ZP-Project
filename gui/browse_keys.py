from tkinter import simpledialog
from gui.base import BaseFrame
from tkinter import *
from backend.config import Cfg

from backend.ring import Keyring, PublicKeyRow, keyrings, PrivateKeyRow


class Table(Frame):
	def __init__(self, parent, columns):
		super().__init__(parent)

		for ind, column in enumerate(columns):
			Grid.columnconfigure(self, ind, weight=1)
			Label(self, text=column).grid(row=0, column=ind, sticky=W)


class PrivateTable(Table):
	def __init__(self, parent):
		super().__init__(parent, ["Timestamp", "Key ID", "User ID", "Public Key", "Private Key"])
		
		private_keys = keyrings[Cfg.USERNAME].private if Cfg.USERNAME in keyrings else []
		
		for private_key in private_keys:
			self.insert(private_key)
	

	def insert(self, private_key: PrivateKeyRow):
		entry_timestamp = Entry(self)
		entry_timestamp.insert(0, private_key.timestamp)
		entry_timestamp.config(state="readonly")
		entry_timestamp['readonlybackground'] = "white"
		entry_timestamp['relief'] = 'ridge'
		
		entry_id = Entry(self)
		entry_id.insert(0, private_key.key_id)
		entry_id.config(state="readonly")
		entry_id['readonlybackground'] = "white"
		entry_id['relief'] = 'ridge'
		
		entry_user_id = Entry(self)
		entry_user_id.insert(0, private_key.user_id)
		entry_user_id.config(state="readonly")
		entry_user_id['readonlybackground'] = "white"
		entry_user_id['relief'] = 'ridge'
		
		entry_public_key = Entry(self)
		entry_public_key.insert(0, private_key.public_key)
		entry_public_key.config(state="readonly")
		entry_public_key['readonlybackground'] = "white"
		entry_public_key['relief'] = 'ridge'
		
		entry_private_key = Entry(self)
		entry_private_key.insert(0, "HIDDEN")
		entry_private_key.config(state="disabled")
		entry_private_key['readonlybackground'] = "white"
		entry_private_key['relief'] = 'ridge'
		entry_private_key['cursor'] = "hand2"
		
		entry_private_key.bind("<Button-1>", lambda _: self.show(private_key, entry_private_key))
		
		row = self.grid_size()[1]
		
		Grid.columnconfigure(self, 0, weight=1)
		Grid.columnconfigure(self, 1, weight=1)
		Grid.columnconfigure(self, 2, weight=1)
		Grid.columnconfigure(self, 3, weight=1)
		Grid.columnconfigure(self, 4, weight=1)
		Grid.columnconfigure(self, 5)
		
		entry_timestamp.grid(row=row, column=0, sticky=NSEW)
		entry_id.grid(row=row, column=1, sticky=NSEW)
		entry_user_id.grid(row=row, column=2, sticky=NSEW)
		entry_public_key.grid(row=row, column=3, sticky=NSEW)
		entry_private_key.grid(row=row, column=4, sticky=NSEW)
		
	def show(self, private_key: PrivateKeyRow, entry):
		password = simpledialog.askstring("Password", "Enter password", show="*")
		
		if password is None:
			return
		
		decrypted_key = private_key.get_private_key(password)
		
		if decrypted_key is None:
			return
		
		entry['cursor'] = "xterm"
		entry.unbind("<Button-1>")
		entry.config(state="normal")
		entry.delete(0, END)
		entry.insert(0, decrypted_key)
		entry.config(state="readonly")
		

class PublicTable(Table):
	def __init__(self, parent):
		super().__init__(parent, ["Timestamp", "Key ID", "Public Key", "User ID"])
		
		public_keys = Keyring.public
		
		for public_key in public_keys:
			self.insert(public_key)
			
			
	def insert(self, public_key: PublicKeyRow):
		entry_timestamp = Entry(self)
		entry_timestamp.insert(0, public_key.timestamp)
		entry_timestamp.config(state="readonly")
		entry_timestamp['readonlybackground'] = "white"
		entry_timestamp['relief'] = 'ridge'
		
		entry_id = Entry(self)
		entry_id.insert(0, public_key.key_id)
		entry_id.config(state="readonly")
		entry_id['readonlybackground'] = "white"
		entry_id['relief'] = 'ridge'
		
		entry_user_id = Entry(self)
		entry_user_id.insert(0, public_key.user_id)
		entry_user_id.config(state="readonly")
		entry_user_id['readonlybackground'] = "white"
		entry_user_id['relief'] = 'ridge'
		
		entry_public_key = Entry(self)
		entry_public_key.insert(0, public_key.public_key)
		entry_public_key.config(state="readonly")
		entry_public_key['readonlybackground'] = "white"
		entry_public_key['relief'] = 'ridge'
		
		row = self.grid_size()[1]
		
		Grid.columnconfigure(self, 0, weight=1)
		Grid.columnconfigure(self, 1, weight=1)
		Grid.columnconfigure(self, 2, weight=1)
		Grid.columnconfigure(self, 3, weight=1)
		
		entry_timestamp.grid(row=row, column=0, sticky=NSEW)
		entry_id.grid(row=row, column=1, sticky=NSEW)
		entry_user_id.grid(row=row, column=2, sticky=NSEW)
		entry_public_key.grid(row=row, column=3, sticky=NSEW)

class BrowseKeysFrame(BaseFrame):
	title = "Browse Keys"

	def fill(self):
		self.private_keys_frame()
		self.public_keys_frame()

	def private_keys_frame(self):
		PrivateTable(self).pack(side=TOP, anchor=W, expand=True, fill="both")

	def public_keys_frame(self):
		PublicTable(self).pack(side=TOP, anchor=W, expand=True, fill="both")
