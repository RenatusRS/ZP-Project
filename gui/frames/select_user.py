from backend.store import Store
from gui.frames.tab import Tab
from tkinter.ttk import Label, Combobox
from tkinter import LEFT, StringVar

from backend.keys.keyring import keyrings
from gui.utils import set_user


class SelectUserTab(Tab):
	def __init__(self, parent, *args, **kwargs):
		super().__init__(parent, (0, 0, 0, 0), *args, **kwargs)

	def fill(self):
		user = StringVar(value = Store.USERNAME)
		
		self.combo_users = Combobox(self, textvar = user, values=list(keyrings.keys()))
		
		user.trace('w', lambda *args: set_user(user.get()))
		
		# Pack
		
		Label(self, text='USER ').pack(side=LEFT)
		self.combo_users.pack(side=LEFT)

	def add_user(self, user):
		self.combo_users['values'] = (*self.combo_users['values'], user)