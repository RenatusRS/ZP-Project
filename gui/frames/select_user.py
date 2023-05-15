from tkinter.ttk import Combobox
from backend.store import Store
from gui.frames.tab import Tab
from tkinter import *

from backend.ring import keyrings


class SelectUserTab(Tab):

	def fill(self):
		frame_user_input = Frame(self)
		
		user = StringVar(value = Store.USERNAME)
		user.trace(W, lambda a, b, c: self.set_user(user.get()))
		
		combo_users = Combobox(frame_user_input, textvar = user, values=list(keyrings.keys()))
		
		# Pack
		
		Label(frame_user_input, text='User').pack(side=TOP)
		combo_users.pack(side=TOP)
		Label(frame_user_input, text='').pack(side=TOP)
		
		frame_user_input.pack(side=TOP)
		
		frame_user_input.pack(side=TOP, expand=True, fill=X)
		
	
	def set_user(self, user):
		if user == '':
			return
		
		Store.USERNAME = user
		Store.ROOT.title(f'ZP Projekat 2022/2023 [{Store.USERNAME}]')
