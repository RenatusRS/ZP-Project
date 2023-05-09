from tkinter.ttk import Combobox
from gui.base import BaseFrame
from tkinter import *
from backend.config import Cfg

from backend.ring import keyrings


class SelectUserFrame(BaseFrame):
	title = "Select User"

	def fill(self):
		frame_userinput = Frame(self)
		
		user = StringVar(value = Cfg.USERNAME)
		user.trace("w", lambda a, b, c: self.swap(user.get()))
		
		combo_users = Combobox(frame_userinput, textvar = user, values=list(keyrings.keys()))
		
		Label(frame_userinput, text="User").pack(side="top")
		combo_users.pack(side="top")
		
		frame_userinput.pack(side="top", expand=True, fill="x")
		
	
	def swap(self, user):
		if user == "":
			return
		
		Cfg.USERNAME = user
		self.master.master.title(f"ZP Projekat 2022/2023 [{Cfg.USERNAME}]")
		
		
