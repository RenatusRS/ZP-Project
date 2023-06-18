from tkinter import Tk, BOTH, messagebox
from gui.components.CTabbedView import CTabbedView
from gui.frames.select_user import SelectUserTab
from gui.frames.tab import Tab

import traceback

class TabbedWindow(Tk):

	def __init__(self):
		super().__init__()
		
		Tk.report_callback_exception = self.error_boundary

		self.tabbed = CTabbedView(self)
		
		self.user_input = SelectUserTab(self)
		
		self.user_input.pack(side='top', anchor='w', padx=10, pady=10)
		self.tabbed.pack(expand=True, fill=BOTH)			

	def add_tab(self, tab_class: Tab, title: str):
		self.tabbed.add_tab(tab_class, title)
		
	def refresh(self):
		self.tabbed.refresh()
		
	def add_user(self, user):
		self.user_input.add_user(user)
		
	def error_boundary(self, type, value, trace):
		print()
		print('=========================================')
		print('EXCEPTION')
		print('=========================================')
		print(f'{type.__name__}: {value}')
		print('=========================================')
		print(traceback.print_tb(trace))
		print('=========================================')

		messagebox.showerror('Error', value)
