from tkinter import *
from tkinter import messagebox
from gui.components.CTabbedView import CTabbedView
from gui.frames.tab import Tab

class TabbedWindow(Tk):

	def __init__(self):
		super().__init__()
		
		Tk.report_callback_exception = self.error_boundry

		self.tabbed = CTabbedView(self)
		self.tabbed.pack(expand=True, fill=BOTH)
				

	def add_tab(self, tab_class: Tab, title: str):
		self.tabbed.add_tab(tab_class, title)
		

	def error_boundry(self, type, value, traceback):
		print()
		print('=========================================')
		print('Exception')
		print('=========================================')
		print(f'{type.__name__}: {value}')

		messagebox.showerror('Error', f'{type.__name__}: {value}')
