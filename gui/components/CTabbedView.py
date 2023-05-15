from tkinter import *
from tkinter.ttk import Notebook

from gui.frames.tab import Tab

class CTabbedView(Notebook):
	def __init__(self, parent, *args, **kwargs):
		super().__init__(parent, *args, **kwargs)

		self.bind('<<NotebookTabChanged>>', lambda _: self.refresh())
		
	def refresh(self):
		tab: Tab = self.winfo_children()[self.index('current')]
		tab.refresh()
		
	def add_tab(self, tab_class: Tab, text: str):
		tab = tab_class(self)
		self.add(tab, text=text)