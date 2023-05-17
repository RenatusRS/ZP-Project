from tkinter.ttk import Entry
from tkinter import StringVar, W

class CEntry(Entry):
	def __init__(self, parent, maxlength = None, *args, **kwargs):
		variable = StringVar()
		
		super().__init__(parent, textvariable=variable, *args, **kwargs)
		
		self.maxlength = maxlength
		
		variable.trace(W, lambda *args: self.on_change(variable))
		
	def on_change(self, variable):
		if self.maxlength is not None:
			variable.set(variable.get()[:self.maxlength])