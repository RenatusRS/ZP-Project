from tkinter.ttk import Checkbutton
from tkinter import BooleanVar


class CCheckbutton(Checkbutton):
	def __init__(self, parent, *args, **kwargs):
		self.variable = BooleanVar()
		
		super().__init__(parent, variable=self.variable, *args, **kwargs)
			
	def get(self) -> bool:
		return self.variable.get()