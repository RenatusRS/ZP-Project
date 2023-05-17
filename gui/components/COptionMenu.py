from tkinter.ttk import OptionMenu
from tkinter import StringVar, DISABLED

class COptionMenu(OptionMenu):
	def __init__(self, parent, values):
		self.values = values if values else {"No Options": None}
		
		default = list(self.values)[0]
		
		self.variable = StringVar(value=default)
		
		super().__init__(parent, self.variable, default, *self.values.keys())
		
		if not values:
			self.configure(state=DISABLED)
	
	def get(self):
		return self.values[self.variable.get()]
	