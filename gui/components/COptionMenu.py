from tkinter import *
from typing import List, Tuple, Any

class COptionMenu(OptionMenu):
	def __init__(self, parent, values: List[Tuple[str, Any]]):
		self.values = {value[0]: value[1] for value in values}
		
		text_options = [value[0] for value in values]
		
		default = text_options[0] if text_options else None
		
		self.variable = StringVar(value=default)
		
		super().__init__(parent, self.variable, default, *text_options[1:])
		
		if not values:
			self.config(state=DISABLED)
	
	def get(self):
		return self.values[self.variable.get()] if self.values else None