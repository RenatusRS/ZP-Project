from tkinter.ttk import Label
from tkinter import StringVar

class CLabel(Label):
	def __init__(self, parent, text: str, *args, **kwargs):
		self.var = StringVar(value=text)
		
		super().__init__(parent, textvariable=self.var, *args, **kwargs)
		
	def set(self, text: str):
		self.var.set(text)
		
	def get(self) -> str:
		return self.var.get()
	