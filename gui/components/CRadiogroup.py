from tkinter import StringVar

class CRadiogroup():
	def __init__(self):
		self.variable = None
		self.values = dict()
		
	def add(self, text: str, value):
		if not self.variable:
			self.variable = StringVar(value=text)
			
		self.values[text] = value
	
	def get(self):
		return self.values[self.variable.get()] if self.variable else None