from tkinter import *

class CRadiobutton(Radiobutton):
	values: dict[str, dict] = dict()
	variables: dict[str, StringVar] = dict()
	
	def __init__(self, parent, group: str, text: str, value, *args, **kwargs):
		if group not in CRadiobutton.values:
			CRadiobutton.variables[group] = StringVar(value=text)
			CRadiobutton.values[group] = dict()
			
		CRadiobutton.values[group][text] = value
		
		super().__init__(parent, variable=CRadiobutton.variables[group], text=text, value=text, *args, **kwargs)
		
	
	@staticmethod
	def get(group: str):
		return CRadiobutton.values[group][CRadiobutton.variables[group].get()]