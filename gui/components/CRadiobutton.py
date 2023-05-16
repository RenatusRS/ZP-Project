from tkinter.ttk import Radiobutton
from tkinter import StringVar

from gui.components.CRadiogroup import CRadiogroup

class CRadiobutton(Radiobutton):
	def __init__(self, parent, group: CRadiogroup, text: str, value, *args, **kwargs):
		group.add(text, value)
		
		super().__init__(parent, variable=group.variable, text=text, value=text, *args, **kwargs)